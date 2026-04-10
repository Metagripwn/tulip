#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-only

"""
Tulip Auto-Setup Script

Automatically generates .env configuration file with sensible defaults.
Supports three modes:
  1. Quick Start (default): All defaults, no prompts
  2. CTF Interactive: Prompts for CTF-specific configuration
  3. CLI Arguments: All configuration via command line
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional, Any


# Default configuration values
DEFAULTS = {
    # Tulip Infrastructure
    "FRONTEND_ADDR": "0.0.0.0:3000",
    "TRAFFIC_DIR": "./traffic",
    "INGESTOR_ROTATE": "30s",
    "INGESTOR_ADDR": "0.0.0.0:9999",
    "ASSEMBLER_TCP_LAZY": "true",
    "ASSEMBLER_EXPERIMENTAL": "true",
    "ASSEMBLER_NONSTRICT": "true",
    "ASSEMBLER_FLUSH_INTERVAL": "30s",
    "ASSEMBLER_CONNECTION_TIMEOUT": "1m",
    # CTF Game Config
    "TICK_START": None,  # Will be generated dynamically
    "TICK_LENGTH": "120000",
    "FLAG_REGEX": "[A-Z0-9]{31}=",
    "VM_IP": "10.0.0.1",
    "GAME_SERVICES": "srv1:5000 srv2:3000 srv3:1337",
    "FLAGID_URL": "http://10.10.0.1:8081/flagId",
}


class ValidationError(Exception):
    """Raised when configuration validation fails"""
    pass


class SetupScript:
    def __init__(self):
        self.env_example_path = Path(".env.example")
        self.env_path = Path(".env")
        self.config_path = Path(".tulip-config.json")

    def parse_args(self) -> argparse.Namespace:
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description="Tulip Auto-Setup: Generate .env configuration file",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  ./setup.py                    # Quick start with defaults
  ./setup.py --ctf              # Interactive CTF configuration
  ./setup.py --vm-ip 10.60.1.1  # Override specific values
            """
        )

        # Mode flags
        parser.add_argument("--ctf", "--interactive", action="store_true",
                          help="Interactive CTF configuration mode")
        parser.add_argument("--force", action="store_true",
                          help="Overwrite existing .env without prompting")
        parser.add_argument("--backup", action="store_true", default=True,
                          help="Create backup before overwriting (default: true)")
        parser.add_argument("--no-backup", action="store_false", dest="backup",
                          help="Don't create backup")
        parser.add_argument("--validate-only", action="store_true",
                          help="Validate configuration without writing files")
        parser.add_argument("--show-config", action="store_true",
                          help="Display configuration and exit")

        # Infrastructure config
        parser.add_argument("--frontend-addr", metavar="ADDR",
                          help="Frontend listen address (default: 0.0.0.0:3000)")
        parser.add_argument("--traffic-dir", metavar="DIR",
                          help="Traffic directory path (default: ./traffic)")
        parser.add_argument("--ingestor-addr", metavar="ADDR",
                          help="Ingestor listen address (default: 0.0.0.0:9999)")
        parser.add_argument("--ingestor-rotate", metavar="DURATION",
                          help="PCAP rotation interval (default: 30s)")

        # CTF game config
        parser.add_argument("--tick-start", metavar="DATETIME",
                          help="CTF start time (ISO 8601 format)")
        parser.add_argument("--tick-length", metavar="MS", type=int,
                          help="Tick length in milliseconds (default: 120000)")
        parser.add_argument("--flag-regex", metavar="REGEX",
                          help="Flag pattern regex (default: [A-Z0-9]{31}=)")
        parser.add_argument("--vm-ip", metavar="IP",
                          help="Vulnerable box IP address (default: 10.0.0.1)")
        parser.add_argument("--services", metavar="SERVICES",
                          help="Game services (format: 'name:port name:port')")
        parser.add_argument("--flagid-url", metavar="URL",
                          help="FlagID service URL (optional)")

        # Assembler config
        parser.add_argument("--assembler-tcp-lazy", metavar="BOOL",
                          help="TCP lazy mode (default: true)")
        parser.add_argument("--assembler-experimental", metavar="BOOL",
                          help="Experimental features (default: true)")
        parser.add_argument("--assembler-nonstrict", metavar="BOOL",
                          help="Non-strict mode (default: true)")
        parser.add_argument("--assembler-flush-interval", metavar="DURATION",
                          help="Flush interval (default: 30s)")
        parser.add_argument("--assembler-connection-timeout", metavar="DURATION",
                          help="Connection timeout (default: 1m)")

        return parser.parse_args()

    def generate_defaults(self) -> Dict[str, str]:
        """Generate default configuration values"""
        config = DEFAULTS.copy()

        # Generate TICK_START as current time + 5 minutes
        if config["TICK_START"] is None:
            now = datetime.now(timezone.utc)
            start_time = now + timedelta(minutes=5)
            # Format as ISO 8601 with local timezone
            local_tz = datetime.now().astimezone().tzinfo
            start_time_local = start_time.astimezone(local_tz)
            config["TICK_START"] = start_time_local.strftime("%Y-%m-%dT%H:%M:%S%z")
            # Insert colon in timezone offset (2025-04-10T14:00:00+0200 -> 2025-04-10T14:00:00+02:00)
            config["TICK_START"] = config["TICK_START"][:-2] + ":" + config["TICK_START"][-2:]

        return config

    def validate_ip_address(self, ip_str: str) -> str:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip_str)
            return ip_str
        except ValueError:
            raise ValidationError(f"Invalid IP address: {ip_str}\nExample: 10.0.0.1")

    def validate_regex(self, pattern: str) -> str:
        """Validate regex pattern"""
        try:
            re.compile(pattern)
            return pattern
        except re.error as e:
            raise ValidationError(f"Invalid regex pattern: {pattern}\nError: {e}")

    def validate_datetime(self, dt_str: str) -> str:
        """Validate ISO 8601 datetime format"""
        try:
            # Try parsing with timezone
            datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
            return dt_str
        except ValueError:
            raise ValidationError(
                f"Invalid datetime format: {dt_str}\n"
                "Expected ISO 8601 format: 2025-04-10T14:00:00+02:00"
            )

    def validate_host_port(self, host_port: str) -> str:
        """Validate host:port format"""
        pattern = r'^[a-zA-Z0-9.-]+:\d+$'
        if not re.match(pattern, host_port):
            raise ValidationError(
                f"Invalid host:port format: {host_port}\n"
                "Expected format: host:port (e.g., 0.0.0.0:3000)"
            )
        return host_port

    def validate_duration(self, duration: str) -> str:
        """Validate duration format (e.g., 30s, 1m)"""
        pattern = r'^\d+[smh]$'
        if not re.match(pattern, duration):
            raise ValidationError(
                f"Invalid duration format: {duration}\n"
                "Expected format: number + unit (e.g., 30s, 1m, 2h)"
            )
        return duration

    def validate_url(self, url: str, allow_empty: bool = True) -> str:
        """Validate URL format"""
        if allow_empty and not url:
            return url

        pattern = r'^https?://[a-zA-Z0-9.-]+(:\d+)?(/.*)?$'
        if not re.match(pattern, url):
            raise ValidationError(
                f"Invalid URL format: {url}\n"
                "Expected format: http://host:port/path"
            )
        return url

    def validate_service_list(self, services: str) -> str:
        """Validate service list format"""
        if not services.strip():
            raise ValidationError("Service list cannot be empty")

        parts = services.split()
        for part in parts:
            if ':' not in part:
                raise ValidationError(
                    f"Invalid service format: {part}\n"
                    "Expected format: 'name:port name:port' (e.g., 'web:80 api:8080')"
                )
            name, port = part.split(':', 1)
            if not name or not port.isdigit():
                raise ValidationError(
                    f"Invalid service format: {part}\n"
                    "Port must be a number"
                )
        return services

    def validate_boolean(self, value: str) -> str:
        """Validate boolean value"""
        if value.lower() not in ["true", "false"]:
            raise ValidationError(
                f"Invalid boolean value: {value}\n"
                "Expected: true or false"
            )
        return value.lower()

    def validate_config(self, config: Dict[str, str]) -> None:
        """Validate all configuration values"""
        validators = {
            "FRONTEND_ADDR": self.validate_host_port,
            "INGESTOR_ADDR": self.validate_host_port,
            "INGESTOR_ROTATE": self.validate_duration,
            "ASSEMBLER_FLUSH_INTERVAL": self.validate_duration,
            "ASSEMBLER_CONNECTION_TIMEOUT": self.validate_duration,
            "TICK_START": self.validate_datetime,
            "FLAG_REGEX": self.validate_regex,
            "VM_IP": self.validate_ip_address,
            "GAME_SERVICES": self.validate_service_list,
            "ASSEMBLER_TCP_LAZY": self.validate_boolean,
            "ASSEMBLER_EXPERIMENTAL": self.validate_boolean,
            "ASSEMBLER_NONSTRICT": self.validate_boolean,
        }

        for key, validator in validators.items():
            if key in config:
                try:
                    config[key] = validator(config[key])
                except ValidationError as e:
                    print(f"\nValidation error for {key}:")
                    print(f"  {e}")
                    sys.exit(1)

        # Validate FLAGID_URL if present (allow empty)
        if "FLAGID_URL" in config:
            try:
                config["FLAGID_URL"] = self.validate_url(config["FLAGID_URL"], allow_empty=True)
            except ValidationError as e:
                print(f"\nValidation error for FLAGID_URL:")
                print(f"  {e}")
                sys.exit(1)

    def create_directory(self, path: str) -> None:
        """Create directory with permission checks"""
        dir_path = Path(path)

        if dir_path.exists():
            if not dir_path.is_dir():
                raise ValidationError(f"{path} exists but is not a directory")
            # Test write permission
            test_file = dir_path / ".test_write"
            try:
                test_file.touch()
                test_file.unlink()
            except PermissionError:
                raise ValidationError(f"No write permission for directory: {path}")
        else:
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
                print(f"✓ Created directory: {path}")
            except PermissionError:
                raise ValidationError(f"No permission to create directory: {path}")

    def backup_env_file(self) -> Optional[str]:
        """Create timestamped backup of existing .env file"""
        if not self.env_path.exists():
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = Path(f".env.backup.{timestamp}")
        shutil.copy2(self.env_path, backup_path)
        return str(backup_path)

    def read_existing_env(self) -> Dict[str, str]:
        """Read existing .env file into dictionary"""
        if not self.env_path.exists():
            return {}

        config = {}
        with open(self.env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, value = line.split('=', 1)
                    # Remove quotes if present
                    value = value.strip('"\'')
                    config[key.strip()] = value
        return config

    def write_env_file(self, config: Dict[str, str]) -> None:
        """Write configuration to .env file"""
        with open(self.env_path, 'w') as f:
            f.write("# SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>\n")
            f.write("#\n")
            f.write("# SPDX-License-Identifier: GPL-3.0-only\n\n")

            f.write("##############################\n")
            f.write("# Tulip config\n")
            f.write("##############################\n\n")

            # Infrastructure config
            f.write(f'FRONTEND_ADDR="{config["FRONTEND_ADDR"]}"\n')
            f.write(f'TRAFFIC_DIR="{config["TRAFFIC_DIR"]}"\n')
            f.write(f'INGESTOR_ROTATE="{config["INGESTOR_ROTATE"]}"\n')
            f.write(f'INGESTOR_ADDR="{config["INGESTOR_ADDR"]}"\n\n')

            f.write(f'ASSEMBLER_TCP_LAZY="{config["ASSEMBLER_TCP_LAZY"]}"\n')
            f.write(f'ASSEMBLER_EXPERIMENTAL="{config["ASSEMBLER_EXPERIMENTAL"]}"\n')
            f.write(f'ASSEMBLER_NONSTRICT="{config["ASSEMBLER_NONSTRICT"]}"\n')
            f.write(f'ASSEMBLER_FLUSH_INTERVAL="{config["ASSEMBLER_FLUSH_INTERVAL"]}"\n')
            f.write(f'ASSEMBLER_CONNECTION_TIMEOUT="{config["ASSEMBLER_CONNECTION_TIMEOUT"]}"\n\n')

            f.write("##############################\n")
            f.write("# Game config\n")
            f.write("##############################\n\n")

            # CTF config
            f.write(f'TICK_START="{config["TICK_START"]}"\n')
            f.write(f'TICK_LENGTH={config["TICK_LENGTH"]}\n')
            f.write(f'FLAG_REGEX="{config["FLAG_REGEX"]}"\n')
            f.write(f'VM_IP="{config["VM_IP"]}"\n')
            f.write(f'GAME_SERVICES="{config["GAME_SERVICES"]}"\n')
            f.write(f'FLAGID_URL="{config["FLAGID_URL"]}"\n')

    def show_config(self, config: Dict[str, str]) -> None:
        """Display configuration"""
        print("\n" + "="*60)
        print("Tulip Configuration")
        print("="*60)
        print("\nTulip Infrastructure:")
        print(f"  FRONTEND_ADDR: {config['FRONTEND_ADDR']}")
        print(f"  TRAFFIC_DIR: {config['TRAFFIC_DIR']}")
        print(f"  INGESTOR_ADDR: {config['INGESTOR_ADDR']}")
        print(f"  INGESTOR_ROTATE: {config['INGESTOR_ROTATE']}")

        print("\nAssembler:")
        print(f"  TCP_LAZY: {config['ASSEMBLER_TCP_LAZY']}")
        print(f"  EXPERIMENTAL: {config['ASSEMBLER_EXPERIMENTAL']}")
        print(f"  NONSTRICT: {config['ASSEMBLER_NONSTRICT']}")
        print(f"  FLUSH_INTERVAL: {config['ASSEMBLER_FLUSH_INTERVAL']}")
        print(f"  CONNECTION_TIMEOUT: {config['ASSEMBLER_CONNECTION_TIMEOUT']}")

        print("\nCTF Game:")
        print(f"  TICK_START: {config['TICK_START']}")
        print(f"  TICK_LENGTH: {config['TICK_LENGTH']}")
        print(f"  FLAG_REGEX: {config['FLAG_REGEX']}")
        print(f"  VM_IP: {config['VM_IP']}")
        print(f"  GAME_SERVICES: {config['GAME_SERVICES']}")
        print(f"  FLAGID_URL: {config['FLAGID_URL']}")
        print("="*60 + "\n")

    def print_next_steps(self, config: Dict[str, str]) -> None:
        """Print next steps for user"""
        print("\nNext steps:")
        print("  1. Review configuration: cat .env")
        print("  2. Start Tulip: docker compose up -d")
        print(f"  3. Access UI: http://{config['FRONTEND_ADDR'].replace('0.0.0.0', 'localhost')}")
        print("\n  To capture traffic:")
        print(f"    sudo tcpdump -n -i eth0 -w - | nc localhost {config['INGESTOR_ADDR'].split(':')[1]}")
        print("\nDone! 🌷\n")

    def merge_configs(self, base: Dict[str, str], override: Dict[str, str]) -> Dict[str, str]:
        """Merge two configurations, with override taking precedence"""
        result = base.copy()
        result.update({k: v for k, v in override.items() if v is not None})
        return result

    def apply_cli_args(self, config: Dict[str, str], args: argparse.Namespace) -> Dict[str, str]:
        """Apply CLI arguments to configuration"""
        arg_mapping = {
            "frontend_addr": "FRONTEND_ADDR",
            "traffic_dir": "TRAFFIC_DIR",
            "ingestor_addr": "INGESTOR_ADDR",
            "ingestor_rotate": "INGESTOR_ROTATE",
            "tick_start": "TICK_START",
            "tick_length": "TICK_LENGTH",
            "flag_regex": "FLAG_REGEX",
            "vm_ip": "VM_IP",
            "services": "GAME_SERVICES",
            "flagid_url": "FLAGID_URL",
            "assembler_tcp_lazy": "ASSEMBLER_TCP_LAZY",
            "assembler_experimental": "ASSEMBLER_EXPERIMENTAL",
            "assembler_nonstrict": "ASSEMBLER_NONSTRICT",
            "assembler_flush_interval": "ASSEMBLER_FLUSH_INTERVAL",
            "assembler_connection_timeout": "ASSEMBLER_CONNECTION_TIMEOUT",
        }

        for arg_name, config_key in arg_mapping.items():
            arg_value = getattr(args, arg_name, None)
            if arg_value is not None:
                if arg_name == "tick_length":
                    config[config_key] = str(arg_value)
                else:
                    config[config_key] = arg_value

        return config

    def handle_existing_env(self, args: argparse.Namespace) -> str:
        """Handle existing .env file, return action"""
        if not self.env_path.exists():
            return "create"

        if args.force:
            return "overwrite"

        print(f"\n.env file already exists.")
        print("Options:")
        print("  [O]verwrite - Start fresh (creates backup)")
        print("  [M]erge - Keep existing values, add missing ones")
        print("  [A]bort - Exit without changes")

        while True:
            choice = input("\nChoice [M/o/a]: ").strip().lower()
            if choice in ['', 'm', 'merge']:
                return "merge"
            elif choice in ['o', 'overwrite']:
                return "overwrite"
            elif choice in ['a', 'abort']:
                print("Aborted.")
                sys.exit(0)
            else:
                print("Invalid choice. Please enter M, O, or A.")

    def run(self) -> None:
        """Main entry point"""
        args = self.parse_args()

        # Print header
        print("\n🌷 Tulip Auto-Setup")
        print("=" * 60)

        # Generate defaults
        config = self.generate_defaults()

        # Apply CLI arguments
        config = self.apply_cli_args(config, args)

        # Handle existing .env file
        action = self.handle_existing_env(args)

        if action == "merge":
            existing = self.read_existing_env()
            # Merge: existing values take precedence over defaults
            config = self.merge_configs(config, existing)
            print("Merging with existing .env file...")

        # Validate configuration
        print("\nValidating configuration...")
        self.validate_config(config)

        # Show configuration if requested
        if args.show_config:
            self.show_config(config)
            sys.exit(0)

        # Validate-only mode
        if args.validate_only:
            print("✓ Configuration is valid")
            self.show_config(config)
            sys.exit(0)

        # Create traffic directory
        try:
            self.create_directory(config["TRAFFIC_DIR"])
        except ValidationError as e:
            print(f"\nError: {e}")
            sys.exit(1)

        # Backup existing .env if needed
        if action in ["overwrite", "merge"] and args.backup:
            backup_path = self.backup_env_file()
            if backup_path:
                print(f"✓ Backup created: {backup_path}")

        # Write .env file
        self.write_env_file(config)
        print(f"✓ Configuration written to .env")

        # Print next steps
        self.print_next_steps(config)


def main():
    try:
        script = SetupScript()
        script.run()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
