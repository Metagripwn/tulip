#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-only

"""
Tulip Auto-Setup Script

Automatically generates .env configuration file with sensible defaults.
Supports three modes:
  1. Quick Start (default): Defaults with automatic service discovery
  2. CTF Interactive: Prompts for CTF-specific configuration
  3. CLI Arguments: All configuration via command line
"""

import argparse
import ipaddress
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Any, List

try:
    import ruamel.yaml
    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# Default configuration values
DEFAULT_TICK_LENGTH_MS = "120000"
DEFAULT_GAME_INTERFACE = "game"
DEFAULT_TICK_START_INTERVALS = [
    ("30m", 30),
    ("1h", 60),
    ("2h", 120),
]

DEFAULTS = {
    # Tulip Infrastructure
    "FRONTEND_ADDR": "0.0.0.0:3030",
    "TRAFFIC_DIR": "./traffic",
    "INGESTOR_ROTATE": "30s",
    "INGESTOR_ADDR": "0.0.0.0:6969",
    "ASSEMBLER_TCP_LAZY": "true",
    "ASSEMBLER_EXPERIMENTAL": "true",
    "ASSEMBLER_NONSTRICT": "true",
    "ASSEMBLER_FLUSH_INTERVAL": "30s",
    "ASSEMBLER_CONNECTION_TIMEOUT": "1m",
    # CTF Game Config
    "TICK_START": None,  # Will be generated dynamically
    "TICK_LENGTH": DEFAULT_TICK_LENGTH_MS,
    "FLAG_REGEX": "[A-Z0-9]{31}=",
    "VM_IP": "10.0.0.1",
    "GAME_SERVICES": "srv1:5000 srv2:3000 srv3:1337",
    "FLAGID_URL": "http://10.10.0.1:8081/flagId",
    # Authentication
    "TULIP_AUTH_USERNAME": "admin",
    "TULIP_AUTH_PASSWORD_HASH": None,  # Will be generated dynamically
    "_TULIP_AUTH_PASSWORD_PLAINTEXT": None,  # Temporary, not written to file
}

class ValidationError(Exception):
    """Raised when configuration validation fails"""
    pass


class SetupScript:
    def __init__(self):
        self.env_example_path = Path(".env.example")
        self.env_path = Path(".env")
        self.config_path = Path(".tulip-config.json")
        self.game_interface = DEFAULT_GAME_INTERFACE
        # Directories to skip when scanning for services
        self.service_blacklist = [
            "traffic", "frontend", "services", "suricata",
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            "ctf_proxy", "tulip"
        ]

    def detect_vm_ip(self, interface_name: Optional[str] = None) -> Optional[str]:
        """Detect the IPv4 address for the game interface."""
        interface_name = interface_name or self.game_interface
        detection_commands = [
            ["ip", "-j", "-4", "addr", "show", "dev", interface_name],
            ["ip", "-4", "addr", "show", "dev", interface_name],
            ["ifconfig", interface_name],
        ]

        for command in detection_commands:
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

            if result.returncode != 0 or not result.stdout:
                continue

            ip_addr = self.extract_ipv4_from_output(command, result.stdout)
            if ip_addr:
                print(f"✓ Detected VM_IP from '{interface_name}' interface: {ip_addr}")
                return ip_addr

        print(
            f"⚠️  Warning: Could not detect an IPv4 address for interface "
            f"'{interface_name}'. Using default VM_IP: {DEFAULTS['VM_IP']}"
        )
        return None

    def extract_ipv4_from_output(self, command: List[str], output: str) -> Optional[str]:
        """Extract the first IPv4 address from interface inspection output."""
        if command[:3] == ["ip", "-j", "-4"]:
            try:
                interface_data = json.loads(output)
            except json.JSONDecodeError:
                return None

            for iface in interface_data:
                for addr_info in iface.get("addr_info", []):
                    if addr_info.get("family") != "inet":
                        continue
                    local_ip = addr_info.get("local")
                    if local_ip:
                        return local_ip
            return None

        match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)(?:/\d+)?\b", output)
        if not match:
            return None

        try:
            return str(ipaddress.ip_address(match.group(1)))
        except ValueError:
            return None

    def format_env_datetime(self, value: datetime) -> str:
        """Format a datetime for Tulip's .env file."""
        formatted = value.astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
        return formatted[:-2] + ":" + formatted[-2:]

    def get_next_rounded_time(self, now: datetime, interval_minutes: int) -> datetime:
        """Round up to the next future boundary for the given interval."""
        now = now.astimezone()
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        minutes_since_midnight = now.hour * 60 + now.minute
        next_boundary = ((minutes_since_midnight // interval_minutes) + 1) * interval_minutes
        days, rounded_minutes = divmod(next_boundary, 24 * 60)
        return day_start + timedelta(days=days, minutes=rounded_minutes)

    def get_tick_start_options(self, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Build the next rounded TICK_START candidates."""
        now = now.astimezone() if now else datetime.now().astimezone()
        options: List[Dict[str, Any]] = []

        for label, interval_minutes in DEFAULT_TICK_START_INTERVALS:
            candidate = self.get_next_rounded_time(now, interval_minutes)
            options.append(
                {
                    "value": self.format_env_datetime(candidate),
                    "datetime": candidate,
                    "label": label,
                }
            )

        return options

    def select_tick_start(self, now: Optional[datetime] = None) -> str:
        """Select a TICK_START value from the next rounded candidates."""
        options = self.get_tick_start_options(now)
        default_option = options[0]

        if not sys.stdin.isatty():
            print(
                f"✓ Auto-selected TICK_START: {default_option['value']} "
                f"(next {default_option['label']} slot)"
            )
            return default_option["value"]

        print("\n⏰ Select TICK_START:")
        for index, option in enumerate(options, start=1):
            print(
                f"  [{index}] {option['value']}  "
                f"(next {option['label']} slot)"
            )
        print(f"  [Enter] {default_option['value']}")

        while True:
            choice = input(f"\nChoice [1-{len(options)}]: ").strip().lower()
            if choice == "":
                return default_option["value"]
            if choice.isdigit():
                option_index = int(choice) - 1
                if 0 <= option_index < len(options):
                    return options[option_index]["value"]
            print(f"Invalid choice. Please enter a number between 1 and {len(options)}.")

    def prompt_yes_no(self, prompt: str, default: bool = False) -> bool:
        """Ask a yes/no question in interactive terminals."""
        if not sys.stdin.isatty():
            return default

        while True:
            choice = input(prompt).strip().lower()
            if choice == "":
                return default
            if choice in ["y", "yes"]:
                return True
            if choice in ["n", "no"]:
                return False
            print("Invalid choice. Please enter Y or N.")

    def get_tcpdump_command(self, config: Dict[str, str]) -> str:
        """Build the tcpdump pipeline command for Tulip."""
        port = config["INGESTOR_ADDR"].split(":")[1]
        return (
            f"sudo tcpdump -n -i {self.game_interface} -w - | "
            f"nc localhost {port}"
        )

    def start_tulip_services(self) -> bool:
        """Start Tulip with docker compose up -d."""
        if shutil.which("docker") is None:
            print("⚠️  Warning: Docker is not installed or not in PATH.")
            return False

        print("\n🚀 Starting Tulip with docker compose up -d...\n")
        try:
            result = subprocess.run(["docker", "compose", "up", "-d"])
        except FileNotFoundError:
            print("⚠️  Warning: Docker is not installed or not in PATH.")
            return False
        except Exception as e:
            print(f"⚠️  Warning: Failed to start Tulip: {e}")
            return False

        if result.returncode != 0:
            print("❌ docker compose up -d failed.")
            return False

        return True

    def wait_for_running_services(self, timeout_seconds: int = 15) -> bool:
        """Wait until docker compose reports running services."""
        for _ in range(timeout_seconds):
            try:
                result = subprocess.run(
                    ["docker", "compose", "ps", "--status", "running", "--services"],
                    capture_output=True,
                    text=True,
                )
            except Exception as e:
                print(f"⚠️  Warning: Failed to verify running services: {e}")
                return False

            running_services = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            if result.returncode == 0 and running_services:
                print(f"✓ Confirmed running services: {', '.join(running_services)}")
                return True

            time.sleep(1)

        print("⚠️  Warning: docker compose up -d completed, but running services could not be confirmed.")
        print("   Check with: docker compose ps")
        return False

    def start_tcpdump_tmux(self, config: Dict[str, str]) -> bool:
        """Start tcpdump in a detached tmux session."""
        session_name = "tcpdumper"
        if shutil.which("tmux") is None:
            print("⚠️  Warning: tmux is not installed or not in PATH.")
            return False

        try:
            existing_session = subprocess.run(
                ["tmux", "has-session", "-t", session_name],
                capture_output=True,
                text=True,
            )
        except Exception as e:
            print(f"⚠️  Warning: Failed to inspect tmux sessions: {e}")
            return False

        if existing_session.returncode == 0:
            print(f"⚠️  Warning: tmux session '{session_name}' already exists.")
            print(f"   Attach with: tmux attach -t {session_name}")
            return False

        print("\n📡 Preparing tcpdump in tmux session 'tcpdumper'...")
        try:
            sudo_result = subprocess.run(["sudo", "-v"])
        except FileNotFoundError:
            print("⚠️  Warning: sudo is not available.")
            return False
        except Exception as e:
            print(f"⚠️  Warning: Failed to validate sudo access: {e}")
            return False

        if sudo_result.returncode != 0:
            print("⚠️  Warning: sudo authentication failed. tcpdump was not started.")
            return False

        tcpdump_command = self.get_tcpdump_command(config)
        try:
            start_result = subprocess.run(
                ["tmux", "new-session", "-d", "-s", session_name, tcpdump_command],
                capture_output=True,
                text=True,
            )
        except Exception as e:
            print(f"⚠️  Warning: Failed to start tmux session: {e}")
            return False

        if start_result.returncode != 0:
            print("⚠️  Warning: Failed to start tcpdump tmux session.")
            if start_result.stderr:
                print(start_result.stderr.strip())
            return False

        time.sleep(1)
        check_result = subprocess.run(
            ["tmux", "has-session", "-t", session_name],
            capture_output=True,
            text=True,
        )
        if check_result.returncode == 0:
            print(f"✓ tcpdump started in tmux session '{session_name}'")
            print(f"   Attach with: tmux attach -t {session_name}")
            return True

        print("⚠️  Warning: tmux session 'tcpdumper' exited immediately.")
        print("   Check that sudo, tcpdump, and nc are available, then run the command manually:")
        print(f"   {tcpdump_command}")
        return False

    def prompt_post_setup_actions(self, config: Dict[str, str]) -> tuple[bool, bool]:
        """Offer to start Tulip and tcpdump after setup completes."""
        tulip_running = False
        tcpdump_running = False

        if not sys.stdin.isatty():
            return tulip_running, tcpdump_running

        if not self.prompt_yes_no("\nStart Tulip now with docker compose up -d? [Y/n]: ", default=True):
            return tulip_running, tcpdump_running

        if not self.start_tulip_services():
            return tulip_running, tcpdump_running

        tulip_running = self.wait_for_running_services()
        if not tulip_running:
            return tulip_running, tcpdump_running

        if self.prompt_yes_no("\nStart tcpdump in tmux session 'tcpdumper'? [y/N]: ", default=False):
            tcpdump_running = self.start_tcpdump_tmux(config)

        return tulip_running, tcpdump_running

    def get_default_service_scan_roots(self) -> List[Path]:
        """Return the default roots used for game service discovery."""
        cwd = Path.cwd().resolve()
        candidate_roots = [cwd, cwd.parent]
        scan_roots: List[Path] = []
        seen_roots = set()

        for root in candidate_roots:
            root_key = str(root)
            if root_key in seen_roots:
                continue
            seen_roots.add(root_key)
            scan_roots.append(root)

        return scan_roots

    def find_service_directories(self, scan_roots: Optional[List[Path]] = None) -> List[Path]:
        """Find directories that look like CTF services."""
        scan_roots = scan_roots or self.get_default_service_scan_roots()
        candidate_dirs: List[Path] = []
        seen_dirs = set()

        for scan_root in scan_roots:
            try:
                entries = list(scan_root.iterdir())
            except OSError as e:
                print(f"⚠️  Warning: Could not scan {scan_root}: {e}")
                continue

            for item in entries:
                if not item.is_dir():
                    continue
                if item.name.startswith("."):
                    continue
                if item.name in self.service_blacklist:
                    continue
                if not (item / "docker-compose.yml").exists() and not (item / "docker-compose.yaml").exists():
                    continue

                item_key = str(item.resolve())
                if item_key in seen_dirs:
                    continue
                seen_dirs.add(item_key)
                candidate_dirs.append(item)

        return candidate_dirs

    def discover_services(self, service_dirs: Optional[List[str]] = None) -> str:
        """
        Discover game services from docker-compose files.
        Similar to ctf_proxy's service discovery.

        Returns: Space-separated string of "name:port" pairs
        """
        if not HAS_YAML:
            print("\n⚠️  Warning: ruamel.yaml not installed. Cannot auto-discover services.")
            print("   Install with: pip install ruamel.yaml")
            print("   Using default services instead.\n")
            return DEFAULTS["GAME_SERVICES"]

        services = []
        dirs_to_scan = []

        # Use provided directories or scan the current directory and its parent
        if service_dirs:
            for dir_path in service_dirs:
                d = Path(dir_path)
                if not d.exists() or not d.is_dir():
                    print(f"⚠️  Warning: {dir_path} is not a valid directory, skipping")
                    continue
                dirs_to_scan.append(d)
        else:
            print("\n🔍 Scanning for CTF game services...")
            scan_roots = self.get_default_service_scan_roots()
            print("   Search roots:")
            for scan_root in scan_roots:
                print(f"   - {scan_root}")

            for item in self.find_service_directories(scan_roots):
                # Ask user if this is a game service
                response = input(f"   Is '{item.name}' a CTF game service? [y/N]: ").strip().lower()
                if response in ['y', 'yes']:
                    dirs_to_scan.append(item)

        if not dirs_to_scan:
            print("   No services found. Using defaults.")
            return DEFAULTS["GAME_SERVICES"]

        # Parse docker-compose files to extract ports
        print("\n📋 Extracting service ports...")
        for service_dir in dirs_to_scan:
            compose_file = service_dir / "docker-compose.yml"
            if not compose_file.exists():
                compose_file = service_dir / "docker-compose.yaml"

            try:
                with open(compose_file, 'r') as f:
                    compose_data = yaml.load(f)

                if 'services' not in compose_data:
                    continue

                # Extract ports from all containers in this service
                for container_name, container_config in compose_data['services'].items():
                    if 'ports' not in container_config:
                        continue

                    ports = container_config['ports']
                    if isinstance(ports, list):
                        for port_mapping in ports:
                            # Parse port mapping (can be "8080:80" or "0.0.0.0:8080:80")
                            port_str = str(port_mapping)
                            port_parts = port_str.split(':')

                            # Get the exposed port (left side of mapping)
                            if len(port_parts) >= 2:
                                exposed_port = port_parts[-2]  # Second to last is the exposed port
                                service_name = service_dir.name
                                service_entry = f"{service_name}:{exposed_port}"

                                if service_entry not in services:
                                    services.append(service_entry)
                                    print(f"   ✓ Found: {service_entry}")

            except Exception as e:
                print(f"   ⚠️  Error parsing {compose_file}: {e}")
                continue

        if not services:
            print("   No ports found. Using defaults.")
            return DEFAULTS["GAME_SERVICES"]

        return " ".join(services)

    def generate_password(self, length: int = 16) -> str:
        """Generate a secure random password"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password

    def hash_password_caddy(self, password: str) -> Optional[str]:
        """Hash password using Caddy's hash-password command via Docker"""
        try:
            # Try using docker to run caddy hash-password
            result = subprocess.run(
                ['docker', 'run', '--rm', 'caddy', 'caddy', 'hash-password', '--plaintext', password],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                print(f"⚠️  Warning: Failed to hash password with Caddy: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print("⚠️  Warning: Caddy password hashing timed out")
            return None
        except FileNotFoundError:
            print("⚠️  Warning: Docker not found. Cannot hash password.")
            return None
        except Exception as e:
            print(f"⚠️  Warning: Error hashing password: {e}")
            return None

    def generate_auth_credentials(self) -> tuple[str, str, str]:
        """
        Generate authentication credentials.
        Returns: (username, plaintext_password, password_hash)
        """
        username = "admin"
        password = self.generate_password()
        password_hash = self.hash_password_caddy(password)

        if password_hash is None:
            # Fallback: use a pre-generated hash for password "changeme"
            print("\n⚠️  Using fallback password: changeme")
            print("   Please change this after first login!")
            password = "changeme"
            # This is bcrypt hash of "changeme"
            password_hash = "$2a$14$wlpmTeITF5VI0DpT1smL1uWyPx48GlIY.b4hN8gklmlQ4BKbRayR6"

        return username, password, password_hash

    def parse_args(self) -> argparse.Namespace:
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description="Tulip Auto-Setup: Generate .env configuration file",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  ./setup.py                              # Quick start with auto-discovered services
  ./setup.py --discover-services          # Explicitly auto-discover game services
  ./setup.py --no-discover-services       # Use default GAME_SERVICES values
  ./setup.py --service-dirs ../web ../api # Scan specific directories
  ./setup.py --ctf                        # Interactive CTF configuration
  ./setup.py --vm-ip 10.60.1.1            # Override specific values
  ./setup.py --hash-password mypassword   # Hash a password for .env file
            """
        )

        # Mode flags
        parser.add_argument("--ctf", "--interactive", action="store_true",
                          help="Interactive CTF configuration mode")
        parser.add_argument("--discover-services", dest="discover_services",
                          action="store_true", default=True,
                          help="Auto-discover game services from docker-compose files (default: enabled)")
        parser.add_argument("--no-discover-services", dest="discover_services",
                          action="store_false",
                          help="Disable auto-discovery and use default GAME_SERVICES unless overridden")
        parser.add_argument("--service-dirs", nargs='+', metavar="DIR",
                          help="Directories to scan for services (implies --discover-services)")
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
        parser.add_argument("--hash-password", metavar="PASSWORD",
                          help="Hash a password and exit (useful for manual .env editing)")

        # Infrastructure config
        parser.add_argument("--frontend-addr", metavar="ADDR",
                          help="Frontend listen address (default: 0.0.0.0:3030)")
        parser.add_argument("--traffic-dir", metavar="DIR",
                          help="Traffic directory path (default: ./traffic)")
        parser.add_argument("--ingestor-addr", metavar="ADDR",
                          help="Ingestor listen address (default: 0.0.0.0:6969)")
        parser.add_argument("--ingestor-rotate", metavar="DURATION",
                          help="PCAP rotation interval (default: 30s)")

        # CTF game config
        parser.add_argument("--tick-start", metavar="DATETIME",
                          help="CTF start time (ISO 8601 format; default: next rounded 30m/1h/2h slot)")
        parser.add_argument("--flag-regex", metavar="REGEX",
                          help="Flag pattern regex (default: [A-Z0-9]{31}=)")
        parser.add_argument("--vm-ip", metavar="IP",
                          help=f"Vulnerable box IP address (default: auto-detected from {DEFAULT_GAME_INTERFACE}, fallback: 10.0.0.1)")
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

        # Generate TICK_START from the next rounded slot
        if config["TICK_START"] is None:
            config["TICK_START"] = self.get_tick_start_options()[0]["value"]

        # Generate authentication credentials
        if config["TULIP_AUTH_PASSWORD_HASH"] is None:
            username, password, password_hash = self.generate_auth_credentials()
            config["TULIP_AUTH_USERNAME"] = username
            config["TULIP_AUTH_PASSWORD_HASH"] = password_hash
            config["_TULIP_AUTH_PASSWORD_PLAINTEXT"] = password

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
                "Expected format: host:port (e.g., 0.0.0.0:3030)"
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
            f.write(f'FLAGID_URL="{config["FLAGID_URL"]}"\n\n')

            f.write("##############################\n")
            f.write("# HTTP Basic Authentication\n")
            f.write("##############################\n\n")

            # Authentication
            # IMPORTANT: Escape $ as $$ for docker-compose variable substitution
            escaped_hash = config["TULIP_AUTH_PASSWORD_HASH"].replace("$", "$$")
            f.write(f'TULIP_AUTH_USERNAME="{config["TULIP_AUTH_USERNAME"]}"\n')
            f.write(f'TULIP_AUTH_PASSWORD_HASH="{escaped_hash}"\n')

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

        print("\nAuthentication:")
        print(f"  USERNAME: {config['TULIP_AUTH_USERNAME']}")
        print(f"  PASSWORD_HASH: {config['TULIP_AUTH_PASSWORD_HASH'][:20]}...{config['TULIP_AUTH_PASSWORD_HASH'][-10:]}")
        if "_TULIP_AUTH_PASSWORD_PLAINTEXT" in config and config["_TULIP_AUTH_PASSWORD_PLAINTEXT"]:
            print(f"  PASSWORD: {config['_TULIP_AUTH_PASSWORD_PLAINTEXT']}")
        print("="*60 + "\n")

    def print_next_steps(self, config: Dict[str, str], tulip_running: bool = False,
                         tcpdump_running: bool = False) -> None:
        """Print next steps for user"""
        # Display credentials if they were generated
        if "_TULIP_AUTH_PASSWORD_PLAINTEXT" in config and config["_TULIP_AUTH_PASSWORD_PLAINTEXT"]:
            print("\n" + "="*60)
            print("⚠️  IMPORTANT: Save your login credentials!")
            print("="*60)
            print(f"  Username: {config['TULIP_AUTH_USERNAME']}")
            print(f"  Password: {config['_TULIP_AUTH_PASSWORD_PLAINTEXT']}")
            print("="*60)

        print("\nNext steps:")
        print("  1. Review configuration: cat .env")
        if tulip_running:
            print("  2. Tulip is running: docker compose ps")
        else:
            print("  2. Start Tulip: docker compose up -d")
        print(f"  3. Access UI: http://{config['FRONTEND_ADDR'].replace('0.0.0.0', 'localhost')}")
        if "_TULIP_AUTH_PASSWORD_PLAINTEXT" in config and config["_TULIP_AUTH_PASSWORD_PLAINTEXT"]:
            print(f"     Login with username '{config['TULIP_AUTH_USERNAME']}' and the password above")
        if tcpdump_running:
            print("\n  tcpdump session:")
            print("    tmux attach -t tcpdumper")
        else:
            print("\n  To capture traffic:")
            print(f"    {self.get_tcpdump_command(config)}")
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

        # Handle password hashing utility
        if args.hash_password:
            print("\n🔐 Hashing password...")
            password_hash = self.hash_password_caddy(args.hash_password)
            if password_hash:
                # Escape $ for docker-compose .env files
                escaped_hash = password_hash.replace("$", "$$")
                print(f"\nOriginal hash: {password_hash}")
                print(f"For .env file: {escaped_hash}")
                print("\nCopy the 'For .env file' version to your .env file")
            else:
                print("\n❌ Failed to hash password. Make sure Docker is running.")
            sys.exit(0)

        # Print header
        print("\n🌷 Tulip Auto-Setup")
        print("=" * 60)

        # Generate defaults
        config = self.generate_defaults()

        if args.vm_ip is None:
            detected_vm_ip = self.detect_vm_ip()
            if detected_vm_ip:
                config["VM_IP"] = detected_vm_ip

        # Discover services by default
        if args.discover_services or args.service_dirs:
            discovered_services = self.discover_services(args.service_dirs)
            config["GAME_SERVICES"] = discovered_services

        # Apply CLI arguments (these override discovered services if both are provided)
        config = self.apply_cli_args(config, args)

        # Handle existing .env file
        action = self.handle_existing_env(args)
        existing = {}

        if action == "merge":
            existing = self.read_existing_env()
            # Merge: existing values take precedence over defaults
            config = self.merge_configs(config, existing)
            print("Merging with existing .env file...")

        config["TICK_LENGTH"] = DEFAULT_TICK_LENGTH_MS

        if args.tick_start is None and not existing.get("TICK_START"):
            config["TICK_START"] = self.select_tick_start()

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

        tulip_running, tcpdump_running = self.prompt_post_setup_actions(config)

        # Print next steps
        self.print_next_steps(config, tulip_running=tulip_running, tcpdump_running=tcpdump_running)


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
