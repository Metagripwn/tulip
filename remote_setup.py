#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Tulip contributors
#
# SPDX-License-Identifier: GPL-3.0-only

"""Set up a local Tulip stack that captures traffic from an SSH host.

The remote host only runs tcpdump.  PCAP bytes travel on the existing SSH
connection to the local ``remote-capture`` Compose service, which sends them
to Tulip's ingestor on the private Compose network.
"""

import argparse
import getpass
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from setup import DEFAULT_GAME_INTERFACE, SetupScript, ValidationError


class RemoteSetupError(Exception):
    """Raised when a remote prerequisite or discovery operation fails."""


class RemoteSetup:
    def __init__(self) -> None:
        self.local = SetupScript()
        self.args: argparse.Namespace
        self.identity_file: Optional[Path] = None
        self.password_file: Optional[Path] = None
        self.ssh_dir = Path(".tulip/ssh")
        self.known_hosts = self.ssh_dir / "known_hosts"

    def parse_args(self) -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description="Configure local Tulip to capture PCAP traffic from a remote SSH host.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  ./remote_setup.py
  ./remote_setup.py --ssh-host game.example --ssh-user ctf
  ./remote_setup.py --ssh-host game.example --ssh-auth key --identity-file ~/.ssh/game_ed25519
  ./remote_setup.py --ssh-host game.example --capture-filter 'tcp and port 5000'

Password authentication is the default. The password is requested without
echoing it and stored only in a mode-0600 file below the ignored .tulip
directory so the capture service can reconnect. Use --ssh-auth key to opt in
to key authentication instead.
            """,
        )
        parser.add_argument("--ssh-host", help="Remote SSH hostname or IP address; prompted when omitted")
        parser.add_argument("--ssh-user", help="Remote SSH user; prompted when omitted")
        parser.add_argument("--ssh-port", type=int, default=22, help="Remote SSH port (default: 22)")
        parser.add_argument("--ssh-auth", choices=("password", "key"), default="password", help="SSH authentication method (default: password)")
        parser.add_argument("--identity-file", metavar="PATH", help="SSH private key; required for --ssh-auth key")
        parser.add_argument("--accept-new-host-key", action="store_true", help="Trust a newly scanned SSH host key without prompting")
        parser.add_argument("--interface", help=f"Remote interface to capture (default: auto-detect, preferring {DEFAULT_GAME_INTERFACE!r})")
        parser.add_argument("--capture-filter", default="", help="Additional tcpdump BPF expression")
        parser.add_argument("--snaplen", type=int, default=0, help="tcpdump snapshot length; 0 keeps complete packets")
        parser.add_argument("--vm-ip", help="Override the remote vulnerable-machine IP")
        parser.add_argument("--services", help="Override game services: 'name:port name:port'")
        parser.add_argument("--tick-start", help="Override TICK_START with an ISO-8601 datetime")
        parser.add_argument("--flag-regex", help="Override the flag regex")
        parser.add_argument("--flagid-url", help="Override the FlagID endpoint")
        parser.add_argument("--frontend-addr", default="127.0.0.1:3030", help="Local Tulip UI bind address")
        parser.add_argument("--traffic-dir", default="./traffic", help="Local directory for rotated PCAP files")
        parser.add_argument("--ingestor-rotate", default="30s", help="Local PCAP rotation interval")
        parser.add_argument("--no-start", action="store_true", help="Write configuration but do not start Compose")
        parser.add_argument("--force", action="store_true", help="Overwrite local .env settings instead of merging them")
        parser.add_argument("--no-backup", action="store_true", help="Do not back up an existing .env")
        return parser.parse_args()

    @staticmethod
    def prompt_yes_no(prompt: str, default: bool = False) -> bool:
        if not sys.stdin.isatty():
            return default
        suffix = "Y/n" if default else "y/N"
        while True:
            answer = input(f"{prompt} [{suffix}]: ").strip().lower()
            if not answer:
                return default
            if answer in {"y", "yes"}:
                return True
            if answer in {"n", "no"}:
                return False
            print("Please answer y or n.")

    def choose(self, prompt: str, choices: List[str]) -> str:
        if len(choices) == 1:
            return choices[0]
        if not sys.stdin.isatty():
            raise RemoteSetupError(f"{prompt}; pass an explicit option instead")
        print(f"\n{prompt}:")
        for index, choice in enumerate(choices, 1):
            print(f"  [{index}] {choice}")
        while True:
            answer = input(f"Choice [1-{len(choices)}]: ").strip()
            if answer.isdigit() and 1 <= int(answer) <= len(choices):
                return choices[int(answer) - 1]
            print("Choose one of the listed numbers.")

    def find_identity_file(self) -> Path:
        if self.args.identity_file:
            identity = Path(self.args.identity_file).expanduser()
            if not identity.is_file():
                raise RemoteSetupError(f"SSH identity does not exist or is not a file: {identity}")
            return identity

        candidates = [
            path for path in (
                Path.home() / ".ssh/id_ed25519",
                Path.home() / ".ssh/id_ecdsa",
                Path.home() / ".ssh/id_rsa",
            ) if path.is_file()
        ]
        if not candidates:
            raise RemoteSetupError("No standard SSH identity found; pass --identity-file PATH")
        return Path(self.choose("Select the SSH identity", [str(path) for path in candidates])).expanduser()

    def _ssh_prefix(self, known_hosts: Path, read_stdin: bool = False) -> List[str]:
        prefix = [
            "ssh", "-T", "-p", str(self.args.ssh_port),
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
        ]
        if self.args.ssh_auth == "key":
            if self.identity_file is None:
                raise RemoteSetupError("SSH identity has not been prepared")
            prefix[3:3] = ["-i", str(self.identity_file), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"]
        else:
            prefix[3:3] = [
                "-o", "BatchMode=no", "-o", "PubkeyAuthentication=no",
                "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "NumberOfPasswordPrompts=1",
            ]
        prefix.append(f"{self.args.ssh_user}@{self.args.ssh_host}")
        if not read_stdin:
            prefix.insert(3, "-n")
        return prefix

    def remote(
        self, command: str, check: bool = True, timeout: int = 20, stdin_data: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        if self.args.ssh_auth == "password" and self.password_file is None:
            raise RemoteSetupError("SSH password has not been prepared")
        environment = os.environ.copy()
        if self.args.ssh_auth == "password":
            environment.update({
                "SSH_ASKPASS": str(self.ssh_dir / "askpass.sh"),
                "SSH_ASKPASS_REQUIRE": "force",
                "DISPLAY": "tulip-remote-setup",
            })
        result = subprocess.run(
            self._ssh_prefix(self.known_hosts, read_stdin=stdin_data is not None) + [command],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
            input=stdin_data,
        )
        if check and result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "unknown SSH error"
            raise RemoteSetupError(f"Remote command failed: {detail}")
        return result

    def prepare_ssh_material(self) -> None:
        self.ssh_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.ssh_dir, 0o700)

        if self.args.ssh_auth == "key":
            identity = self.find_identity_file()
            project_identity = self.ssh_dir / "id_remote"
            shutil.copy2(identity, project_identity)
            os.chmod(project_identity, 0o600)
            self.identity_file = project_identity
        else:
            password = os.environ.get("TULIP_REMOTE_SSH_PASSWORD")
            if password is None:
                if not sys.stdin.isatty():
                    raise RemoteSetupError("Set TULIP_REMOTE_SSH_PASSWORD when password setup is non-interactive")
                password = getpass.getpass(f"SSH password for {self.args.ssh_user}@{self.args.ssh_host}: ")
            if not password:
                raise RemoteSetupError("SSH password cannot be empty")
            if "\n" in password or "\r" in password:
                raise RemoteSetupError("SSH passwords containing newlines are not supported")
            self.password_file = self.ssh_dir / "password"
            self.password_file.write_text(password + "\n", encoding="utf-8")
            os.chmod(self.password_file, 0o600)
            askpass = self.ssh_dir / "askpass.sh"
            askpass.write_text('#!/bin/sh\ncat "$(dirname "$0")/password"\n', encoding="utf-8")
            os.chmod(askpass, 0o700)

        host_patterns = [self.args.ssh_host]
        if self.args.ssh_port != 22:
            host_patterns.insert(0, f"[{self.args.ssh_host}]:{self.args.ssh_port}")
        system_known_hosts = Path.home() / ".ssh/known_hosts"
        entries: List[str] = []
        if system_known_hosts.exists():
            for pattern in host_patterns:
                result = subprocess.run(
                    ["ssh-keygen", "-F", pattern, "-f", str(system_known_hosts)],
                    capture_output=True, text=True,
                )
                entries.extend(line for line in result.stdout.splitlines() if line and not line.startswith("#"))

        if not entries:
            scan = subprocess.run(
                ["ssh-keyscan", "-p", str(self.args.ssh_port), self.args.ssh_host],
                capture_output=True, text=True, timeout=15,
            )
            scanned_entries = [line for line in scan.stdout.splitlines() if line and not line.startswith("#")]
            if not scanned_entries:
                raise RemoteSetupError("Could not retrieve an SSH host key with ssh-keyscan")
            fingerprint = subprocess.run(
                ["ssh-keygen", "-lf", "-"], input="\n".join(scanned_entries) + "\n",
                capture_output=True, text=True,
            ).stdout.strip()
            if not self.args.accept_new_host_key and not self.prompt_yes_no(
                f"Trust new SSH host key for {self.args.ssh_host}?\n{fingerprint}", default=False,
            ):
                raise RemoteSetupError("SSH host key was not trusted")
            entries = scanned_entries

        self.known_hosts.write_text("\n".join(dict.fromkeys(entries)) + "\n", encoding="utf-8")
        os.chmod(self.known_hosts, 0o600)

        self.remote("printf tulip-remote-ok", timeout=20)
        print(f"✓ Connected to {self.args.ssh_user}@{self.args.ssh_host} with a verified SSH host key")

    def remote_json(self, command: str) -> Any:
        output = self.remote(command).stdout
        try:
            return json.loads(output)
        except json.JSONDecodeError as error:
            raise RemoteSetupError(f"Remote command returned invalid JSON: {error}") from error

    def discover_interface_and_ip(self) -> Tuple[str, str]:
        addresses = self.remote_json("ip -j -4 addr show up")
        interfaces: Dict[str, List[str]] = {}
        for item in addresses:
            name = item.get("ifname")
            ips = [
                address.get("local") for address in item.get("addr_info", [])
                if address.get("family") == "inet" and address.get("scope") == "global" and address.get("local")
            ]
            if name and ips:
                interfaces[name] = ips
        if not interfaces:
            raise RemoteSetupError("No active remote IPv4 interface was found; pass --interface and --vm-ip")

        if self.args.interface:
            if self.args.interface not in interfaces:
                raise RemoteSetupError(f"Remote interface {self.args.interface!r} has no active IPv4 address")
            interface = self.args.interface
        elif DEFAULT_GAME_INTERFACE in interfaces:
            interface = DEFAULT_GAME_INTERFACE
        else:
            routes = self.remote_json("ip -j route show default")
            default_interface = next((route.get("dev") for route in routes if route.get("dev") in interfaces), None)
            interface = default_interface or self.choose("Select the remote capture interface", sorted(interfaces))

        vm_ip = self.args.vm_ip or interfaces[interface][0]
        try:
            ipaddress.ip_address(vm_ip)
        except ValueError as error:
            raise RemoteSetupError(f"Invalid VM IP: {vm_ip}") from error
        print(f"✓ Remote capture interface: {interface}; VM_IP: {vm_ip}")
        return interface, vm_ip

    def discover_services(self) -> str:
        if self.args.services is not None:
            self.local.validate_service_list(self.args.services)
            return self.args.services

        result = self.remote("docker ps --format '{{.Names}}\\t{{.Ports}}' 2>/dev/null || true")
        services: List[str] = []
        for line in result.stdout.splitlines():
            if "\t" not in line:
                continue
            name, ports = line.split("\t", 1)
            published = re.findall(r"(?:^|,\s*)(?:\[[^]]+\]|[^,:]+):(\d+)->\d+/(?:tcp)", ports)
            for port in published:
                entry = f"{name}:{port}"
                if entry not in services:
                    services.append(entry)

        if services:
            value = " ".join(services)
            print(f"✓ Discovered remote game services: {value}")
            return value

        if not sys.stdin.isatty():
            print("⚠️  No published Docker services found remotely; leaving GAME_SERVICES empty.")
            return ""
        value = input("No published Docker services found. Enter GAME_SERVICES, or leave blank: ").strip()
        if value:
            self.local.validate_service_list(value)
        return value

    def remote_sudo(self, command: str, sudo_mode: str, timeout: int = 20) -> subprocess.CompletedProcess:
        if sudo_mode == "false":
            return self.remote(command, timeout=timeout)
        if sudo_mode == "true":
            return self.remote(f"sudo -n {command}", timeout=timeout)
        if sudo_mode == "password":
            if self.password_file is None:
                raise RemoteSetupError("A password-authenticated SSH session is required for sudo password mode")
            return self.remote(
                f"sudo -S -p '' {command}", timeout=timeout,
                stdin_data=self.password_file.read_text(encoding="utf-8"),
            )
        raise RemoteSetupError(f"Unknown sudo mode: {sudo_mode}")

    def install_tcpdump(self, sudo_mode: str) -> None:
        command = (
            "if command -v apt-get >/dev/null; then "
            "apt-get update && apt-get install -y tcpdump; "
            "elif command -v dnf >/dev/null; then "
            "dnf install -y tcpdump; "
            "elif command -v yum >/dev/null; then "
            "yum install -y tcpdump; "
            "elif command -v apk >/dev/null; then "
            "apk add tcpdump; "
            "else exit 127; fi"
        )
        self.remote_sudo(command, sudo_mode, timeout=180)

    def verify_remote_capture_prerequisites(self) -> str:
        is_root = self.remote("test \"$(id -u)\" = 0", check=False).returncode == 0
        sudo_mode = "false"
        if not is_root:
            if self.remote("sudo -n true", check=False).returncode == 0:
                sudo_mode = "true"
            elif self.args.ssh_auth == "password" and self.password_file is not None:
                try:
                    self.remote_sudo("true", "password")
                    sudo_mode = "password"
                except RemoteSetupError as error:
                    raise RemoteSetupError(
                        "Remote sudo rejected the SSH password. Use a root SSH account, configure passwordless sudo, "
                        "or make the SSH and sudo passwords match."
                    ) from error
            else:
                raise RemoteSetupError(
                    "Remote capture needs passwordless sudo for tcpdump when using key authentication, or a root SSH account."
                )

        if self.remote("command -v tcpdump", check=False).returncode != 0:
            print("tcpdump is missing remotely; installing it now...")
            self.install_tcpdump(sudo_mode)

        if self.args.capture_filter:
            self.remote_sudo(f"tcpdump -d -- {self._shell_quote(self.args.capture_filter)} >/dev/null", sudo_mode)
        print("✓ Remote tcpdump and capture privileges are ready")
        return sudo_mode

    @staticmethod
    def _shell_quote(value: str) -> str:
        return "'" + value.replace("'", "'\\''") + "'"

    def build_config(self, vm_ip: str, services: str) -> Dict[str, str]:
        config = self.local.generate_defaults()
        config.update({
            "FRONTEND_ADDR": self.args.frontend_addr,
            "TRAFFIC_DIR": self.args.traffic_dir,
            "INGESTOR_ADDR": "127.0.0.1:6969",
            "INGESTOR_ROTATE": self.args.ingestor_rotate,
            "VM_IP": vm_ip,
            "GAME_SERVICES": services,
            "FLAGID_URL": self.args.flagid_url if self.args.flagid_url is not None else "",
        })
        if self.args.tick_start:
            config["TICK_START"] = self.args.tick_start
        if self.args.flag_regex:
            config["FLAG_REGEX"] = self.args.flag_regex

        existing = self.local.read_existing_env()
        if existing and not self.args.force:
            config = self.local.merge_configs(config, existing)
            # Remote discovery must win over values from an old local capture setup.
            config.update({"FRONTEND_ADDR": self.args.frontend_addr, "INGESTOR_ADDR": "127.0.0.1:6969", "VM_IP": vm_ip, "GAME_SERVICES": services})

        validators = {
            "FRONTEND_ADDR": self.local.validate_host_port,
            "INGESTOR_ADDR": self.local.validate_host_port,
            "INGESTOR_ROTATE": self.local.validate_duration,
            "TICK_START": self.local.validate_datetime,
            "FLAG_REGEX": self.local.validate_regex,
            "VM_IP": self.local.validate_ip_address,
        }
        for key, validator in validators.items():
            config[key] = validator(config[key])
        if config["GAME_SERVICES"]:
            config["GAME_SERVICES"] = self.local.validate_service_list(config["GAME_SERVICES"])
        return config

    @staticmethod
    def _env_value(value: str) -> str:
        return value.replace("$", "$$").replace('"', '\\"').replace("\n", "")

    def write_remote_config(self, config: Dict[str, str], interface: str, sudo_mode: str) -> None:
        if self.local.env_path.exists() and not self.args.no_backup:
            backup = self.local.backup_env_file()
            if backup:
                print(f"✓ Backup created: {backup}")
        self.local.create_directory(config["TRAFFIC_DIR"])
        self.local.write_env_file(config)

        remote_values = {
            "REMOTE_SSH_HOST": self.args.ssh_host,
            "REMOTE_SSH_PORT": str(self.args.ssh_port),
            "REMOTE_SSH_USER": self.args.ssh_user,
            "REMOTE_SSH_AUTH": self.args.ssh_auth,
            "REMOTE_SSH_DIR": "./.tulip/ssh",
            "REMOTE_SSH_IDENTITY_FILE": "/root/.ssh/id_remote",
            "REMOTE_SSH_PASSWORD_FILE": "/root/.ssh/password",
            "REMOTE_CAPTURE_INTERFACE": interface,
            "REMOTE_CAPTURE_FILTER": self.args.capture_filter,
            "REMOTE_CAPTURE_SNAPLEN": str(self.args.snaplen),
            "REMOTE_CAPTURE_USE_SUDO": sudo_mode,
        }
        with self.local.env_path.open("a", encoding="utf-8") as env_file:
            env_file.write("\n# Remote capture (managed by remote_setup.py)\n")
            for key, value in remote_values.items():
                env_file.write(f'{key}="{self._env_value(value)}"\n')
        print("✓ Wrote local Tulip and remote-capture configuration")

    def start(self) -> None:
        print("\n🚀 Starting local Tulip and the remote capture service...\n")
        result = subprocess.run(["docker", "compose", "--profile", "remote", "up", "-d", "--build"])
        if result.returncode != 0:
            raise RemoteSetupError("docker compose failed to start Tulip")
        self.local.wait_for_running_services(timeout_seconds=30)

    def run(self) -> None:
        self.args = self.parse_args()
        for command in ("docker", "ssh", "ssh-keygen", "ssh-keyscan"):
            if shutil.which(command) is None:
                raise RemoteSetupError(f"Required local command was not found in PATH: {command}")
        if not self.args.ssh_host:
            if not sys.stdin.isatty():
                raise RemoteSetupError("Pass --ssh-host when setup is non-interactive")
            self.args.ssh_host = input("Remote server IP or hostname: ").strip()
        if not self.args.ssh_host:
            raise RemoteSetupError("Remote SSH host cannot be empty")
        if not self.args.ssh_user:
            if not sys.stdin.isatty():
                raise RemoteSetupError("Pass --ssh-user when setup is non-interactive")
            default_user = os.environ.get("USER", "root")
            self.args.ssh_user = input(f"Remote SSH user [{default_user}]: ").strip() or default_user
        if not 1 <= self.args.ssh_port <= 65535:
            raise RemoteSetupError("--ssh-port must be between 1 and 65535")
        if self.args.snaplen < 0:
            raise RemoteSetupError("--snaplen must be non-negative")

        print("\n🌷 Tulip Remote Setup\n" + "=" * 60)
        self.prepare_ssh_material()
        interface, vm_ip = self.discover_interface_and_ip()
        services = self.discover_services()
        sudo_mode = self.verify_remote_capture_prerequisites()
        config = self.build_config(vm_ip, services)
        self.write_remote_config(config, interface, sudo_mode)

        if not self.args.no_start:
            self.start()
        print("\nTulip is configured locally.")
        print(f"UI: http://{config['FRONTEND_ADDR'].replace('0.0.0.0', 'localhost')}")
        print("Remote capture status: docker compose --profile remote logs -f remote-capture")


if __name__ == "__main__":
    try:
        RemoteSetup().run()
    except (RemoteSetupError, ValidationError, subprocess.TimeoutExpired) as error:
        print(f"\n❌ Remote setup failed: {error}", file=sys.stderr)
        sys.exit(1)
