"""Adapter for ProjectDiscovery httpx."""

import json
import shutil
import subprocess
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import TYPE_CHECKING, Any, cast

from redforge.domain.host import Host

if TYPE_CHECKING:
    from collections.abc import Sequence


class HttpxAdapterError(Exception):
    """Base exception for httpx adapter errors."""

    pass


class HttpxNotFoundError(HttpxAdapterError):
    """Raised when httpx binary is not found."""

    pass


class HttpxExecutionError(HttpxAdapterError):
    """Raised when httpx execution fails."""

    def __init__(self, returncode: int, stderr: str) -> None:
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"httpx execution failed with return code {returncode}")


class HttpxParseError(HttpxAdapterError):
    """Raised when httpx output cannot be parsed."""

    pass


class HttpxAdapter:
    """Adapter for executing httpx and parsing its JSON output.

    This adapter handles subprocess execution, output capture, and parsing
    of HTTP probe results from httpx.
    """

    def __init__(self, binary_path: str = "httpx") -> None:
        """Initialize the httpx adapter.

        Args:
            binary_path: Path to the httpx binary (default: "httpx").
        """
        self.binary_path = binary_path

    def verify_binary(self) -> None:
        """Verify that httpx binary exists and is executable.

        Raises:
            HttpxNotFoundError: If httpx binary is not found.
        """
        if not shutil.which(self.binary_path):
            raise HttpxNotFoundError(f"httpx binary not found: {self.binary_path}")

    def probe_hosts(self, hosts: list[Host]) -> list[Host]:
        """Probe hosts for reachable HTTP/HTTPS services using httpx.

        Args:
            hosts: Hosts to probe.

        Returns:
            Hosts that responded to HTTP/HTTPS probing.

        Raises:
            HttpxNotFoundError: If httpx binary is not found.
            HttpxExecutionError: If httpx execution fails.
            HttpxParseError: If httpx output cannot be parsed.
        """
        if not hosts:
            return []

        self.verify_binary()

        input_text = "\n".join(self._host_to_input(host) for host in hosts)
        command: Sequence[str] = [
            self.binary_path,
            "-l",
            "-",
            "-json",
            "-silent",
            "-ip",
        ]
        try:
            result = subprocess.run(
                command,
                input=input_text,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise HttpxExecutionError(e.returncode, e.stderr) from e

        return self._parse_output(result.stdout)

    def _host_to_input(self, host: Host) -> str:
        if host.hostname:
            return host.hostname
        return str(host.address)

    def _parse_output(self, stdout: str) -> list[Host]:
        alive_hosts: list[Host] = []
        seen: set[tuple[str, str | None]] = set()

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError as e:
                raise HttpxParseError(f"Failed to parse httpx JSON output: {e}") from e

            if not isinstance(parsed, dict):
                raise HttpxParseError("httpx JSON output must be an object")

            entry = cast(dict[str, Any], parsed)
            host = self._entry_to_host(entry)
            if host is None:
                continue

            key = (str(host.address), host.hostname)
            if key in seen:
                continue

            seen.add(key)
            alive_hosts.append(host)

        return alive_hosts

    def _entry_to_host(self, entry: dict[str, Any]) -> Host | None:
        if entry.get("failed", False):
            return None

        hostname = self._extract_hostname(entry)
        address = self._extract_address(entry)
        if address is None:
            return None

        return Host(address=address, hostname=hostname)

    def _extract_hostname(self, entry: dict[str, Any]) -> str | None:
        input_value = entry.get("input")
        if isinstance(input_value, str) and input_value:
            return input_value
        return None

    def _extract_address(self, entry: dict[str, Any]) -> IPv4Address | IPv6Address | None:
        host_ip = entry.get("host_ip")
        if isinstance(host_ip, str) and host_ip:
            return self._parse_address(host_ip)

        a_records = entry.get("a")
        if isinstance(a_records, list):
            for record in cast(list[Any], a_records):
                if isinstance(record, str) and record:
                    return self._parse_address(record)

        host_field = entry.get("host")
        if isinstance(host_field, str) and host_field:
            try:
                return self._parse_address(host_field)
            except ValueError:
                return None

        return None

    def _parse_address(self, value: str) -> IPv4Address | IPv6Address:
        return ip_address(value)
