"""Adapter for ProjectDiscovery Katana."""

import contextlib
import json
import shutil
import subprocess
from typing import TYPE_CHECKING, Any, cast

from redforge.domain.endpoint import Endpoint

if TYPE_CHECKING:
    from collections.abc import Sequence


class KatanaAdapterError(Exception):
    """Base exception for Katana adapter errors."""

    pass


class KatanaNotFoundError(KatanaAdapterError):
    """Raised when Katana binary is not found."""

    pass


class KatanaExecutionError(KatanaAdapterError):
    """Raised when Katana execution fails."""

    def __init__(self, returncode: int, stderr: str) -> None:
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"Katana execution failed with return code {returncode}")


class KatanaParseError(KatanaAdapterError):
    """Raised when Katana output cannot be parsed."""

    pass


class KatanaAdapter:
    """Adapter for executing Katana and parsing its JSON output.

    This adapter handles subprocess execution, output capture, and parsing
    of web crawling results from Katana into Endpoint domain objects.
    """

    def __init__(self, binary_path: str = "katana") -> None:
        """Initialize the Katana adapter.

        Args:
            binary_path: Path to the Katana binary (default: "katana").
        """
        self.binary_path = binary_path

    def verify_binary(self) -> None:
        """Verify that Katana binary exists and is executable.

        Raises:
            KatanaNotFoundError: If Katana binary is not found.
        """
        if not shutil.which(self.binary_path):
            raise KatanaNotFoundError(f"Katana binary not found: {self.binary_path}")

    def crawl_hosts(self, hosts: list[str]) -> list[Endpoint]:
        """Crawl hosts for endpoints using Katana.

        Args:
            hosts: List of host URLs to crawl.

        Returns:
            List of discovered endpoints.

        Raises:
            KatanaNotFoundError: If Katana binary is not found.
            KatanaExecutionError: If Katana execution fails.
            KatanaParseError: If Katana output cannot be parsed.
        """
        if not hosts:
            return []

        self.verify_binary()

        input_text = "\n".join(hosts)
        command: Sequence[str] = [
            self.binary_path,
            "-list",
            "-",
            "-json",
            "-silent",
            "-depth",
            "2",
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
            raise KatanaExecutionError(e.returncode, e.stderr) from e

        return self._parse_output(result.stdout)

    def _parse_output(self, stdout: str) -> list[Endpoint]:
        endpoints: list[Endpoint] = []
        seen: set[tuple[str, int, str, str | None]] = set()

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError as e:
                raise KatanaParseError(f"Failed to parse Katana JSON output: {e}") from e

            if not isinstance(parsed, dict):
                raise KatanaParseError("Katana JSON output must be an object")

            entry = cast(dict[str, Any], parsed)
            endpoint = self._entry_to_endpoint(entry)
            if endpoint is None:
                continue

            key = (endpoint.host, endpoint.port, endpoint.protocol, endpoint.path)
            if key in seen:
                continue

            seen.add(key)
            endpoints.append(endpoint)

        return endpoints

    def _entry_to_endpoint(self, entry: dict[str, Any]) -> Endpoint | None:
        url = entry.get("url")
        if not isinstance(url, str) or not url:
            return None

        return self._url_to_endpoint(url)

    def _url_to_endpoint(self, url: str) -> Endpoint:
        """Convert a URL string to an Endpoint object."""
        # Parse URL components
        protocol = "http"
        if url.startswith("https://"):
            protocol = "https"
            url = url[8:]
        elif url.startswith("http://"):
            url = url[7:]

        # Extract host and path
        parts = url.split("/", 1)
        host_part = parts[0]
        path = "/" + parts[1] if len(parts) > 1 else "/"

        # Extract port
        port = 443 if protocol == "https" else 80
        if ":" in host_part:
            host, port_str = host_part.rsplit(":", 1)
            with contextlib.suppress(ValueError):
                port = int(port_str)
        else:
            host = host_part

        return Endpoint(host=host, port=port, protocol=protocol, path=path)
