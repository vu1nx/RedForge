"""Adapter for ProjectDiscovery Subfinder."""

import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from redforge.adapters.errors import (
    AdapterConfigurationError,
    AdapterError,
    AdapterUnavailableError,
)

if TYPE_CHECKING:
    from collections.abc import Sequence


class SubfinderAdapterError(AdapterError):
    """Base exception for Subfinder adapter errors."""

    pass


class SubfinderNotFoundError(SubfinderAdapterError, AdapterConfigurationError):
    """Raised when Subfinder binary is not found."""

    pass


class SubfinderExecutionError(SubfinderAdapterError, AdapterUnavailableError):
    """Raised when Subfinder execution fails."""

    def __init__(self, returncode: int, stderr: str) -> None:
        self.returncode = returncode
        del stderr
        super().__init__(f"Subfinder execution failed with return code {returncode}")


@dataclass(frozen=True, slots=True)
class SubdomainDiscoveryResult:
    """Typed deterministic candidate-hostname output."""

    hostnames: tuple[str, ...] = ()


class SubdomainProvider(Protocol):
    """Minimal candidate hostname discovery port."""

    def discover(self, domain: str) -> SubdomainDiscoveryResult:
        """Discover candidate hostnames for a target domain."""
        ...


class SubfinderAdapter:
    """Adapter for executing Subfinder and parsing its output.

    This adapter handles subprocess execution, output capture, and parsing
    of discovered subdomains from Subfinder.
    """

    def __init__(self, binary_path: str = "subfinder") -> None:
        """Initialize the Subfinder adapter.

        Args:
            binary_path: Path to the Subfinder binary (default: "subfinder").
        """
        self.binary_path = binary_path

    def verify_binary(self) -> None:
        """Verify that Subfinder binary exists and is executable.

        Raises:
            SubfinderNotFoundError: If Subfinder binary is not found.
        """
        if not shutil.which(self.binary_path):
            raise SubfinderNotFoundError("Subfinder binary not found")

    def discover_subdomains(self, domain: str) -> list[str]:
        """Discover subdomains for the given domain using Subfinder.

        Args:
            domain: The target domain for subdomain discovery.

        Returns:
            A list of discovered subdomains.

        Raises:
            SubfinderNotFoundError: If Subfinder binary is not found.
            SubfinderExecutionError: If Subfinder execution fails.
        """
        self.verify_binary()

        command: Sequence[str] = [self.binary_path, "-d", domain, "-silent"]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise SubfinderExecutionError(e.returncode, e.stderr) from e

        # Parse output - one subdomain per line
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return subdomains

    def discover(self, domain: str) -> SubdomainDiscoveryResult:
        """Implement the typed discovery provider port."""
        hostnames = {
            item.strip().lower().removesuffix(".")
            for item in self.discover_subdomains(domain)
            if item.strip()
        }
        return SubdomainDiscoveryResult(hostnames=tuple(sorted(hostnames)))
