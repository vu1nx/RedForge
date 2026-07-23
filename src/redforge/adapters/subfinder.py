"""Adapter for ProjectDiscovery Subfinder."""

import shutil
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


class SubfinderAdapterError(Exception):
    """Base exception for Subfinder adapter errors."""

    pass


class SubfinderNotFoundError(SubfinderAdapterError):
    """Raised when Subfinder binary is not found."""

    pass


class SubfinderExecutionError(SubfinderAdapterError):
    """Raised when Subfinder execution fails."""

    def __init__(self, returncode: int, stderr: str) -> None:
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"Subfinder execution failed with return code {returncode}")


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
            raise SubfinderNotFoundError(f"Subfinder binary not found: {self.binary_path}")

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
