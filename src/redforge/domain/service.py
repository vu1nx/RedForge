"""Service domain model."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Service:
    """Represents a network service running on a host.

    A service is a specific application or daemon that provides network functionality.
    """

    name: str
    """Name of the service."""

    port: int
    """Port number on which the service listens."""

    protocol: str
    """Network protocol used by the service (e.g., tcp, udp)."""

    version: str | None = None
    """Version of the service software."""

    description: str | None = None
    """Additional description or context about the service."""
