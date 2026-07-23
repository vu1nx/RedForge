"""Endpoint domain model."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Endpoint:
    """Represents a network endpoint.

    An endpoint is a specific destination for network communication,
    combining address, port, and protocol information.
    """

    host: str
    """Host address or hostname."""

    port: int
    """Port number."""

    protocol: str
    """Network protocol (e.g., http, https, tcp, udp)."""

    path: str | None = None
    """Path or resource identifier (for HTTP-based endpoints)."""

    description: str | None = None
    """Additional description or context about the endpoint."""
