"""Host domain model."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address


@dataclass(frozen=True, slots=True)
class Host:
    """Represents a host machine or server.

    A host is a computing device that can be addressed via IP address.
    """

    address: IPv4Address | IPv6Address
    """IP address of the host."""

    hostname: str | None = None
    """Hostname of the host."""

    operating_system: str | None = None
    """Operating system running on the host."""

    description: str | None = None
    """Additional description or context about the host."""
