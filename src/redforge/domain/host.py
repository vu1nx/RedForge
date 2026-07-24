"""Resolved host domain models."""

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import cast


class IPVersion(StrEnum):
    """Supported Internet Protocol address versions."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"


@dataclass(frozen=True, slots=True)
class HostAddress:
    """One canonical IP address associated with a hostname."""

    value: str
    version: IPVersion

    def __post_init__(self) -> None:
        parsed = ip_address(self.value)
        expected = IPVersion.IPV4 if parsed.version == 4 else IPVersion.IPV6
        if self.version != expected:
            raise ValueError("host address version does not match its value")
        object.__setattr__(self, "value", str(parsed))


@dataclass(frozen=True, slots=True, init=False)
class Host:
    """A hostname and its explicit resolved network addresses."""

    hostname: str | None
    addresses: tuple[HostAddress, ...]
    evidence: tuple[str, ...]
    operating_system: str | None
    description: str | None

    def __init__(
        self,
        hostname: str | None = None,
        addresses: tuple[HostAddress, ...] = (),
        evidence: tuple[str, ...] = (),
        *,
        address: IPv4Address | IPv6Address | None = None,
        operating_system: str | None = None,
        description: str | None = None,
    ) -> None:
        """Create a host, accepting the legacy single-address keyword."""
        if address is not None:
            if addresses:
                raise ValueError("use either address or addresses, not both")
            addresses = (
                HostAddress(
                    value=str(address),
                    version=(
                        IPVersion.IPV4
                        if isinstance(address, IPv4Address)
                        else IPVersion.IPV6
                    ),
                ),
            )
        address_values = cast(object, addresses)
        if not isinstance(address_values, tuple) or not all(
            isinstance(item, HostAddress)
            for item in cast(tuple[object, ...], address_values)
        ):
            raise TypeError("host addresses must be a tuple of HostAddress values")
        evidence_values = cast(object, evidence)
        if not isinstance(evidence_values, tuple) or not all(
            isinstance(item, str)
            for item in cast(tuple[object, ...], evidence_values)
        ):
            raise TypeError("host evidence must be a tuple of strings")
        object.__setattr__(self, "hostname", hostname)
        object.__setattr__(self, "addresses", addresses)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "operating_system", operating_system)
        object.__setattr__(self, "description", description)

    @property
    def address(self) -> IPv4Address | IPv6Address:
        """Return the first address for compatibility with single-address consumers."""
        if not self.addresses:
            raise ValueError("host has no resolved addresses")
        return ip_address(self.addresses[0].value)


@dataclass(frozen=True, slots=True)
class HostResolution:
    """Deterministic collection of resolved hosts."""

    hosts: tuple[Host, ...] = ()
