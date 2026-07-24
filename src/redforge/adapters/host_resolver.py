"""Standard-library host resolver adapter."""

import socket
from ipaddress import ip_address
from typing import Protocol

from redforge.adapters.errors import AdapterUnavailableError


class HostResolverError(AdapterUnavailableError):
    """Expected inability to resolve a hostname."""


class HostResolver(Protocol):
    """Minimal hostname resolution port."""

    def resolve(self, hostname: str) -> tuple[str, ...]:
        """Return canonical address strings for a normalized hostname."""
        ...


class StandardHostResolver:
    """Resolve IPv4 and IPv6 addresses using the operating system resolver."""

    def resolve(self, hostname: str) -> tuple[str, ...]:
        """Return unique canonical addresses in deterministic order."""
        try:
            records = socket.getaddrinfo(
                hostname,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as error:
            raise HostResolverError("hostname resolution failed") from error

        addresses: set[str] = set()
        for record in records:
            try:
                value = record[4][0]
                addresses.add(str(ip_address(value)))
            except (IndexError, TypeError, ValueError):
                continue
        if not addresses:
            raise HostResolverError("hostname resolution returned no valid addresses")
        return tuple(sorted(addresses, key=_address_sort_key))


def _address_sort_key(value: str) -> tuple[int, str]:
    parsed = ip_address(value)
    return (parsed.version, str(parsed))
