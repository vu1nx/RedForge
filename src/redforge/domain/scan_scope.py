"""Immutable DNS-root scan target and authorization scope."""

import re
from dataclasses import dataclass
from ipaddress import ip_address
from typing import cast

from redforge.domain.endpoint import Endpoint
from redforge.domain.hostname import normalize_dns_hostname

_EXACT_ORIGIN_PATTERN = re.compile(
    r"(?P<scheme>http|https)://"
    r"(?P<hostname>[^/?#:@\s]+):"
    r"(?P<port>[0-9]{1,5})/?"
)


@dataclass(frozen=True, slots=True, order=True)
class ScanTarget:
    """Canonical application-approved DNS root domain."""

    value: str

    def __post_init__(self) -> None:
        value = cast(object, self.value)
        if not isinstance(value, str):
            raise ValueError("scan target is invalid")
        try:
            normalized = normalize_dns_hostname(value)
        except ValueError:
            raise ValueError("scan target is invalid") from None
        object.__setattr__(self, "value", normalized)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True, init=False)
class ExactNetworkTarget:
    """One canonical HTTP origin bound to one expected IP address."""

    value: str
    scheme: str
    hostname: str
    port: int
    expected_ip: str

    def __init__(self, value: str, *, expected_ip: str) -> None:
        if not isinstance(cast(object, value), str):
            raise ValueError("exact network target is invalid")
        match = _EXACT_ORIGIN_PATTERN.fullmatch(value)
        if match is None:
            raise ValueError("exact network target is invalid")
        try:
            hostname = normalize_dns_hostname(match.group("hostname"))
            address = str(ip_address(expected_ip))
            port = int(match.group("port"))
        except (TypeError, ValueError):
            raise ValueError("exact network target is invalid") from None
        if not 1 <= port <= 65_535:
            raise ValueError("exact network target is invalid")
        scheme = match.group("scheme")
        canonical = f"{scheme}://{hostname}:{port}"
        object.__setattr__(self, "value", canonical)
        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "hostname", hostname)
        object.__setattr__(self, "port", port)
        object.__setattr__(self, "expected_ip", address)

    def __str__(self) -> str:
        return self.value

    def contains_endpoint(self, endpoint: Endpoint) -> bool:
        """Return whether an endpoint remains inside this exact origin."""
        endpoint_value = cast(object, endpoint)
        return (
            isinstance(endpoint_value, Endpoint)
            and endpoint.protocol == self.scheme
            and endpoint.host == self.hostname
            and endpoint.port == self.port
        )


@dataclass(frozen=True, slots=True)
class ScanScope:
    """Authorization policy for exactly one DNS root and its subdomains."""

    root: ScanTarget | ExactNetworkTarget

    def __post_init__(self) -> None:
        if not isinstance(
            cast(object, self.root), (ScanTarget, ExactNetworkTarget)
        ):
            raise TypeError(
                "scan scope requires a ScanTarget or ExactNetworkTarget"
            )

    def contains_hostname(self, hostname: str) -> bool:
        """Return whether a valid DNS hostname is the root or its subdomain."""
        try:
            normalized = normalize_dns_hostname(hostname)
        except (TypeError, ValueError):
            return False
        if isinstance(self.root, ExactNetworkTarget):
            return normalized == self.root.hostname
        root = self.root.value
        return normalized == root or normalized.endswith(f".{root}")

    def contains_endpoint(self, endpoint: Endpoint) -> bool:
        """Return whether an HTTP(S) DNS endpoint stays inside this scope."""
        endpoint_value = cast(object, endpoint)
        if not isinstance(endpoint_value, Endpoint):
            return False
        if isinstance(self.root, ExactNetworkTarget):
            return self.root.contains_endpoint(endpoint)
        if endpoint.protocol not in {"http", "https"}:
            return False
        if (
            not isinstance(cast(object, endpoint.port), int)
            or isinstance(cast(object, endpoint.port), bool)
            or not 1 <= endpoint.port <= 65535
        ):
            return False
        return self.contains_hostname(endpoint.host)
