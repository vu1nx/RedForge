"""Immutable DNS-root scan target and authorization scope."""

from dataclasses import dataclass
from typing import cast

from redforge.domain.endpoint import Endpoint
from redforge.domain.hostname import normalize_dns_hostname


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


@dataclass(frozen=True, slots=True)
class ScanScope:
    """Authorization policy for exactly one DNS root and its subdomains."""

    root: ScanTarget

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.root), ScanTarget):
            raise TypeError("scan scope requires a ScanTarget")

    def contains_hostname(self, hostname: str) -> bool:
        """Return whether a valid DNS hostname is the root or its subdomain."""
        try:
            normalized = normalize_dns_hostname(hostname)
        except (TypeError, ValueError):
            return False
        root = self.root.value
        return normalized == root or normalized.endswith(f".{root}")

    def contains_endpoint(self, endpoint: Endpoint) -> bool:
        """Return whether an HTTP(S) DNS endpoint stays inside this scope."""
        endpoint_value = cast(object, endpoint)
        if not isinstance(endpoint_value, Endpoint):
            return False
        if endpoint.protocol not in {"http", "https"}:
            return False
        if (
            not isinstance(cast(object, endpoint.port), int)
            or isinstance(cast(object, endpoint.port), bool)
            or not 1 <= endpoint.port <= 65535
        ):
            return False
        return self.contains_hostname(endpoint.host)
