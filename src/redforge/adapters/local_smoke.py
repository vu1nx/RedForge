"""Network-free providers for one explicitly authorized local smoke origin."""

from typing import cast

from redforge.domain.scan_scope import ExactNetworkTarget
from redforge.sdk.subdomain_discovery import SubdomainDiscoveryResult


class LocalSeedSubdomainProvider:
    """Publish one configured hostname without subprocess or network access."""

    __slots__ = ("_target",)

    def __init__(self, target: ExactNetworkTarget) -> None:
        if not isinstance(cast(object, target), ExactNetworkTarget):
            raise TypeError("local seed discovery requires an exact target")
        self._target = target

    def discover(self, domain: str) -> SubdomainDiscoveryResult:
        """Return the authorized hostname only for the exact configured origin."""
        if domain != self._target.value:
            raise ValueError("local seed discovery target does not match")
        return SubdomainDiscoveryResult(hostnames=(self._target.hostname,))


class LocalStaticHostResolver:
    """Resolve only the configured hostname to its configured address."""

    __slots__ = ("_target",)

    def __init__(self, target: ExactNetworkTarget) -> None:
        if not isinstance(cast(object, target), ExactNetworkTarget):
            raise TypeError("local static resolver requires an exact target")
        self._target = target

    def resolve(self, hostname: str) -> tuple[str, ...]:
        """Return one static address without consulting DNS."""
        if hostname != self._target.hostname:
            raise ValueError("local static resolver target does not match")
        return (self._target.expected_ip,)


__all__ = [
    "LocalSeedSubdomainProvider",
    "LocalStaticHostResolver",
]
