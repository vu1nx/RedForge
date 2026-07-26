"""Tool-agnostic subdomain discovery capability."""

from dataclasses import replace
from typing import cast

from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status
from redforge.sdk.subdomain_discovery import (
    SubdomainDiscoveryResult,
    SubdomainDiscoveryStatus,
    SubdomainProvider,
)


class _UnavailableSubdomainProvider:
    """Safe manual-construction default with no external execution."""

    def discover(self, domain: str) -> SubdomainDiscoveryResult:
        del domain
        return SubdomainDiscoveryResult(
            status=SubdomainDiscoveryStatus.UNAVAILABLE,
            message="Subdomain discovery provider is unavailable.",
        )


class SubdomainDiscovery(Capability):
    """Discover subdomains through an injected replaceable domain provider."""

    def __init__(self, *, provider: SubdomainProvider | None = None) -> None:
        self._provider = provider or _UnavailableSubdomainProvider()

    def execute(self, context: Context) -> Result[SubdomainDiscoveryResult]:
        """Run one provider call and map its domain status to runtime status."""
        try:
            response = cast(object, self._provider.discover(context.target_id))
        except Exception:
            return self._error_result(
                "Subdomain provider failed with an unexpected execution error"
            )
        if not isinstance(response, SubdomainDiscoveryResult):
            return self._error_result(
                "Subdomain provider returned an invalid result"
            )

        hostnames = tuple(sorted(set(response.hostnames)))
        output = replace(response, hostnames=hostnames)
        provider_status = response.status
        if provider_status is SubdomainDiscoveryStatus.SUCCESS:
            status = Status.SUCCESS
        elif provider_status is SubdomainDiscoveryStatus.PARTIAL:
            status = Status.PARTIAL if hostnames else Status.FAILURE
        elif provider_status is SubdomainDiscoveryStatus.FAILURE:
            status = Status.FAILURE
        else:
            status = Status.ERROR

        errors = (
            []
            if status is Status.SUCCESS
            else [
                response.message
                or (
                    "Subdomain discovery completed with partial findings"
                    if status is Status.PARTIAL
                    else "Subdomain discovery failed"
                )
            ]
        )
        return Result(
            status=status,
            data=output,
            errors=errors,
            metadata={
                "count": len(hostnames),
                "target_id": context.target_id,
                "provider_status": provider_status.value,
                "malformed_record_count": response.malformed_record_count,
                "out_of_scope_count": response.out_of_scope_count,
                "duplicate_count": response.duplicate_count,
                "truncated": response.truncated,
            },
        )

    @staticmethod
    def _error_result(message: str) -> Result[SubdomainDiscoveryResult]:
        return Result(
            status=Status.ERROR,
            errors=[message],
            data=SubdomainDiscoveryResult(
                status=SubdomainDiscoveryStatus.ERROR,
                message=message,
            ),
        )

    @property
    def name(self) -> str:
        """Return the stable capability identity."""
        return "subdomain_discovery"
