"""Subdomain discovery capability using Subfinder."""

from typing import cast

from redforge.adapters.errors import AdapterError
from redforge.adapters.subfinder import (
    SubdomainDiscoveryResult,
    SubdomainProvider,
    SubfinderAdapter,
)
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


class SubdomainDiscovery(Capability):
    """Subdomain discovery capability using ProjectDiscovery Subfinder.

    This capability discovers subdomains for a target domain using the
    Subfinder external tool through the adapter pattern.
    """

    def __init__(
        self,
        binary_path: str = "subfinder",
        *,
        provider: SubdomainProvider | None = None,
    ) -> None:
        """Initialize the subdomain discovery capability.

        Args:
            binary_path: Path to the Subfinder binary (default: "subfinder").
        """
        self._provider = provider or SubfinderAdapter(binary_path=binary_path)

    def execute(self, context: Context) -> Result[SubdomainDiscoveryResult]:
        """Execute subdomain discovery.

        Args:
            context: Runtime context containing the target domain.

        Returns:
            Result containing discovered subdomains or error information.
        """
        target_id = context.target_id

        try:
            response = cast(object, self._provider.discover(target_id))
        except AdapterError:
            return Result(
                status=Status.FAILURE,
                errors=["Subdomain provider is unavailable"],
                data=SubdomainDiscoveryResult(),
            )
        except Exception:
            return Result(
                status=Status.ERROR,
                errors=["Subdomain provider failed with an unexpected execution error"],
                data=SubdomainDiscoveryResult(),
            )
        if not isinstance(response, SubdomainDiscoveryResult):
            return Result(
                status=Status.ERROR,
                errors=["Subdomain provider returned an invalid result"],
                data=SubdomainDiscoveryResult(),
            )
        response_hostnames = cast(object, response.hostnames)
        if not isinstance(response_hostnames, tuple) or not all(
            isinstance(item, str) and item
            for item in cast(tuple[object, ...], response_hostnames)
        ):
            return Result(
                status=Status.ERROR,
                errors=["Subdomain provider returned an invalid result"],
                data=SubdomainDiscoveryResult(),
            )
        hostnames = tuple(
            sorted(set(cast(tuple[str, ...], response_hostnames)))
        )
        output = SubdomainDiscoveryResult(hostnames=hostnames)
        return Result(
            status=Status.SUCCESS,
            data=output,
            metadata={"count": len(hostnames), "target_id": target_id},
        )

    @property
    def name(self) -> str:
        """Get the name of the capability.

        Returns:
            The capability name.
        """
        return "subdomain_discovery"
