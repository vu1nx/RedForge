"""Subdomain discovery capability using Subfinder."""

from typing import Any

from redforge.adapters.subfinder import SubfinderAdapter, SubfinderAdapterError
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


class SubdomainDiscovery(Capability):
    """Subdomain discovery capability using ProjectDiscovery Subfinder.

    This capability discovers subdomains for a target domain using the
    Subfinder external tool through the adapter pattern.
    """

    def __init__(self, binary_path: str = "subfinder") -> None:
        """Initialize the subdomain discovery capability.

        Args:
            binary_path: Path to the Subfinder binary (default: "subfinder").
        """
        self._adapter = SubfinderAdapter(binary_path=binary_path)

    def execute(self, context: Context) -> Result[dict[str, Any]]:
        """Execute subdomain discovery.

        Args:
            context: Runtime context containing the target domain.

        Returns:
            Result containing discovered subdomains or error information.
        """
        target_id = context.target_id

        try:
            subdomains = self._adapter.discover_subdomains(target_id)
            return Result(
                status=Status.SUCCESS,
                data={
                    "subdomains": subdomains,
                    "count": len(subdomains),
                    "target_id": target_id,
                },
            )
        except SubfinderAdapterError as e:
            return Result(
                status=Status.ERROR,
                errors=[str(e)],
                data={"target_id": target_id},
            )

    @property
    def name(self) -> str:
        """Get the name of the capability.

        Returns:
            The capability name.
        """
        return "subdomain_discovery"
