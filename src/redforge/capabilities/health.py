"""Health capability for validating Runtime and SDK integration."""

from typing import Any

from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


class HealthCapability(Capability):
    """Health check capability for validating Runtime and SDK integration.

    This capability is used to verify that the Runtime and SDK are working
    together correctly. It performs no external operations and simply returns
    a successful result.
    """

    def execute(self, context: Context) -> Result[dict[str, Any]]:
        """Execute the health check capability.

        Args:
            context: Runtime context (not used in this capability).

        Returns:
            A successful Result indicating the Runtime and SDK are operational.
        """
        return Result(
            status=Status.SUCCESS,
            data={"message": "Runtime and SDK are operational", "target_id": context.target_id},
        )

    @property
    def name(self) -> str:
        """Get the name of the capability.

        Returns:
            The capability name.
        """
        return "health"
