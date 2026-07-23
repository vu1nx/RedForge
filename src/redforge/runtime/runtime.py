"""Runtime for orchestrating capability execution."""

from collections.abc import Sequence
from typing import TYPE_CHECKING

from redforge.runtime.discovery import register_capabilities
from redforge.runtime.registry import CapabilityRegistry

if TYPE_CHECKING:
    from redforge.sdk.capability import Capability


class Runtime:
    """Runtime for managing and orchestrating capabilities.

    The runtime provides the minimal public API for capability management
    through a registry. Execution logic is not implemented in this foundation.
    """

    def __init__(self) -> None:
        """Initialize a new runtime with a capability registry."""
        self._registry = CapabilityRegistry()

    @property
    def registry(self) -> CapabilityRegistry:
        """Get the capability registry.

        Returns:
            The capability registry instance.
        """
        return self._registry

    def register_capabilities(self, capabilities: Sequence["Capability"]) -> None:
        """Register multiple capabilities to the runtime.

        Args:
            capabilities: A sequence of capability instances to register.

        Raises:
            DuplicateCapabilityError: If a capability with the same name is already registered.
        """
        register_capabilities(self._registry, capabilities)
