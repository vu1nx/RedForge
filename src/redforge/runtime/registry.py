"""Capability registry for registration and lookup."""

from typing import TYPE_CHECKING

from redforge.runtime.exceptions import CapabilityNotFoundError, DuplicateCapabilityError

if TYPE_CHECKING:
    from redforge.sdk.capability import Capability


class CapabilityRegistry:
    """Registry for managing capability registration and lookup.

    The registry stores capability instances and provides methods to
    register and retrieve them by name.
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._capabilities: dict[str, Capability] = {}

    def register(self, capability: "Capability") -> None:
        """Register a capability instance.

        Args:
            capability: The capability instance to register.

        Raises:
            DuplicateCapabilityError: If a capability with the same name is already registered.
        """
        name = capability.name
        if name in self._capabilities:
            raise DuplicateCapabilityError(name)
        self._capabilities[name] = capability

    def get(self, name: str) -> "Capability":
        """Retrieve a capability instance by name.

        Args:
            name: The name of the capability to retrieve.

        Returns:
            The capability instance.

        Raises:
            CapabilityNotFoundError: If no capability with the given name is registered.
        """
        if name not in self._capabilities:
            raise CapabilityNotFoundError(name)
        return self._capabilities[name]

    def list_names(self) -> list[str]:
        """List all registered capability names.

        Returns:
            A list of registered capability names.
        """
        return list(self._capabilities.keys())

    def is_registered(self, name: str) -> bool:
        """Check if a capability is registered.

        Args:
            name: The name of the capability to check.

        Returns:
            True if the capability is registered, False otherwise.
        """
        return name in self._capabilities
