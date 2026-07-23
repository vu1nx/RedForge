"""Capability discovery and registration system."""

from collections.abc import Sequence
from typing import TYPE_CHECKING

from redforge.runtime.registry import CapabilityRegistry

if TYPE_CHECKING:
    from redforge.sdk.capability import Capability


def register_capabilities(registry: CapabilityRegistry, capabilities: Sequence["Capability"]) -> None:
    """Register multiple capabilities to the registry.

    This function allows bulk registration of capabilities, making it easy
    to register all available capabilities at once without hardcoding each
    registration individually.

    Args:
        registry: The capability registry to register to.
        capabilities: A sequence of capability instances to register.

    Raises:
        DuplicateCapabilityError: If a capability with the same name is already registered.
    """
    for capability in capabilities:
        registry.register(capability)
