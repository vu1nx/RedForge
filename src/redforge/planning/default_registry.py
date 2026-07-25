"""Default Registry v2 construction from canonical built-in definitions."""

from redforge.planning.registry import CapabilityRegistry
from redforge.sdk.default_capabilities import DEFAULT_CAPABILITY_DEFINITIONS


def create_default_registry() -> CapabilityRegistry:
    """Return a new registry containing current capability state contracts."""
    return CapabilityRegistry(DEFAULT_CAPABILITY_DEFINITIONS)
