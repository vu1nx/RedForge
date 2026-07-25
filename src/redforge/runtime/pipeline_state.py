"""Centralized keys for pipeline state propagation."""

from collections.abc import Mapping
from types import MappingProxyType

from redforge.sdk.capability_id import CapabilityId
from redforge.sdk.default_capabilities import DEFAULT_CAPABILITY_DEFINITIONS
from redforge.sdk.state import PipelineStateKey

CAPABILITY_OUTPUT_CONTRACTS: Mapping[
    CapabilityId, tuple[PipelineStateKey, ...]
] = MappingProxyType(
    {
        definition.capability_id: definition.provides
        for definition in DEFAULT_CAPABILITY_DEFINITIONS
    }
)
"""Default immutable output contracts for manual pipelines."""


CAPABILITY_OUTPUT_KEYS: Mapping[str, str] = MappingProxyType(
    {
        capability_id.value: state_keys[0]
        for capability_id, state_keys in CAPABILITY_OUTPUT_CONTRACTS.items()
        if len(state_keys) == 1
    }
)
"""Legacy single-output view retained for compatibility."""
