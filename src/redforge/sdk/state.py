"""Typed state-key identities shared by capabilities and the runtime."""

from enum import StrEnum
from typing import cast


class PipelineStateKey(StrEnum):
    """Canonical keys used to pass typed data between capabilities."""

    HOSTS = "hosts"
    SUBDOMAINS = "subdomains"
    ALIVE_HOSTS = "alive_hosts"
    HTTP_ENDPOINTS = "http_endpoints"
    ENDPOINTS = "endpoints"
    TECHNOLOGIES = "technologies"
    ASSET_INTELLIGENCE = "asset_intelligence"
    VULNERABILITY_INTELLIGENCE = "vulnerability_intelligence"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    RISK_INTELLIGENCE = "risk_intelligence"


def validate_pipeline_state_value(key: PipelineStateKey, value: object) -> None:
    """Validate state contracts whose immutable domain types are canonical."""
    if key is PipelineStateKey.ALIVE_HOSTS:
        from redforge.domain.host import Host

        _validate_typed_tuple(value, Host, key)
    elif key is PipelineStateKey.HTTP_ENDPOINTS:
        from redforge.domain.http_probe import HttpProbeEndpoint

        _validate_typed_tuple(value, HttpProbeEndpoint, key)


def _validate_typed_tuple(
    value: object,
    item_type: type[object],
    key: PipelineStateKey,
) -> None:
    if not isinstance(value, tuple) or not all(
        isinstance(item, item_type) for item in cast(tuple[object, ...], value)
    ):
        raise TypeError(f"state value for '{key.value}' has an invalid type")
