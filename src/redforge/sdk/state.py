"""Typed state-key identities shared by capabilities and the runtime."""

from enum import StrEnum


class PipelineStateKey(StrEnum):
    """Canonical keys used to pass typed data between capabilities."""

    HOSTS = "hosts"
    SUBDOMAINS = "subdomains"
    ALIVE_HOSTS = "alive_hosts"
    ENDPOINTS = "endpoints"
    TECHNOLOGIES = "technologies"
    ASSET_INTELLIGENCE = "asset_intelligence"
    VULNERABILITY_INTELLIGENCE = "vulnerability_intelligence"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    RISK_INTELLIGENCE = "risk_intelligence"
