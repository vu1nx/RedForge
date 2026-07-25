"""Centralized keys for pipeline state propagation."""

from collections.abc import Mapping
from types import MappingProxyType

from redforge.sdk.state import PipelineStateKey

CAPABILITY_OUTPUT_CONTRACTS: Mapping[str, tuple[PipelineStateKey, ...]] = MappingProxyType(
    {
        "subdomain_discovery": (PipelineStateKey.SUBDOMAINS,),
        "host_resolution": (PipelineStateKey.HOSTS,),
        "http_probe": (PipelineStateKey.ALIVE_HOSTS,),
        "web_crawl": (PipelineStateKey.ENDPOINTS,),
        "technology_detection": (PipelineStateKey.TECHNOLOGIES,),
        "asset_intelligence": (PipelineStateKey.ASSET_INTELLIGENCE,),
        "vulnerability_intelligence": (PipelineStateKey.VULNERABILITY_INTELLIGENCE,),
        "knowledge_graph": (PipelineStateKey.KNOWLEDGE_GRAPH,),
        "risk_intelligence": (PipelineStateKey.RISK_INTELLIGENCE,),
    }
)
"""Default immutable output contracts for manual pipelines."""


CAPABILITY_OUTPUT_KEYS: Mapping[str, str] = MappingProxyType(
    {name: state_keys[0] for name, state_keys in CAPABILITY_OUTPUT_CONTRACTS.items()}
)
"""Legacy single-output view retained for compatibility."""
