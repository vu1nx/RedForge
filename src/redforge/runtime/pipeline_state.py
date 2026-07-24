"""Centralized keys for pipeline state propagation."""


class PipelineStateKey:
    """State keys used to pass data between pipeline capabilities."""

    HOSTS = "hosts"
    SUBDOMAINS = "subdomains"
    ALIVE_HOSTS = "alive_hosts"
    ENDPOINTS = "endpoints"
    TECHNOLOGIES = "technologies"
    ASSET_INTELLIGENCE = "asset_intelligence"
    VULNERABILITY_INTELLIGENCE = "vulnerability_intelligence"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    RISK_INTELLIGENCE = "risk_intelligence"


CAPABILITY_OUTPUT_KEYS: dict[str, str] = {
    "subdomain_discovery": PipelineStateKey.SUBDOMAINS,
    "host_resolution": PipelineStateKey.HOSTS,
    "http_probe": PipelineStateKey.ALIVE_HOSTS,
    "web_crawl": PipelineStateKey.ENDPOINTS,
    "technology_detection": PipelineStateKey.TECHNOLOGIES,
    "asset_intelligence": PipelineStateKey.ASSET_INTELLIGENCE,
    "vulnerability_intelligence": PipelineStateKey.VULNERABILITY_INTELLIGENCE,
    "knowledge_graph": PipelineStateKey.KNOWLEDGE_GRAPH,
    "risk_intelligence": PipelineStateKey.RISK_INTELLIGENCE,
}
