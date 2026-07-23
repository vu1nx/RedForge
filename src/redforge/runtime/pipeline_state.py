"""Centralized keys for pipeline state propagation."""


class PipelineStateKey:
    """State keys used to pass data between pipeline capabilities."""

    HOSTS = "hosts"
    SUBDOMAINS = "subdomains"
    ALIVE_HOSTS = "alive_hosts"
    ENDPOINTS = "endpoints"
    TECHNOLOGIES = "technologies"


CAPABILITY_OUTPUT_KEYS: dict[str, str] = {
    "subdomain_discovery": PipelineStateKey.SUBDOMAINS,
    "http_probe": PipelineStateKey.ALIVE_HOSTS,
    "web_crawl": PipelineStateKey.ENDPOINTS,
    "technology_detection": PipelineStateKey.TECHNOLOGIES,
}
