"""RedForge Adapters.

This package contains adapters for external tools and services.
"""

from redforge.adapters.errors import (
    AdapterConfigurationError,
    AdapterError,
    AdapterResponseError,
    AdapterUnavailableError,
)
from redforge.adapters.host_resolver import HostResolver, StandardHostResolver
from redforge.adapters.httpx import (
    HttpProbeAdapterResult,
    HttpProbeTransport,
    HttpxAdapter,
)
from redforge.adapters.katana import (
    KatanaAdapter,
    WebCrawlAdapterResult,
    WebCrawler,
)
from redforge.adapters.nvd import NvdAdapter, VulnerabilityProvider
from redforge.adapters.subfinder import (
    SubdomainDiscoveryResult,
    SubdomainProvider,
    SubfinderAdapter,
)
from redforge.adapters.technology_detection import (
    TechnologyDetectionAdapter,
    TechnologyDetectionResult,
    TechnologyDetector,
)

__all__ = [
    "HttpxAdapter",
    "AdapterConfigurationError",
    "AdapterError",
    "AdapterResponseError",
    "AdapterUnavailableError",
    "HostResolver",
    "HttpProbeAdapterResult",
    "HttpProbeTransport",
    "StandardHostResolver",
    "KatanaAdapter",
    "NvdAdapter",
    "SubdomainDiscoveryResult",
    "SubdomainProvider",
    "SubfinderAdapter",
    "TechnologyDetectionAdapter",
    "TechnologyDetectionResult",
    "TechnologyDetector",
    "VulnerabilityProvider",
    "WebCrawlAdapterResult",
    "WebCrawler",
]
