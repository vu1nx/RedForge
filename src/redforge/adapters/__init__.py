"""RedForge Adapters.

This package contains adapters for external tools and services.
"""

from redforge.adapters.default_tools import create_default_tool_registry
from redforge.adapters.errors import (
    AdapterConfigurationError,
    AdapterError,
    AdapterResponseError,
    AdapterUnavailableError,
)
from redforge.adapters.host_resolver import HostResolver, StandardHostResolver
from redforge.adapters.httpx import (
    HTTPX_TOOL,
    HTTPX_TOOL_ID,
    HttpProbeAdapterResult,
    HttpProbeProvider,
    HttpProbeProviderResult,
    HttpProbeProviderStatus,
    HttpProbeTransport,
    HttpxConfig,
    HttpxProbeProvider,
)
from redforge.adapters.katana import (
    KATANA_TOOL,
    KATANA_TOOL_ID,
    KatanaAdapter,
    KatanaConfig,
    KatanaWebCrawlProvider,
    WebCrawlAdapterResult,
    WebCrawler,
)
from redforge.adapters.local_smoke import (
    LocalSeedSubdomainProvider,
    LocalStaticHostResolver,
)
from redforge.adapters.nuclei import (
    NUCLEI_TOOL,
    NUCLEI_TOOL_ID,
    NucleiConfig,
    NucleiVulnerabilityDetectionProvider,
)
from redforge.adapters.nvd import NvdAdapter, VulnerabilityProvider
from redforge.adapters.platform import (
    SystemPlatformInformationProbe,
    SystemPythonRuntimeInformationProbe,
)
from redforge.adapters.readiness import (
    ToolRunnerReadinessProbe,
    ToolRunnerVersionProbe,
)
from redforge.adapters.subfinder import (
    SUBFINDER_TOOL,
    SUBFINDER_TOOL_ID,
    SubdomainDiscoveryResult,
    SubdomainDiscoveryStatus,
    SubdomainProvider,
    SubfinderConfig,
    SubfinderSubdomainProvider,
)
from redforge.adapters.technology_detection import (
    WHATWEB_TOOL,
    WHATWEB_TOOL_ID,
    TechnologyDetectionAdapter,
    TechnologyDetectionResult,
    TechnologyDetector,
    WhatWebConfig,
    WhatWebTechnologyDetectionProvider,
)
from redforge.adapters.tool_runner import LocalSubprocessToolRunner

__all__ = [
    "HTTPX_TOOL",
    "HTTPX_TOOL_ID",
    "AdapterConfigurationError",
    "AdapterError",
    "AdapterResponseError",
    "AdapterUnavailableError",
    "create_default_tool_registry",
    "HostResolver",
    "HttpProbeAdapterResult",
    "HttpProbeProvider",
    "HttpProbeProviderResult",
    "HttpProbeProviderStatus",
    "HttpProbeTransport",
    "HttpxConfig",
    "HttpxProbeProvider",
    "StandardHostResolver",
    "KatanaAdapter",
    "KATANA_TOOL",
    "KATANA_TOOL_ID",
    "KatanaConfig",
    "KatanaWebCrawlProvider",
    "LocalSubprocessToolRunner",
    "LocalSeedSubdomainProvider",
    "LocalStaticHostResolver",
    "NvdAdapter",
    "NUCLEI_TOOL",
    "NUCLEI_TOOL_ID",
    "NucleiConfig",
    "NucleiVulnerabilityDetectionProvider",
    "SubdomainDiscoveryResult",
    "SubdomainDiscoveryStatus",
    "SubdomainProvider",
    "SUBFINDER_TOOL",
    "SUBFINDER_TOOL_ID",
    "SubfinderConfig",
    "SubfinderSubdomainProvider",
    "SystemPlatformInformationProbe",
    "SystemPythonRuntimeInformationProbe",
    "TechnologyDetectionAdapter",
    "TechnologyDetectionResult",
    "TechnologyDetector",
    "ToolRunnerReadinessProbe",
    "ToolRunnerVersionProbe",
    "WHATWEB_TOOL",
    "WHATWEB_TOOL_ID",
    "WhatWebConfig",
    "WhatWebTechnologyDetectionProvider",
    "VulnerabilityProvider",
    "WebCrawlAdapterResult",
    "WebCrawler",
]
