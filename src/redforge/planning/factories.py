"""Explicit factories for translating planned names into runtime capabilities."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from redforge.adapters.host_resolver import HostResolver
from redforge.adapters.httpx import HttpProbeTransport
from redforge.adapters.katana import WebCrawler
from redforge.adapters.nvd import VulnerabilityProvider
from redforge.adapters.subfinder import SubdomainProvider
from redforge.adapters.technology_detection import TechnologyDetector
from redforge.capabilities.asset_intelligence import AssetIntelligenceCapability
from redforge.capabilities.host_resolution import HostResolutionCapability
from redforge.capabilities.http_probe import HttpProbeCapability
from redforge.capabilities.knowledge_graph import KnowledgeGraphCapability
from redforge.capabilities.risk_intelligence import RiskIntelligenceCapability
from redforge.capabilities.subdomain_discovery import SubdomainDiscovery
from redforge.capabilities.technology_detection import TechnologyDetectionCapability
from redforge.capabilities.vulnerability_intelligence import (
    VulnerabilityIntelligenceCapability,
)
from redforge.capabilities.web_crawl import WebCrawlCapability
from redforge.planning.errors import (
    CapabilityDescriptorMismatchError,
    InvalidCapabilityFactoryError,
    MissingCapabilityFactoryError,
)
from redforge.sdk.capability import Capability

type CapabilityFactory = Callable[[], Capability]


def _valid_capability_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip().lower()
        and all(character.isalnum() or character == "_" for character in value)
    )


class CapabilityFactoryRegistry:
    """Register and invoke one explicit factory per canonical capability name."""

    def __init__(self) -> None:
        self._factories: dict[str, CapabilityFactory] = {}

    def register(self, name: str, factory: CapabilityFactory) -> None:
        """Register a callable factory without silent replacement."""
        if not _valid_capability_name(name):
            raise InvalidCapabilityFactoryError("invalid")
        if name in self._factories:
            raise InvalidCapabilityFactoryError(name)
        if not callable(cast(object, factory)):
            raise InvalidCapabilityFactoryError(name)
        self._factories[name] = factory

    @property
    def names(self) -> tuple[str, ...]:
        """Return registered names in deterministic immutable order."""
        return tuple(sorted(self._factories))

    def has(self, name: str) -> bool:
        """Return whether a factory is registered for a canonical name."""
        return name in self._factories

    def create(self, name: str) -> Capability:
        """Create and validate one fresh runtime capability."""
        try:
            factory = self._factories[name]
        except KeyError:
            raise MissingCapabilityFactoryError(name) from None

        try:
            candidate = cast(object, factory())
        except Exception:
            raise InvalidCapabilityFactoryError(name, failed=True) from None
        if not isinstance(candidate, Capability):
            raise InvalidCapabilityFactoryError(name)
        try:
            actual_name = cast(object, candidate.name)
        except Exception:
            raise InvalidCapabilityFactoryError(name, failed=True) from None
        if not _valid_capability_name(actual_name):
            raise InvalidCapabilityFactoryError(name)
        if actual_name != name:
            raise CapabilityDescriptorMismatchError(name, "runtime capability name")
        return candidate


@dataclass(frozen=True, slots=True)
class CapabilityDependencies:
    """Optional explicit ports shared by fresh default capability instances."""

    subdomain_provider: SubdomainProvider | None = None
    host_resolver: HostResolver | None = None
    http_transport: HttpProbeTransport | None = None
    web_crawler: WebCrawler | None = None
    technology_detector: TechnologyDetector | None = None
    vulnerability_provider: VulnerabilityProvider | None = None


def create_default_factory_registry(
    *,
    dependencies: CapabilityDependencies | None = None,
    subdomain_provider: SubdomainProvider | None = None,
    host_resolver: HostResolver | None = None,
    http_transport: HttpProbeTransport | None = None,
    web_crawler: WebCrawler | None = None,
    technology_detector: TechnologyDetector | None = None,
    vulnerability_provider: VulnerabilityProvider | None = None,
) -> CapabilityFactoryRegistry:
    """Return lazy factories for every executable default descriptor."""
    configured = dependencies or CapabilityDependencies(
        subdomain_provider=subdomain_provider,
        host_resolver=host_resolver,
        http_transport=http_transport,
        web_crawler=web_crawler,
        technology_detector=technology_detector,
        vulnerability_provider=vulnerability_provider,
    )
    if dependencies is not None and any(
        item is not None
        for item in (
            subdomain_provider,
            host_resolver,
            http_transport,
            web_crawler,
            technology_detector,
            vulnerability_provider,
        )
    ):
        raise ValueError(
            "dependencies cannot be combined with individual dependency arguments"
        )

    registry = CapabilityFactoryRegistry()
    registry.register(
        "subdomain_discovery",
        lambda: SubdomainDiscovery(provider=configured.subdomain_provider),
    )
    registry.register(
        "host_resolution",
        lambda: HostResolutionCapability(resolver=configured.host_resolver),
    )
    registry.register(
        "http_probe",
        lambda: HttpProbeCapability(transport=configured.http_transport),
    )
    registry.register(
        "web_crawl",
        lambda: WebCrawlCapability(crawler=configured.web_crawler),
    )
    registry.register(
        "technology_detection",
        lambda: TechnologyDetectionCapability(
            detector=configured.technology_detector
        ),
    )
    registry.register("asset_intelligence", AssetIntelligenceCapability)
    registry.register(
        "vulnerability_intelligence",
        lambda: VulnerabilityIntelligenceCapability(
            provider=configured.vulnerability_provider
        ),
    )
    registry.register("knowledge_graph", KnowledgeGraphCapability)
    registry.register("risk_intelligence", RiskIntelligenceCapability)
    return registry
