"""Explicit factories for translating planned names into runtime capabilities."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from redforge.adapters.host_resolver import HostResolver
from redforge.adapters.httpx import HttpProbeTransport
from redforge.adapters.katana import WebCrawler
from redforge.adapters.nvd import VulnerabilityProvider
from redforge.adapters.subfinder import SubfinderSubdomainProvider
from redforge.adapters.technology_detection import TechnologyDetector
from redforge.adapters.tool_runner import LocalSubprocessToolRunner
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
from redforge.planning.registry import CapabilityRegistry
from redforge.sdk.capability import Capability
from redforge.sdk.capability_id import (
    ASSET_INTELLIGENCE,
    HOST_RESOLUTION,
    HTTP_PROBE,
    KNOWLEDGE_GRAPH,
    RISK_INTELLIGENCE,
    SUBDOMAIN_DISCOVERY,
    TECHNOLOGY_DETECTION,
    VULNERABILITY_INTELLIGENCE,
    WEB_CRAWL,
    CapabilityId,
    normalize_capability_id,
)
from redforge.sdk.subdomain_discovery import SubdomainProvider
from redforge.sdk.tool import ToolRunner

type CapabilityFactory = Callable[[], Capability]


class CapabilityFactoryRegistry:
    """Register and invoke one explicit factory per typed capability identity."""

    def __init__(self) -> None:
        self._factories: dict[CapabilityId, CapabilityFactory] = {}

    def register(
        self,
        capability_id: CapabilityId | str,
        factory: CapabilityFactory,
    ) -> None:
        """Register a callable factory without silent replacement."""
        try:
            identity = normalize_capability_id(capability_id)
        except (TypeError, ValueError):
            raise InvalidCapabilityFactoryError("invalid") from None
        if identity in self._factories:
            raise InvalidCapabilityFactoryError(identity.value)
        if not callable(cast(object, factory)):
            raise InvalidCapabilityFactoryError(identity.value)
        self._factories[identity] = factory

    @property
    def ids(self) -> tuple[CapabilityId, ...]:
        """Return registered typed identities in deterministic order."""
        return tuple(sorted(self._factories))

    @property
    def names(self) -> tuple[str, ...]:
        """Return the legacy serialized identity view."""
        return tuple(item.value for item in self.ids)

    def has(self, capability_id: CapabilityId | str) -> bool:
        """Return whether a factory is registered for a canonical identity."""
        try:
            identity = normalize_capability_id(capability_id)
        except (TypeError, ValueError):
            return False
        return identity in self._factories

    def create(self, capability_id: CapabilityId | str) -> Capability:
        """Create and validate one fresh runtime capability."""
        try:
            identity = normalize_capability_id(capability_id)
        except (TypeError, ValueError):
            raise MissingCapabilityFactoryError("invalid") from None
        try:
            factory = self._factories[identity]
        except KeyError:
            raise MissingCapabilityFactoryError(identity.value) from None

        try:
            candidate = cast(object, factory())
        except Exception:
            raise InvalidCapabilityFactoryError(
                identity.value, failed=True
            ) from None
        if not isinstance(candidate, Capability):
            raise InvalidCapabilityFactoryError(identity.value)
        try:
            actual_name = cast(object, candidate.name)
        except Exception:
            raise InvalidCapabilityFactoryError(
                identity.value, failed=True
            ) from None
        try:
            actual_id = normalize_capability_id(cast(str, actual_name))
        except (TypeError, ValueError):
            raise InvalidCapabilityFactoryError(identity.value) from None
        if actual_id != identity:
            raise CapabilityDescriptorMismatchError(
                identity.value, "runtime capability identity"
            )
        return candidate

    def validate_against(self, definitions: CapabilityRegistry) -> None:
        """Reject factories whose typed identities have no definition."""
        unknown = tuple(
            capability_id
            for capability_id in self.ids
            if not definitions.contains(capability_id)
        )
        if unknown:
            raise CapabilityDescriptorMismatchError(
                unknown[0].value, "definition registry identity"
            )


@dataclass(frozen=True, slots=True)
class CapabilityDependencies:
    """Optional explicit ports shared by fresh default capability instances."""

    subdomain_provider: SubdomainProvider | None = None
    host_resolver: HostResolver | None = None
    http_transport: HttpProbeTransport | None = None
    web_crawler: WebCrawler | None = None
    technology_detector: TechnologyDetector | None = None
    vulnerability_provider: VulnerabilityProvider | None = None
    tool_runner: ToolRunner | None = None


def create_default_factory_registry(
    *,
    dependencies: CapabilityDependencies | None = None,
    subdomain_provider: SubdomainProvider | None = None,
    host_resolver: HostResolver | None = None,
    http_transport: HttpProbeTransport | None = None,
    web_crawler: WebCrawler | None = None,
    technology_detector: TechnologyDetector | None = None,
    vulnerability_provider: VulnerabilityProvider | None = None,
    tool_runner: ToolRunner | None = None,
) -> CapabilityFactoryRegistry:
    """Return lazy factories for every executable default descriptor."""
    configured = dependencies or CapabilityDependencies(
        subdomain_provider=subdomain_provider,
        host_resolver=host_resolver,
        http_transport=http_transport,
        web_crawler=web_crawler,
        technology_detector=technology_detector,
        vulnerability_provider=vulnerability_provider,
        tool_runner=tool_runner,
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
            tool_runner,
        )
    ):
        raise ValueError(
            "dependencies cannot be combined with individual dependency arguments"
        )

    registry = CapabilityFactoryRegistry()
    registry.register(
        SUBDOMAIN_DISCOVERY,
        lambda: SubdomainDiscovery(
            provider=(
                configured.subdomain_provider
                or SubfinderSubdomainProvider(
                    runner=(
                        configured.tool_runner
                        or LocalSubprocessToolRunner()
                    )
                )
            )
        ),
    )
    registry.register(
        HOST_RESOLUTION,
        lambda: HostResolutionCapability(resolver=configured.host_resolver),
    )
    registry.register(
        HTTP_PROBE,
        lambda: HttpProbeCapability(transport=configured.http_transport),
    )
    registry.register(
        WEB_CRAWL,
        lambda: WebCrawlCapability(crawler=configured.web_crawler),
    )
    registry.register(
        TECHNOLOGY_DETECTION,
        lambda: TechnologyDetectionCapability(
            detector=configured.technology_detector
        ),
    )
    registry.register(ASSET_INTELLIGENCE, AssetIntelligenceCapability)
    registry.register(
        VULNERABILITY_INTELLIGENCE,
        lambda: VulnerabilityIntelligenceCapability(
            provider=configured.vulnerability_provider
        ),
    )
    registry.register(KNOWLEDGE_GRAPH, KnowledgeGraphCapability)
    registry.register(RISK_INTELLIGENCE, RiskIntelligenceCapability)
    return registry
