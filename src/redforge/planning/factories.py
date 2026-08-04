"""Explicit factories for translating planned names into runtime capabilities."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import cast

from redforge.adapters.host_resolver import HostResolver
from redforge.adapters.httpx import HTTPX_TOOL_ID, HttpxProbeProvider
from redforge.adapters.katana import KATANA_TOOL_ID, KatanaWebCrawlProvider
from redforge.adapters.nuclei import (
    NUCLEI_TOOL_ID,
    NucleiVulnerabilityDetectionProvider,
)
from redforge.adapters.nvd import VulnerabilityProvider
from redforge.adapters.subfinder import (
    SUBFINDER_TOOL_ID,
    SubfinderSubdomainProvider,
)
from redforge.adapters.technology_detection import (
    WHATWEB_TOOL_ID,
    WhatWebTechnologyDetectionProvider,
)
from redforge.adapters.tool_runner import LocalSubprocessToolRunner
from redforge.capabilities.asset_intelligence import AssetIntelligenceCapability
from redforge.capabilities.host_resolution import HostResolutionCapability
from redforge.capabilities.http_probe import HttpProbeCapability
from redforge.capabilities.knowledge_graph import KnowledgeGraphCapability
from redforge.capabilities.risk_intelligence import RiskIntelligenceCapability
from redforge.capabilities.subdomain_discovery import SubdomainDiscovery
from redforge.capabilities.technology_detection import TechnologyDetectionCapability
from redforge.capabilities.vulnerability_detection import (
    VulnerabilityDetectionCapability,
)
from redforge.capabilities.vulnerability_intelligence import (
    VulnerabilityIntelligenceCapability,
)
from redforge.capabilities.web_crawl import WebCrawlCapability
from redforge.domain.scan_scope import ExactNetworkTarget
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
    VULNERABILITY_DETECTION,
    VULNERABILITY_INTELLIGENCE,
    WEB_CRAWL,
    CapabilityId,
    normalize_capability_id,
)
from redforge.sdk.http_probe import HttpProbeProvider
from redforge.sdk.readiness import (
    ProviderRole,
    ReadinessRequirement,
)
from redforge.sdk.subdomain_discovery import SubdomainProvider
from redforge.sdk.technology_detection import TechnologyDetectionProvider
from redforge.sdk.tool import ToolId, ToolRunner
from redforge.sdk.vulnerability import VulnerabilityDetectionProvider
from redforge.sdk.web_crawl import WebCrawlProvider

type CapabilityFactory = Callable[[], Capability]

SUBDOMAIN_PROVIDER_ROLE = ProviderRole("subdomain_discovery_provider")
HTTP_PROBE_PROVIDER_ROLE = ProviderRole("http_probe_provider")
WEB_CRAWL_PROVIDER_ROLE = ProviderRole("web_crawl_provider")
TECHNOLOGY_PROVIDER_ROLE = ProviderRole("technology_detection_provider")
VULNERABILITY_PROVIDER_ROLE = ProviderRole("vulnerability_provider")
VULNERABILITY_DETECTION_PROVIDER_ROLE = ProviderRole(
    "vulnerability_detection_provider"
)


def _external_requirement(
    provider: object | None,
    *,
    provider_role: ProviderRole,
    tool_id: ToolId,
) -> tuple[ReadinessRequirement, ...]:
    if provider is not None:
        return (
            ReadinessRequirement.provider(
                provider_role,
                configuration_present=True,
            ),
        )
    return (ReadinessRequirement.tool(tool_id),)


@dataclass(frozen=True, slots=True, repr=False)
class CapabilityFactoryDefinition:
    """Lazy factory plus immutable, construction-free readiness metadata."""

    capability_id: CapabilityId
    factory: CapabilityFactory = field(repr=False, compare=False)
    requirements: tuple[ReadinessRequirement, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.capability_id), CapabilityId):
            raise TypeError("factory definition capability ID is invalid")
        if not callable(cast(object, self.factory)):
            raise TypeError("factory definition requires a callable")
        requirements_value = cast(object, self.requirements)
        if not isinstance(requirements_value, tuple) or not all(
            isinstance(item, ReadinessRequirement)
            for item in cast(tuple[object, ...], requirements_value)
        ):
            raise TypeError("factory requirements must be an immutable tuple")
        typed = cast(tuple[ReadinessRequirement, ...], requirements_value)
        if len(typed) != len(set(typed)):
            raise ValueError("factory requirements contain duplicates")
        object.__setattr__(self, "requirements", tuple(sorted(typed)))


class CapabilityFactoryRegistry:
    """Register and invoke one explicit factory per typed capability identity."""

    def __init__(self) -> None:
        self._definitions: dict[
            CapabilityId, CapabilityFactoryDefinition
        ] = {}

    def register(
        self,
        capability_id: CapabilityId | str,
        factory: CapabilityFactory,
        *,
        declared_capability_id: CapabilityId | str | None = None,
        requirements: tuple[ReadinessRequirement, ...] = (),
    ) -> None:
        """Register a callable factory without silent replacement."""
        try:
            identity = normalize_capability_id(capability_id)
        except (TypeError, ValueError):
            raise InvalidCapabilityFactoryError("invalid") from None
        if identity in self._definitions:
            raise InvalidCapabilityFactoryError(identity.value)
        if not callable(cast(object, factory)):
            raise InvalidCapabilityFactoryError(identity.value)
        try:
            declared = normalize_capability_id(
                declared_capability_id
                if declared_capability_id is not None
                else identity
            )
            definition = CapabilityFactoryDefinition(
                capability_id=declared,
                factory=factory,
                requirements=requirements,
            )
        except (TypeError, ValueError):
            raise InvalidCapabilityFactoryError(identity.value) from None
        self._definitions[identity] = definition

    @property
    def ids(self) -> tuple[CapabilityId, ...]:
        """Return registered typed identities in deterministic order."""
        return tuple(sorted(self._definitions))

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
        return identity in self._definitions

    def definition_for(
        self,
        capability_id: CapabilityId | str,
    ) -> CapabilityFactoryDefinition | None:
        """Return immutable lazy-factory metadata without calling the factory."""
        try:
            identity = normalize_capability_id(capability_id)
        except (TypeError, ValueError):
            return None
        return self._definitions.get(identity)

    def create(self, capability_id: CapabilityId | str) -> Capability:
        """Create and validate one fresh runtime capability."""
        try:
            identity = normalize_capability_id(capability_id)
        except (TypeError, ValueError):
            raise MissingCapabilityFactoryError("invalid") from None
        try:
            definition = self._definitions[identity]
        except KeyError:
            raise MissingCapabilityFactoryError(identity.value) from None

        try:
            candidate = cast(object, definition.factory())
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
    http_transport: HttpProbeProvider | None = None
    web_crawler: WebCrawlProvider | None = None
    technology_detector: TechnologyDetectionProvider | None = None
    vulnerability_provider: VulnerabilityProvider | None = None
    vulnerability_detector: VulnerabilityDetectionProvider | None = None
    tool_runner: ToolRunner | None = None
    exact_target: ExactNetworkTarget | None = None


def create_default_factory_registry(
    *,
    dependencies: CapabilityDependencies | None = None,
    enabled_capabilities: tuple[CapabilityId, ...] | None = None,
    subdomain_provider: SubdomainProvider | None = None,
    host_resolver: HostResolver | None = None,
    http_transport: HttpProbeProvider | None = None,
    web_crawler: WebCrawlProvider | None = None,
    technology_detector: TechnologyDetectionProvider | None = None,
    vulnerability_provider: VulnerabilityProvider | None = None,
    vulnerability_detector: VulnerabilityDetectionProvider | None = None,
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
        vulnerability_detector=vulnerability_detector,
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
            vulnerability_detector,
            tool_runner,
        )
    ):
        raise ValueError(
            "dependencies cannot be combined with individual dependency arguments"
        )

    if enabled_capabilities is not None:
        if not isinstance(cast(object, enabled_capabilities), tuple):
            raise TypeError("enabled capabilities must be an immutable tuple")
        try:
            enabled = frozenset(
                normalize_capability_id(item)
                for item in enabled_capabilities
            )
        except (TypeError, ValueError):
            raise ValueError("enabled capability identity is invalid") from None
        if len(enabled) != len(enabled_capabilities):
            raise ValueError("enabled capabilities contain duplicates")
    else:
        enabled = None

    registry = CapabilityFactoryRegistry()

    def register(
        capability_id: CapabilityId,
        factory: CapabilityFactory,
        *,
        requirements: tuple[ReadinessRequirement, ...] = (),
    ) -> None:
        if enabled is None or capability_id in enabled:
            registry.register(
                capability_id,
                factory,
                requirements=requirements,
            )

    register(
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
        requirements=_external_requirement(
            configured.subdomain_provider,
            provider_role=SUBDOMAIN_PROVIDER_ROLE,
            tool_id=SUBFINDER_TOOL_ID,
        ),
    )
    register(
        HOST_RESOLUTION,
        lambda: HostResolutionCapability(resolver=configured.host_resolver),
    )
    register(
        HTTP_PROBE,
        lambda: HttpProbeCapability(
            provider=(
                configured.http_transport
                or HttpxProbeProvider(
                    runner=(
                        configured.tool_runner
                        or LocalSubprocessToolRunner()
                    ),
                    exact_target=configured.exact_target,
                )
            )
        ),
        requirements=_external_requirement(
            configured.http_transport,
            provider_role=HTTP_PROBE_PROVIDER_ROLE,
            tool_id=HTTPX_TOOL_ID,
        ),
    )
    register(
        WEB_CRAWL,
        lambda: WebCrawlCapability(
            provider=(
                configured.web_crawler
                or KatanaWebCrawlProvider(
                    runner=(
                        configured.tool_runner
                        or LocalSubprocessToolRunner()
                    ),
                    exact_target=configured.exact_target,
                )
            )
        ),
        requirements=_external_requirement(
            configured.web_crawler,
            provider_role=WEB_CRAWL_PROVIDER_ROLE,
            tool_id=KATANA_TOOL_ID,
        ),
    )
    register(
        TECHNOLOGY_DETECTION,
        lambda: TechnologyDetectionCapability(
            provider=(
                configured.technology_detector
                or WhatWebTechnologyDetectionProvider(
                    runner=(
                        configured.tool_runner
                        or LocalSubprocessToolRunner()
                    ),
                    exact_target=configured.exact_target,
                )
            )
        ),
        requirements=_external_requirement(
            configured.technology_detector,
            provider_role=TECHNOLOGY_PROVIDER_ROLE,
            tool_id=WHATWEB_TOOL_ID,
        ),
    )
    register(ASSET_INTELLIGENCE, AssetIntelligenceCapability)
    register(
        VULNERABILITY_DETECTION,
        lambda: VulnerabilityDetectionCapability(
            provider=(
                configured.vulnerability_detector
                or NucleiVulnerabilityDetectionProvider(
                    runner=(
                        configured.tool_runner
                        or LocalSubprocessToolRunner()
                    )
                )
            )
        ),
        requirements=_external_requirement(
            configured.vulnerability_detector,
            provider_role=VULNERABILITY_DETECTION_PROVIDER_ROLE,
            tool_id=NUCLEI_TOOL_ID,
        ),
    )
    register(
        VULNERABILITY_INTELLIGENCE,
        lambda: VulnerabilityIntelligenceCapability(
            provider=configured.vulnerability_provider
        ),
        requirements=(
            ReadinessRequirement.provider(
                VULNERABILITY_PROVIDER_ROLE,
                configuration_present=(
                    configured.vulnerability_provider is not None
                ),
            ),
        ),
    )
    register(KNOWLEDGE_GRAPH, KnowledgeGraphCapability)
    register(RISK_INTELLIGENCE, RiskIntelligenceCapability)
    if enabled is not None:
        unknown = enabled.difference(registry.ids)
        if unknown:
            raise ValueError("enabled capabilities contain an unknown identity")
    return registry
