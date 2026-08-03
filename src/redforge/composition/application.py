"""Explicit provider-neutral application composition profiles."""

from dataclasses import dataclass, field
from typing import cast

from redforge.adapters import (
    HostResolver,
    LocalSeedSubdomainProvider,
    LocalStaticHostResolver,
    LocalSubprocessToolRunner,
    SystemPlatformInformationProbe,
    SystemPythonRuntimeInformationProbe,
    ToolRunnerReadinessProbe,
    ToolRunnerVersionProbe,
    VulnerabilityProvider,
    create_default_tool_registry,
)
from redforge.application import (
    ReadinessRegistry,
    RedForgeDoctor,
    ScanInspector,
    ScanOrchestrator,
)
from redforge.composition.profile import CompositionProfile
from redforge.domain.scan_scope import ExactNetworkTarget
from redforge.observability import (
    DiagnosticEventSink,
    NullDiagnosticEventSink,
)
from redforge.planning import (
    CapabilityDependencies,
    CapabilityFactoryRegistry,
    CapabilityRegistry,
    create_default_factory_registry,
    create_default_registry,
)
from redforge.sdk import (
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
    ProviderReadinessProbe,
    ProviderRole,
    SubdomainProvider,
    TechnologyDetectionProvider,
    ToolExecutableResolver,
    ToolReadinessProbe,
    ToolRegistry,
    ToolRunner,
    WebCrawlProvider,
)
from redforge.sdk.http_probe import HttpProbeProvider

_RECONNAISSANCE_CAPABILITIES = (
    SUBDOMAIN_DISCOVERY,
    HOST_RESOLUTION,
    HTTP_PROBE,
    WEB_CRAWL,
    TECHNOLOGY_DETECTION,
)
_FULL_ASSESSMENT_CAPABILITIES = (
    *_RECONNAISSANCE_CAPABILITIES,
    ASSET_INTELLIGENCE,
    VULNERABILITY_INTELLIGENCE,
    KNOWLEDGE_GRAPH,
    RISK_INTELLIGENCE,
)


@dataclass(frozen=True, slots=True, repr=False)
class CompositionProviders:
    """Explicit provider ports supplied by one application host."""

    subdomain_provider: SubdomainProvider | None = field(
        default=None,
        repr=False,
    )
    host_resolver: HostResolver | None = field(default=None, repr=False)
    http_transport: HttpProbeProvider | None = field(
        default=None,
        repr=False,
    )
    web_crawler: WebCrawlProvider | None = field(default=None, repr=False)
    technology_detector: TechnologyDetectionProvider | None = field(
        default=None,
        repr=False,
    )
    vulnerability_provider: VulnerabilityProvider | None = field(
        default=None,
        repr=False,
    )


@dataclass(frozen=True, slots=True, repr=False)
class ApplicationComposition:
    """Immutable recipe that constructs one isolated application runtime."""

    profile: CompositionProfile
    providers: CompositionProviders = field(
        default_factory=CompositionProviders,
        repr=False,
    )
    tool_runner: ToolRunner | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    tool_readiness_probe: ToolReadinessProbe | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    provider_readiness_probes: tuple[
        tuple[ProviderRole, ProviderReadinessProbe], ...
    ] = field(default=(), repr=False, compare=False)
    diagnostic_sink: DiagnosticEventSink = field(
        default_factory=NullDiagnosticEventSink,
        repr=False,
        compare=False,
    )
    exact_target: ExactNetworkTarget | None = field(
        default=None,
        repr=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.profile), CompositionProfile):
            raise TypeError("composition profile is invalid")
        if not isinstance(
            cast(object, self.providers), CompositionProviders
        ):
            raise TypeError("composition providers are invalid")
        if self.tool_runner is not None and not all(
            callable(getattr(cast(object, self.tool_runner), method, None))
            for method in ("run", "is_available")
        ):
            raise TypeError("composition tool runner is invalid")
        if self.tool_readiness_probe is not None and not callable(
            getattr(
                cast(object, self.tool_readiness_probe),
                "check",
                None,
            )
        ):
            raise TypeError("tool readiness probe is invalid")
        probes = cast(object, self.provider_readiness_probes)
        if not isinstance(probes, tuple):
            raise TypeError("provider readiness probes must be an immutable tuple")
        roles: list[ProviderRole] = []
        for item in cast(tuple[object, ...], probes):
            if not isinstance(item, tuple):
                raise TypeError("provider readiness probe is invalid")
            pair = cast(tuple[object, ...], item)
            if len(pair) != 2:
                raise TypeError("provider readiness probe is invalid")
            role, probe = pair
            if not isinstance(role, ProviderRole) or not callable(
                getattr(probe, "check", None)
            ):
                raise TypeError("provider readiness probe is invalid")
            roles.append(role)
        if len(roles) != len(set(roles)):
            raise ValueError("provider readiness probes contain duplicate roles")
        if not isinstance(
            cast(object, self.diagnostic_sink),
            DiagnosticEventSink,
        ):
            raise TypeError("diagnostic sink is invalid")
        if self.profile is CompositionProfile.LOCAL_SMOKE:
            if not isinstance(
                cast(object, self.exact_target), ExactNetworkTarget
            ):
                raise TypeError("local smoke composition requires an exact target")
            target = cast(ExactNetworkTarget, self.exact_target)
            if (
                target.scheme != "http"
                or not target.hostname.endswith(".test")
            ):
                raise ValueError("local smoke target must be an HTTP .test origin")
            if any(
                provider is not None
                for provider in (
                    self.providers.subdomain_provider,
                    self.providers.host_resolver,
                    self.providers.http_transport,
                    self.providers.web_crawler,
                    self.providers.technology_detector,
                    self.providers.vulnerability_provider,
                )
            ):
                raise ValueError(
                    "local smoke composition owns its constrained providers"
                )
        elif self.exact_target is not None:
            raise ValueError("exact target is supported only by local smoke")

    @property
    def capability_ids(self) -> tuple[CapabilityId, ...]:
        """Return the immutable capability set owned by this profile."""
        if self.profile in {
            CompositionProfile.RECONNAISSANCE,
            CompositionProfile.LOCAL_SMOKE,
        }:
            return _RECONNAISSANCE_CAPABILITIES
        return _FULL_ASSESSMENT_CAPABILITIES

    def create_orchestrator(self) -> ScanOrchestrator:
        """Construct fresh registries, readiness infrastructure, and service."""
        capability_registry, factories, readiness = (
            self._create_application_components()
        )
        return ScanOrchestrator(
            capability_registry=capability_registry,
            factory_registry=factories,
            readiness_registry=readiness,
            diagnostic_sink=self.diagnostic_sink,
        )

    def create_inspector(self) -> ScanInspector:
        """Construct an execution-free planner and readiness inspector."""
        capability_registry, factories, readiness = (
            self._create_application_components()
        )
        return ScanInspector(
            capability_registry=capability_registry,
            factory_registry=factories,
            readiness_registry=readiness,
        )

    def create_doctor(
        self,
        *,
        configuration_valid: bool = True,
    ) -> RedForgeDoctor:
        """Construct target-free static environment diagnostics."""
        if not isinstance(cast(object, configuration_valid), bool):
            raise TypeError("doctor configuration status is invalid")
        capability_registry, factories, readiness = (
            self._create_application_components()
        )
        availability_probe = readiness.tool_probe
        if availability_probe is None:
            raise RuntimeError("doctor composition requires tool readiness")
        resolver: object | None = self.tool_runner
        if (
            resolver is None
            and isinstance(availability_probe, ToolRunnerReadinessProbe)
        ):
            resolver = availability_probe.runner
        version_probe = (
            ToolRunnerVersionProbe(
                cast(ToolExecutableResolver, resolver)
            )
            if callable(getattr(resolver, "resolve", None))
            else None
        )
        return RedForgeDoctor(
            profile=self.profile,
            platform_probe=SystemPlatformInformationProbe(),
            python_probe=SystemPythonRuntimeInformationProbe(),
            capability_registry=capability_registry,
            factory_registry=factories,
            tool_registry=readiness.tool_registry,
            availability_probe=availability_probe,
            configuration_valid=configuration_valid,
            version_probe=version_probe,
        )

    def _create_application_components(
        self,
    ) -> tuple[
        CapabilityRegistry,
        CapabilityFactoryRegistry,
        ReadinessRegistry,
    ]:
        capability_registry = _profile_capability_registry(
            self.capability_ids
        )
        dependencies = self._capability_dependencies()
        factories = create_default_factory_registry(
            dependencies=dependencies,
            enabled_capabilities=self.capability_ids,
        )
        tool_registry = _required_tool_registry(factories)
        tool_probe = self.tool_readiness_probe
        if tool_probe is None and tool_registry.ids():
            runner = dependencies.tool_runner
            if runner is None:
                raise RuntimeError("tool-backed composition requires a runner")
            tool_probe = ToolRunnerReadinessProbe(runner)
        return (
            capability_registry,
            factories,
            ReadinessRegistry(
                tool_registry=tool_registry,
                tool_probe=tool_probe,
                provider_probes=self.provider_readiness_probes,
            ),
        )

    def _capability_dependencies(self) -> CapabilityDependencies:
        providers = self.providers
        runner = self.tool_runner
        if runner is None and self._requires_tool_runner():
            runner = LocalSubprocessToolRunner()
        if self.profile is CompositionProfile.LOCAL_SMOKE:
            target = cast(ExactNetworkTarget, self.exact_target)
            return CapabilityDependencies(
                subdomain_provider=LocalSeedSubdomainProvider(target),
                host_resolver=LocalStaticHostResolver(target),
                tool_runner=runner,
                exact_target=target,
            )
        return CapabilityDependencies(
            subdomain_provider=providers.subdomain_provider,
            host_resolver=providers.host_resolver,
            http_transport=providers.http_transport,
            web_crawler=providers.web_crawler,
            technology_detector=providers.technology_detector,
            vulnerability_provider=providers.vulnerability_provider,
            tool_runner=runner,
        )

    def _requires_tool_runner(self) -> bool:
        providers = self.providers
        tool_backed = (
            (
                SUBDOMAIN_DISCOVERY,
                providers.subdomain_provider,
            ),
            (HTTP_PROBE, providers.http_transport),
            (WEB_CRAWL, providers.web_crawler),
            (
                TECHNOLOGY_DETECTION,
                providers.technology_detector,
            ),
        )
        enabled = frozenset(self.capability_ids)
        return any(
            capability_id in enabled and provider is None
            for capability_id, provider in tool_backed
        )


def _required_tool_registry(
    factories: CapabilityFactoryRegistry,
) -> ToolRegistry:
    default_tools = create_default_tool_registry()
    required = {
        requirement.tool_id
        for capability_id in factories.ids
        for definition in (factories.definition_for(capability_id),)
        if definition is not None
        for requirement in definition.requirements
        if requirement.tool_id is not None
    }
    return ToolRegistry(
        default_tools.require(tool_id)
        for tool_id in sorted(required)
    )


def _profile_capability_registry(
    capability_ids: tuple[CapabilityId, ...],
) -> CapabilityRegistry:
    defaults = create_default_registry()
    return CapabilityRegistry(
        defaults.require(capability_id)
        for capability_id in capability_ids
    )
