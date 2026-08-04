"""Offline tests for explicit provider-neutral application composition."""

from dataclasses import FrozenInstanceError

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.nvd import NvdCpeCandidate, NvdVulnerabilityRecord
from redforge.application import (
    ReadinessProbeResult,
    ReadinessReason,
    ReadinessStatus,
    ReadinessSubjectKind,
    ScanConfig,
    ScanPreflightError,
)
from redforge.composition import (
    ApplicationComposition,
    CompositionProfile,
    CompositionProviders,
)
from redforge.domain import Endpoint, Host
from redforge.observability import DiagnosticEvent, DiagnosticEventType
from redforge.planning import VULNERABILITY_PROVIDER_ROLE
from redforge.sdk import (
    HttpProbeProviderResult,
    Status,
    SubdomainDiscoveryResult,
    TechnologyDetectionProviderResult,
    ToolDefinition,
    WebCrawlProviderResult,
)
from redforge.testing import FakeToolRunner

RECONNAISSANCE_IDS = (
    "subdomain_discovery",
    "host_resolution",
    "http_probe",
    "web_crawl",
    "technology_detection",
)
FULL_ASSESSMENT_IDS = (
    *RECONNAISSANCE_IDS,
    "asset_intelligence",
    "vulnerability_intelligence",
    "vulnerability_detection",
    "knowledge_graph",
    "risk_intelligence",
)


class EmptySubdomainProvider:
    def __init__(self) -> None:
        self.calls = 0

    def discover(self, domain: str) -> SubdomainDiscoveryResult:
        self.calls += 1
        assert domain == "authorized.example"
        return SubdomainDiscoveryResult()


class UnusedResolver:
    def resolve(self, hostname: str) -> tuple[str, ...]:
        raise AssertionError(f"resolver unexpectedly called for {hostname}")


class UnusedHttpProvider:
    def probe(self, hosts: tuple[Host, ...]) -> HttpProbeProviderResult:
        raise AssertionError(f"HTTP provider unexpectedly called for {hosts!r}")


class UnusedCrawler:
    def crawl(self, hosts: tuple[Host, ...]) -> WebCrawlProviderResult:
        raise AssertionError(f"crawler unexpectedly called for {hosts!r}")


class UnusedTechnologyProvider:
    def detect(
        self,
        endpoints: tuple[Endpoint, ...],
    ) -> TechnologyDetectionProviderResult:
        raise AssertionError(
            f"technology provider unexpectedly called for {endpoints!r}"
        )


class UnusedVulnerabilityProvider:
    def search_cpe_candidates(
        self,
        name: str,
        version: str,
        vendor: str | None = None,
    ) -> tuple[NvdCpeCandidate, ...]:
        raise AssertionError(
            "vulnerability provider unexpectedly called for "
            f"{(name, version, vendor)!r}"
        )

    def get_vulnerabilities(
        self,
        cpe_name: str,
    ) -> tuple[NvdVulnerabilityRecord, ...]:
        raise AssertionError(
            f"vulnerability provider unexpectedly called for {cpe_name}"
        )


class CountingProviderProbe:
    def __init__(self) -> None:
        self.calls = 0

    def check(self) -> ReadinessProbeResult:
        self.calls += 1
        return ReadinessProbeResult(ReadinessStatus.READY)


class CountingToolProbe:
    def __init__(self) -> None:
        self.calls = 0

    def check(
        self,
        definition: ToolDefinition,
    ) -> ReadinessProbeResult:
        _ = definition
        self.calls += 1
        return ReadinessProbeResult(ReadinessStatus.READY)


class RecordingSink:
    def __init__(self) -> None:
        self._events: list[DiagnosticEvent] = []

    def emit(self, event: DiagnosticEvent) -> None:
        self._events.append(event)

    @property
    def events(self) -> tuple[DiagnosticEvent, ...]:
        return tuple(self._events)


def _recon_dependencies(
    subdomains: EmptySubdomainProvider | None = None,
) -> CompositionProviders:
    return CompositionProviders(
        subdomain_provider=subdomains or EmptySubdomainProvider(),
        host_resolver=UnusedResolver(),
        http_transport=UnusedHttpProvider(),
        web_crawler=UnusedCrawler(),
        technology_detector=UnusedTechnologyProvider(),
    )


def test_reconnaissance_profile_is_immutable_and_fully_operational() -> None:
    subdomains = EmptySubdomainProvider()
    composition = ApplicationComposition(
        CompositionProfile.RECONNAISSANCE,
        providers=_recon_dependencies(subdomains),
    )

    with pytest.raises(FrozenInstanceError):
        composition.profile = CompositionProfile.FULL_ASSESSMENT  # type: ignore[misc]

    result = composition.create_orchestrator().run(
        ScanConfig.for_reconnaissance("authorized.example")
    )

    assert tuple(item.value for item in composition.capability_ids) == (
        RECONNAISSANCE_IDS
    )
    assert result.runtime_status is Status.SUCCESS
    assert result.pipeline_result.executed_capabilities == RECONNAISSANCE_IDS
    assert subdomains.calls == 1


def test_composition_wires_one_execution_scoped_diagnostic_sink() -> None:
    sink = RecordingSink()
    composition = ApplicationComposition(
        CompositionProfile.RECONNAISSANCE,
        providers=_recon_dependencies(),
        diagnostic_sink=sink,
    )

    result = composition.create_orchestrator().run(
        ScanConfig.for_reconnaissance("authorized.example")
    )

    assert result.runtime_status is Status.SUCCESS
    assert sink.events[0].event_type is (
        DiagnosticEventType.SCAN_PREPARATION_STARTED
    )
    assert sink.events[-1].event_type is (
        DiagnosticEventType.SCAN_RESULT_CREATED
    )


def test_full_profile_composes_all_factories_but_reports_provider_absence() -> None:
    composition = ApplicationComposition(
        CompositionProfile.FULL_ASSESSMENT,
        providers=_recon_dependencies(),
    )

    with pytest.raises(ScanPreflightError) as caught:
        composition.create_orchestrator().run(
            ScanConfig.for_full_assessment("authorized.example")
        )

    assert tuple(item.value for item in composition.capability_ids) == (
        FULL_ASSESSMENT_IDS
    )
    failures = tuple(
        check
        for check in caught.value.result.checks
        if check.status is not ReadinessStatus.READY
    )
    assert len(failures) == 1
    assert (
        failures[0].subject.kind
        is ReadinessSubjectKind.PROVIDER_CONFIGURATION
    )
    assert failures[0].reason is ReadinessReason.PROVIDER_ABSENT


def test_full_profile_accepts_explicit_provider_and_readiness_probe() -> None:
    probe = CountingProviderProbe()
    dependencies = _recon_dependencies()
    composition = ApplicationComposition(
        CompositionProfile.FULL_ASSESSMENT,
        providers=CompositionProviders(
            subdomain_provider=dependencies.subdomain_provider,
            host_resolver=dependencies.host_resolver,
            http_transport=dependencies.http_transport,
            web_crawler=dependencies.web_crawler,
            technology_detector=dependencies.technology_detector,
            vulnerability_provider=UnusedVulnerabilityProvider(),
        ),
        provider_readiness_probes=((VULNERABILITY_PROVIDER_ROLE, probe),),
    )

    result = composition.create_orchestrator().run(
        ScanConfig.for_full_assessment("authorized.example")
    )

    assert result.runtime_status is Status.SUCCESS
    assert result.pipeline_result.executed_capabilities == tuple(
        item
        for item in FULL_ASSESSMENT_IDS
        if item != "vulnerability_detection"
    )
    assert probe.calls == 1


def test_injected_tool_runner_and_probe_remain_lazy_until_preflight() -> None:
    runner = FakeToolRunner()
    probe = CountingToolProbe()
    composition = ApplicationComposition(
        CompositionProfile.RECONNAISSANCE,
        tool_runner=runner,
        tool_readiness_probe=probe,
    )

    assert runner.invocations == ()
    assert probe.calls == 0
    orchestrator = composition.create_orchestrator()
    assert runner.invocations == ()
    assert probe.calls == 0

    result = orchestrator.run(
        ScanConfig.for_reconnaissance("authorized.example")
    )

    assert probe.calls == 4
    assert runner.invocations == ()
    assert result.runtime_status is Status.ERROR
