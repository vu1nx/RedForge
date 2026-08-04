"""Offline application orchestration through the production planning/runtime path."""

from dataclasses import FrozenInstanceError, dataclass, field, fields
from typing import Any

import pytest  # type: ignore[reportMissingImports]

import redforge.application.orchestration as orchestration_module
from redforge.adapters.nvd import NvdCpeCandidate, NvdVulnerabilityRecord
from redforge.application import (
    DisabledCapabilityError,
    PreflightResult,
    PreparedScan,
    ScanConfig,
    ScanLimits,
    ScanOrchestrator,
    ScanPreflight,
    ScanPreflightError,
    ScanResult,
    is_scan_result_accepted,
)
from redforge.domain import (
    Endpoint,
    Host,
    HttpProbeEndpoint,
    RiskIntelligence,
    Technology,
)
from redforge.observability import (
    DiagnosticEvent,
    DiagnosticEventSink,
    DiagnosticEventType,
)
from redforge.planning import (
    BUILTIN_CAPABILITY_IDS,
    CapabilityDefinition,
    CapabilityDependencies,
    CapabilityDescriptorMismatchError,
    CapabilityFactoryRegistry,
    CapabilityId,
    CapabilityRegistry,
    create_default_factory_registry,
    create_default_registry,
)
from redforge.runtime import DeadlinePhase, DeadlineViolation, StateLimitViolation
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk import (
    Capability,
    Context,
    HttpProbeProviderResult,
    Result,
    Status,
    SubdomainDiscoveryResult,
    TechnologyDetectionPartialReason,
    TechnologyDetectionProviderResult,
    WebCrawlProviderResult,
)
from redforge.sdk.http_probe import HttpProbeProviderStatus
from redforge.sdk.technology_detection import TechnologyDetectionProviderStatus
from redforge.sdk.web_crawl import WebCrawlProviderStatus

FULL_ORDER = (
    "subdomain_discovery",
    "host_resolution",
    "http_probe",
    "web_crawl",
    "technology_detection",
    "asset_intelligence",
    "vulnerability_intelligence",
    "knowledge_graph",
    "risk_intelligence",
)
RECON_ORDER = FULL_ORDER[:5]


@dataclass(slots=True)
class Scenario:
    mode: str = "success"
    calls: dict[str, int] = field(
        default_factory=lambda: dict[str, int]()
    )

    def called(self, name: str) -> None:
        self.calls[name] = self.calls.get(name, 0) + 1


class FakeSubdomains:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario

    def discover(self, domain: str) -> SubdomainDiscoveryResult:
        self.scenario.called("subdomain")
        assert domain == "example.com"
        return SubdomainDiscoveryResult(
            hostnames=(
                ()
                if self.scenario.mode == "empty"
                else ("app.example.com",)
            )
        )


class FakeResolver:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario

    def resolve(self, hostname: str) -> tuple[str, ...]:
        self.scenario.called("resolver")
        assert hostname == "app.example.com"
        return ("192.0.2.10",)


class FakeHttpProbe:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario

    def probe(self, hosts: tuple[Host, ...]) -> HttpProbeProviderResult:
        self.scenario.called("http")
        endpoint = HttpProbeEndpoint(
            url="https://app.example.com",
            scheme="https",
            hostname="app.example.com",
            port=443,
            status_code=200,
            ip_address="192.0.2.10",
        )
        partial = self.scenario.mode == "partial"
        return HttpProbeProviderResult(
            endpoints=(endpoint,),
            responsive_hosts=hosts,
            status=(
                HttpProbeProviderStatus.PARTIAL
                if partial
                else HttpProbeProviderStatus.SUCCESS
            ),
            message="Some probe records were rejected." if partial else None,
        )


class FakeCrawler:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario

    def crawl(self, hosts: tuple[Host, ...]) -> WebCrawlProviderResult:
        self.scenario.called("crawl")
        assert len(hosts) == 1
        if self.scenario.mode == "failure":
            return WebCrawlProviderResult(
                status=WebCrawlProviderStatus.FAILURE,
                message="Web crawling failed.",
            )
        endpoints = (Endpoint("app.example.com", 443, "https", "/"),)
        if self.scenario.mode == "crawl_limit":
            endpoints += (
                Endpoint("app.example.com", 443, "https", "/second"),
            )
        return WebCrawlProviderResult(endpoints=endpoints)


class FakeTechnologyDetector:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario

    def detect(
        self, endpoints: tuple[Endpoint, ...]
    ) -> TechnologyDetectionProviderResult:
        self.scenario.called("technology")
        assert endpoints == (Endpoint("app.example.com", 443, "https", "/"),)
        if self.scenario.mode == "error":
            return TechnologyDetectionProviderResult(
                status=TechnologyDetectionProviderStatus.UNAVAILABLE,
                message="Technology provider is unavailable.",
            )
        technologies = (
            Technology(
                name="nginx",
                category="web-server",
                version="1.24.0",
                vendor="nginx",
                source="https://app.example.com/",
                confidence=100,
            ),
        )
        if self.scenario.mode == "technology_limit":
            technologies += (
                Technology(
                    name="python",
                    category="programming-language",
                    source="https://app.example.com/",
                    confidence=100,
                ),
            )
        if self.scenario.mode == "technology_partial":
            return TechnologyDetectionProviderResult(
                technologies=technologies,
                status=TechnologyDetectionProviderStatus.PARTIAL,
                malformed_record_count=1,
                partial_reasons=(
                    TechnologyDetectionPartialReason.MALFORMED_RECORDS_SKIPPED,
                ),
            )
        return TechnologyDetectionProviderResult(technologies=technologies)


class FakeVulnerabilities:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario

    def search_cpe_candidates(
        self, name: str, version: str, vendor: str | None = None
    ) -> tuple[NvdCpeCandidate, ...]:
        self.scenario.called("vulnerability_search")
        assert (name, version, vendor) == ("nginx", "1.24.0", "nginx")
        return (
            NvdCpeCandidate(
                cpe_name="cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
                title="nginx",
                deprecated=False,
                vendor="nginx",
                product="nginx",
                version="1.24.0",
            ),
        )

    def get_vulnerabilities(
        self, cpe_name: str
    ) -> tuple[NvdVulnerabilityRecord, ...]:
        self.scenario.called("vulnerability_records")
        assert cpe_name.startswith("cpe:2.3:a:nginx:nginx:")
        return (
            NvdVulnerabilityRecord(
                identifier="CVE-2026-0001",
                description="Deterministic test vulnerability.",
                severity="HIGH",
                cvss_score=8.1,
                status="Analyzed",
            ),
        )


class RecordingSink:
    def __init__(self) -> None:
        self._events: list[DiagnosticEvent] = []

    def emit(self, event: DiagnosticEvent) -> None:
        self._events.append(event)

    @property
    def events(self) -> tuple[DiagnosticEvent, ...]:
        return tuple(self._events)


def _orchestrator(
    scenario: Scenario,
    *,
    diagnostic_sink: DiagnosticEventSink | None = None,
) -> ScanOrchestrator:
    factories = create_default_factory_registry(
        dependencies=CapabilityDependencies(
            subdomain_provider=FakeSubdomains(scenario),
            host_resolver=FakeResolver(scenario),
            http_transport=FakeHttpProbe(scenario),
            web_crawler=FakeCrawler(scenario),
            technology_detector=FakeTechnologyDetector(scenario),
            vulnerability_provider=FakeVulnerabilities(scenario),
        )
    )
    return ScanOrchestrator(
        capability_registry=create_default_registry(),
        factory_registry=factories,
        diagnostic_sink=diagnostic_sink,
    )


def test_full_success_uses_complete_offline_composition_once() -> None:
    scenario = Scenario()
    result = _orchestrator(scenario).run(
        ScanConfig.for_full_assessment("EXAMPLE.com.")
    )

    assert result.plan.required_capabilities == FULL_ORDER
    assert result.pipeline_result.executed_capabilities == FULL_ORDER
    assert result.runtime_status is Status.SUCCESS
    assert result.accepted
    assert result.preflight.ready
    assert result.final_context.target_id == "example.com"
    assert result.final_context.has(PipelineStateKey.RISK_INTELLIGENCE)
    risk = result.final_context.get(PipelineStateKey.RISK_INTELLIGENCE)
    assert isinstance(risk, RiskIntelligence)
    assert len(risk.assessments) == 1
    assert scenario.calls == {
        "subdomain": 1,
        "resolver": 1,
        "http": 1,
        "crawl": 1,
        "technology": 1,
        "vulnerability_search": 1,
        "vulnerability_records": 1,
    }


def test_reconnaissance_builds_and_executes_only_recon_closure() -> None:
    scenario = Scenario()
    result = _orchestrator(scenario).run(
        ScanConfig.for_reconnaissance("example.com")
    )

    assert result.plan.required_capabilities == RECON_ORDER
    assert result.pipeline_result.execution_order == RECON_ORDER
    assert result.runtime_status is Status.SUCCESS
    assert result.accepted
    assert not result.final_context.has(PipelineStateKey.ASSET_INTELLIGENCE)
    assert "vulnerability_search" not in scenario.calls


def test_reconnaissance_diagnostic_lifecycle_order_is_deterministic() -> None:
    sink = RecordingSink()

    result = _orchestrator(
        Scenario(),
        diagnostic_sink=sink,
    ).run(ScanConfig.for_reconnaissance("example.com"))

    expected_capabilities: list[DiagnosticEventType] = []
    for _ in RECON_ORDER:
        expected_capabilities.extend(
            (
                DiagnosticEventType.CAPABILITY_STARTED,
                DiagnosticEventType.CAPABILITY_COMPLETED,
            )
        )
    assert tuple(event.event_type for event in sink.events) == (
        DiagnosticEventType.SCAN_PREPARATION_STARTED,
        DiagnosticEventType.SCAN_PREPARATION_COMPLETED,
        DiagnosticEventType.SCAN_PREFLIGHT_STARTED,
        DiagnosticEventType.SCAN_PREFLIGHT_COMPLETED,
        DiagnosticEventType.SCAN_BUILD_STARTED,
        DiagnosticEventType.SCAN_BUILD_COMPLETED,
        DiagnosticEventType.SCAN_EXECUTION_STARTED,
        *expected_capabilities,
        DiagnosticEventType.SCAN_EXECUTION_COMPLETED,
        DiagnosticEventType.SCAN_RESULT_CREATED,
    )
    capability_events = tuple(
        event
        for event in sink.events
        if event.event_type is DiagnosticEventType.CAPABILITY_COMPLETED
    )
    assert tuple(
        event.fields.capability_id for event in capability_events
    ) == RECON_ORDER
    assert result.runtime_status is Status.SUCCESS


def test_partial_diagnostic_preserves_status_and_acceptance_separately() -> None:
    sink = RecordingSink()

    result = _orchestrator(
        Scenario(mode="partial"),
        diagnostic_sink=sink,
    ).run(
        ScanConfig.for_reconnaissance(
            "example.com",
            allow_partial_results=True,
        )
    )

    partial = tuple(
        event
        for event in sink.events
        if event.event_type is DiagnosticEventType.CAPABILITY_PARTIAL
    )
    assert len(partial) == 1
    assert partial[0].fields.capability_id == "http_probe"
    assert partial[0].fields.runtime_status == "PARTIAL"
    created = sink.events[-1]
    assert created.event_type is DiagnosticEventType.SCAN_RESULT_CREATED
    assert created.fields.runtime_status == "PARTIAL"
    assert created.fields.accepted is True
    assert result.runtime_status is Status.PARTIAL
    assert result.accepted


def test_technology_partial_reason_reaches_diagnostic_event_only() -> None:
    sink = RecordingSink()

    result = _orchestrator(
        Scenario(mode="technology_partial"),
        diagnostic_sink=sink,
    ).run(
        ScanConfig.for_reconnaissance(
            "example.com",
            allow_partial_results=True,
        )
    )

    partial = tuple(
        event
        for event in sink.events
        if event.event_type is DiagnosticEventType.CAPABILITY_PARTIAL
    )
    assert len(partial) == 1
    assert partial[0].fields.capability_id == "technology_detection"
    assert partial[0].fields.runtime_status == "PARTIAL"
    assert partial[0].fields.partial_reasons == (
        TechnologyDetectionPartialReason.MALFORMED_RECORDS_SKIPPED,
    )
    assert result.runtime_status is Status.PARTIAL
    assert result.accepted


def test_diagnostics_contain_no_target_evidence_or_runtime_internals() -> None:
    sink = RecordingSink()

    _orchestrator(
        Scenario(),
        diagnostic_sink=sink,
    ).run(ScanConfig.for_reconnaissance("example.com"))

    rendered = repr(sink.events).lower()
    for forbidden in (
        "example.com",
        "app.example.com",
        "192.0.2.10",
        "nginx",
        "stdout",
        "stderr",
        "environment",
        "executable",
        "context(",
        "0x",
    ):
        assert forbidden not in rendered


def test_clean_empty_scan_is_successful_and_skips_downstream_providers() -> None:
    scenario = Scenario(mode="empty")
    result = _orchestrator(scenario).run(
        ScanConfig.for_full_assessment("example.com")
    )

    assert result.runtime_status is Status.SUCCESS
    assert result.accepted
    assert result.pipeline_result.executed_capabilities == FULL_ORDER
    assert scenario.calls == {"subdomain": 1}
    assert result.final_context.get(PipelineStateKey.TECHNOLOGIES) == ()
    assert result.final_context.get(PipelineStateKey.RISK_INTELLIGENCE) == (
        RiskIntelligence()
    )


def test_partial_acceptance_policy_does_not_change_runtime_result() -> None:
    accepted_scenario = Scenario(mode="partial")
    rejected_scenario = Scenario(mode="partial")

    accepted = _orchestrator(accepted_scenario).run(
        ScanConfig.for_full_assessment(
            "example.com", allow_partial_results=True
        )
    )
    rejected = _orchestrator(rejected_scenario).run(
        ScanConfig.for_full_assessment(
            "example.com", allow_partial_results=False
        )
    )

    assert accepted.runtime_status is rejected.runtime_status is Status.PARTIAL
    assert accepted.accepted
    assert not rejected.accepted
    assert accepted.final_context == rejected.final_context
    assert accepted.execution_history == rejected.execution_history
    assert accepted_scenario.calls == rejected_scenario.calls


def test_intermediate_failure_returns_rejected_runtime_result() -> None:
    scenario = Scenario(mode="failure")
    result = _orchestrator(scenario).run(
        ScanConfig.for_full_assessment("example.com")
    )

    assert result.runtime_status is Status.FAILURE
    assert not result.accepted
    assert result.pipeline_result.executed_capabilities[-1] == "web_crawl"
    assert result.final_context.has(PipelineStateKey.ALIVE_HOSTS)
    assert not result.final_context.has(PipelineStateKey.ENDPOINTS)
    assert not result.final_context.has(PipelineStateKey.TECHNOLOGIES)
    assert "technology" not in scenario.calls


def test_provider_unavailable_returns_rejected_sanitized_error_result() -> None:
    scenario = Scenario(mode="error")
    result = _orchestrator(scenario).run(
        ScanConfig.for_full_assessment("example.com")
    )

    assert result.runtime_status is Status.ERROR
    assert not result.accepted
    assert result.pipeline_result.executed_capabilities[-1] == (
        "technology_detection"
    )
    assert not result.final_context.has(PipelineStateKey.TECHNOLOGIES)
    assert "vulnerability_search" not in scenario.calls
    safe = repr(result)
    assert "example.com" not in safe
    assert "path" not in safe.lower()
    assert "environment" not in safe.lower()
    assert "stdout" not in safe.lower()
    assert "stderr" not in safe.lower()


@pytest.mark.parametrize("allow_partial_results", (True, False))
def test_reconnaissance_technology_limit_preserves_upstream_and_is_rejected(
    allow_partial_results: bool,
) -> None:
    scenario = Scenario(mode="technology_limit")
    result = _orchestrator(scenario).run(
        ScanConfig.for_reconnaissance(
            "example.com",
            limits=ScanLimits(max_technologies=1),
            allow_partial_results=allow_partial_results,
        )
    )

    assert result.runtime_status is Status.FAILURE
    assert not result.accepted
    assert result.final_context.has(PipelineStateKey.ENDPOINTS)
    assert not result.final_context.has(PipelineStateKey.TECHNOLOGIES)
    assert result.pipeline_result.executed_capabilities == RECON_ORDER
    assert result.policy_violation == StateLimitViolation(
        PipelineStateKey.TECHNOLOGIES,
        observed=2,
        allowed=1,
    )
    assert "vulnerability_search" not in scenario.calls


def test_limit_diagnostic_precedes_terminal_capability_event() -> None:
    sink = RecordingSink()

    result = _orchestrator(
        Scenario(mode="technology_limit"),
        diagnostic_sink=sink,
    ).run(
        ScanConfig.for_reconnaissance(
            "example.com",
            limits=ScanLimits(max_technologies=1),
        )
    )

    event_types = tuple(event.event_type for event in sink.events)
    limit_position = event_types.index(
        DiagnosticEventType.POLICY_LIMIT_EXCEEDED
    )
    assert event_types[limit_position - 1] is (
        DiagnosticEventType.CAPABILITY_STARTED
    )
    assert event_types[limit_position + 1] is (
        DiagnosticEventType.CAPABILITY_FAILED
    )
    assert event_types[-2:] == (
        DiagnosticEventType.SCAN_EXECUTION_COMPLETED,
        DiagnosticEventType.SCAN_RESULT_CREATED,
    )
    event = sink.events[limit_position]
    assert event.fields.state_key == "TECHNOLOGIES"
    assert event.fields.observed == 2
    assert event.fields.allowed == 1
    assert result.runtime_status is Status.FAILURE


def test_full_crawl_limit_stops_technology_and_intelligence() -> None:
    scenario = Scenario(mode="crawl_limit")
    result = _orchestrator(scenario).run(
        ScanConfig.for_full_assessment(
            "example.com",
            limits=ScanLimits(max_crawl_endpoints=1),
        )
    )

    assert result.runtime_status is Status.FAILURE
    assert not result.accepted
    assert result.final_context.has(PipelineStateKey.HTTP_ENDPOINTS)
    assert result.final_context.has(PipelineStateKey.ALIVE_HOSTS)
    assert not result.final_context.has(PipelineStateKey.ENDPOINTS)
    assert not result.final_context.has(PipelineStateKey.TECHNOLOGIES)
    assert result.pipeline_result.executed_capabilities == FULL_ORDER[:4]
    assert "technology" not in scenario.calls


class ScriptedClock:
    def __init__(self, observations: tuple[float, ...]) -> None:
        self._observations = observations
        self._position = 0

    def monotonic(self) -> float:
        value = self._observations[self._position]
        if self._position < len(self._observations) - 1:
            self._position += 1
        return value


@pytest.mark.parametrize("allow_partial_results", (True, False))
def test_orchestrator_deadline_before_first_step_returns_rejected_result(
    allow_partial_results: bool,
) -> None:
    calls: dict[str, int] = {}
    factories = CapabilityFactoryRegistry()
    identity = CapabilityId("technology_source")
    factories.register(
        identity,
        lambda: _counting_factory(identity, calls),
    )
    orchestrator = _single_state_orchestrator(
        factories,
        clock=ScriptedClock((0, 1)),
    )

    result = orchestrator.run(
        ScanConfig.for_reconnaissance(
            "example.com",
            limits=ScanLimits(overall_timeout_seconds=1),
            allow_partial_results=allow_partial_results,
        )
    )

    assert result.runtime_status is Status.FAILURE
    assert not result.accepted
    assert calls == {"factory": 1}
    assert result.pipeline_result.executed_capabilities == ()
    assert result.policy_violation == DeadlineViolation(
        DeadlinePhase.BEFORE_CAPABILITY
    )


def test_deadline_diagnostic_contains_no_clock_values() -> None:
    calls: dict[str, int] = {}
    factories = CapabilityFactoryRegistry()
    identity = CapabilityId("technology_source")
    factories.register(
        identity,
        lambda: _counting_factory(identity, calls),
    )
    sink = RecordingSink()
    orchestrator = _single_state_orchestrator(
        factories,
        clock=ScriptedClock((0, 1)),
        diagnostic_sink=sink,
    )

    result = orchestrator.run(
        ScanConfig.for_reconnaissance(
            "example.com",
            limits=ScanLimits(overall_timeout_seconds=1),
        )
    )

    event_types = tuple(event.event_type for event in sink.events)
    position = event_types.index(
        DiagnosticEventType.POLICY_DEADLINE_EXCEEDED
    )
    assert event_types[position - 1] is DiagnosticEventType.CAPABILITY_STARTED
    assert event_types[position + 1] is DiagnosticEventType.CAPABILITY_FAILED
    assert sink.events[position].fields.policy_type == "deadline"
    assert sink.events[position].fields.observed is None
    assert sink.events[position].fields.allowed is None
    assert result.runtime_status is Status.FAILURE


@pytest.mark.parametrize(
    ("status", "allow_partial", "expected"),
    (
        (Status.SUCCESS, True, True),
        (Status.SUCCESS, False, True),
        (Status.PARTIAL, True, True),
        (Status.PARTIAL, False, False),
        (Status.FAILURE, True, False),
        (Status.ERROR, True, False),
    ),
)
def test_acceptance_policy_is_pure(
    status: Status,
    allow_partial: bool,
    expected: bool,
) -> None:
    assert (
        is_scan_result_accepted(
            status, allow_partial_results=allow_partial
        )
        is expected
    )


class CountingCapability(Capability):
    def __init__(
        self,
        capability_id: CapabilityId,
        calls: dict[str, int],
    ) -> None:
        self._capability_id = capability_id
        self._calls = calls

    @property
    def name(self) -> str:
        return self._capability_id.value

    def execute(self, context: Context) -> Result[Any]:  # noqa: ARG002
        self._calls["execute"] = self._calls.get("execute", 0) + 1
        return Result(status=Status.SUCCESS, data=())


def test_disabled_dependency_fails_before_preflight_factory_or_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preflight_calls = 0

    def unexpected_preflight(
        self: ScanPreflight,  # noqa: ARG001
        *,
        prepared_scan: PreparedScan,  # noqa: ARG001
        factory_registry: CapabilityFactoryRegistry,  # noqa: ARG001
    ) -> PreflightResult:
        nonlocal preflight_calls
        preflight_calls += 1
        raise AssertionError("preflight must not run")

    monkeypatch.setattr(
        orchestration_module.ScanPreflight,
        "run",
        unexpected_preflight,
    )
    factory_calls: dict[str, int] = {}
    factories = CapabilityFactoryRegistry()
    for capability_id in BUILTIN_CAPABILITY_IDS:
        factories.register(
            capability_id,
            lambda capability_id=capability_id: _counting_factory(
                capability_id, factory_calls
            ),
        )
    orchestrator = ScanOrchestrator(
        capability_registry=create_default_registry(),
        factory_registry=factories,
    )
    config = ScanConfig.for_full_assessment(
        "example.com",
        disabled_capabilities=(CapabilityId("technology_detection"),),
    )

    with pytest.raises(DisabledCapabilityError, match="technology_detection"):
        orchestrator.run(config)

    assert factory_calls == {}
    assert preflight_calls == 0


def _counting_factory(
    capability_id: CapabilityId,
    calls: dict[str, int],
) -> CountingCapability:
    calls["factory"] = calls.get("factory", 0) + 1
    return CountingCapability(capability_id, calls)


def _single_state_orchestrator(
    factories: CapabilityFactoryRegistry,
    *,
    clock: ScriptedClock | None = None,
    diagnostic_sink: DiagnosticEventSink | None = None,
) -> ScanOrchestrator:
    registry = CapabilityRegistry(
        (
            CapabilityDefinition(
                capability_id=CapabilityId("technology_source"),
                display_name="Technology Source",
                description="Test-only technology state producer.",
                version="1.0",
                provides=(PipelineStateKey.TECHNOLOGIES,),
            ),
        )
    )
    return ScanOrchestrator(
        capability_registry=registry,
        factory_registry=factories,
        clock=clock,
        diagnostic_sink=diagnostic_sink,
    )


def test_missing_factory_fails_preflight_before_context_or_scan_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context_calls = 0

    def unexpected_context(config: ScanConfig) -> Context:
        nonlocal context_calls
        context_calls += 1
        return Context(target_id=config.scope.root.value)

    monkeypatch.setattr(
        orchestration_module,
        "create_initial_context",
        unexpected_context,
    )
    with pytest.raises(ScanPreflightError) as caught:
        _single_state_orchestrator(CapabilityFactoryRegistry()).run(
            ScanConfig.for_reconnaissance("example.com")
        )

    assert not caught.value.result.ready
    assert context_calls == 0
    assert "example.com" not in str(caught.value)


def test_preflight_failure_emits_only_preparation_and_preflight_events() -> None:
    sink = RecordingSink()

    with pytest.raises(ScanPreflightError):
        _single_state_orchestrator(
            CapabilityFactoryRegistry(),
            diagnostic_sink=sink,
        ).run(ScanConfig.for_reconnaissance("example.com"))

    assert tuple(event.event_type for event in sink.events) == (
        DiagnosticEventType.SCAN_PREPARATION_STARTED,
        DiagnosticEventType.SCAN_PREPARATION_COMPLETED,
        DiagnosticEventType.SCAN_PREFLIGHT_STARTED,
        DiagnosticEventType.SCAN_PREFLIGHT_FAILED,
    )
    failure = sink.events[-1]
    assert failure.fields.ready is False
    assert failure.fields.preflight_checks_total == 1
    assert failure.fields.preflight_checks_failed == 1


@pytest.mark.parametrize(
    ("mode", "expected_status", "expected_accepted", "expected_calls"),
    (
        ("success", Status.SUCCESS, True, 19),
        ("failure", Status.FAILURE, False, 17),
    ),
)
def test_failing_diagnostic_sink_does_not_change_scan_result(
    mode: str,
    expected_status: Status,
    expected_accepted: bool,
    expected_calls: int,
) -> None:
    class RaisingSink:
        def __init__(self) -> None:
            self.calls = 0

        def emit(self, event: DiagnosticEvent) -> None:
            _ = event
            self.calls += 1
            raise RuntimeError("private sink failure")

    sink = RaisingSink()
    result = _orchestrator(
        Scenario(mode=mode),
        diagnostic_sink=sink,
    ).run(ScanConfig.for_reconnaissance("example.com"))

    assert result.runtime_status is expected_status
    assert result.accepted is expected_accepted
    assert sink.calls == expected_calls


def test_factory_identity_mismatch_is_preserved_before_execution() -> None:
    calls: dict[str, int] = {}
    factories = CapabilityFactoryRegistry()
    factories.register(
        CapabilityId("technology_source"),
        lambda: _counting_factory(CapabilityId("wrong_identity"), calls),
    )

    with pytest.raises(CapabilityDescriptorMismatchError):
        _single_state_orchestrator(factories).run(
            ScanConfig.for_reconnaissance("example.com")
        )

    assert calls == {"factory": 1}


def test_one_run_prepares_builds_executes_and_evaluates_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, int] = {}
    original_prepare = orchestration_module.prepare_scan
    original_preflight = orchestration_module.ScanPreflight.run
    original_create_context = orchestration_module.create_initial_context
    original_acceptance = orchestration_module.is_scan_result_accepted

    def counted_prepare(
        *,
        config: ScanConfig,
        registry: CapabilityRegistry,
    ) -> PreparedScan:
        calls["prepare"] = calls.get("prepare", 0) + 1
        return original_prepare(config=config, registry=registry)

    def counted_create_context(config: ScanConfig) -> Context:
        calls["context"] = calls.get("context", 0) + 1
        return original_create_context(config)

    def counted_preflight(
        self: ScanPreflight,
        *,
        prepared_scan: PreparedScan,
        factory_registry: CapabilityFactoryRegistry,
    ) -> PreflightResult:
        calls["preflight"] = calls.get("preflight", 0) + 1
        return original_preflight(
            self,
            prepared_scan=prepared_scan,
            factory_registry=factory_registry,
        )

    def counted_acceptance(
        status: Status,
        *,
        allow_partial_results: bool,
    ) -> bool:
        calls["acceptance"] = calls.get("acceptance", 0) + 1
        return original_acceptance(
            status,
            allow_partial_results=allow_partial_results,
        )

    monkeypatch.setattr(orchestration_module, "prepare_scan", counted_prepare)
    monkeypatch.setattr(
        orchestration_module.ScanPreflight,
        "run",
        counted_preflight,
    )
    monkeypatch.setattr(
        orchestration_module,
        "create_initial_context",
        counted_create_context,
    )
    monkeypatch.setattr(
        orchestration_module,
        "is_scan_result_accepted",
        counted_acceptance,
    )
    factories = CapabilityFactoryRegistry()
    identity = CapabilityId("technology_source")
    factories.register(
        identity,
        lambda: _counting_factory(identity, calls),
    )

    result = _single_state_orchestrator(factories).run(
        ScanConfig.for_reconnaissance("example.com")
    )

    assert calls == {
        "prepare": 1,
        "preflight": 1,
        "context": 1,
        "factory": 1,
        "execute": 1,
        "acceptance": 1,
    }
    assert result.plan.required_capability_ids == (identity,)
    assert len(result.execution_history) == 1


def test_scan_result_is_immutable_deterministic_and_process_free() -> None:
    first = _orchestrator(Scenario()).run(
        ScanConfig.for_reconnaissance("example.com")
    )
    second = _orchestrator(Scenario()).run(
        ScanConfig.for_reconnaissance("example.com")
    )

    assert first == second
    assert not hasattr(first, "__dict__")
    assert tuple(item.name for item in fields(ScanResult)) == (
        "config",
        "plan",
        "preflight",
        "pipeline_result",
        "accepted",
    )
    with pytest.raises(FrozenInstanceError):
        first.accepted = False  # type: ignore[misc]
    for forbidden in (
        "stdout",
        "stderr",
        "argv",
        "environment",
        "executable",
        "toolrunner",
        "pipeline=",
    ):
        assert forbidden not in repr(first).lower()
