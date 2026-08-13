"""Runtime-readiness tests for the complete default capability graph."""

from dataclasses import dataclass, field

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.host_resolver import HostResolverError
from redforge.adapters.nvd import NvdCpeCandidate, NvdVulnerabilityRecord
from redforge.domain.asset_intelligence import AssetIntelligence
from redforge.domain.endpoint import Endpoint
from redforge.domain.host import Host, HostResolution
from redforge.domain.http_probe import HttpProbeEndpoint
from redforge.domain.knowledge_graph import KnowledgeGraph
from redforge.domain.risk_intelligence import RiskIntelligence
from redforge.domain.technology import Technology
from redforge.domain.vulnerability_intelligence import VulnerabilityIntelligence
from redforge.planning import (
    BUILTIN_CAPABILITY_IDS,
    CapabilityDependencies,
    create_default_factory_registry,
    create_default_planned_execution,
    create_default_registry,
)
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.context import Context
from redforge.sdk.http_probe import (
    HttpProbeProviderResult,
    HttpProbeProviderStatus,
)
from redforge.sdk.result import Status
from redforge.sdk.subdomain_discovery import (
    SubdomainDiscoveryResult,
    SubdomainDiscoveryStatus,
)
from redforge.sdk.technology_detection import (
    TechnologyDetectionProviderResult,
    TechnologyDetectionProviderStatus,
)
from redforge.sdk.web_crawl import (
    WebCrawlProviderResult,
    WebCrawlProviderStatus,
)

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
FULL_STATE = tuple(
    key
    for key in PipelineStateKey
    if key
    not in {
        PipelineStateKey.VULNERABILITIES,
        PipelineStateKey.CANONICAL_FINDINGS,
        PipelineStateKey.ENRICHED_VULNERABILITIES,
    }
)


@dataclass(slots=True)
class Scenario:
    """Deterministic provider outcomes and invocation counters."""

    empty: bool = False
    failure_at: str | None = None
    partial_at: str | None = None
    unavailable_technology: bool = False
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
        if self.scenario.failure_at == "subdomain":
            return SubdomainDiscoveryResult(
                status=SubdomainDiscoveryStatus.FAILURE,
                message="Subdomain discovery failed.",
            )
        hostnames = () if self.scenario.empty else ("app.example.com",)
        status = (
            SubdomainDiscoveryStatus.PARTIAL
            if self.scenario.partial_at == "subdomain"
            else SubdomainDiscoveryStatus.SUCCESS
        )
        return SubdomainDiscoveryResult(
            hostnames=hostnames,
            status=status,
            message=(
                "Some records were rejected."
                if status is SubdomainDiscoveryStatus.PARTIAL
                else None
            ),
        )


class FakeResolver:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario

    def resolve(self, hostname: str) -> tuple[str, ...]:
        self.scenario.called("resolver")
        assert hostname == "app.example.com"
        if self.scenario.failure_at == "resolver":
            raise HostResolverError("resolution unavailable")
        return ("192.0.2.10",)


class FakeHttpProbe:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario

    def probe(self, hosts: tuple[Host, ...]) -> HttpProbeProviderResult:
        self.scenario.called("http")
        assert len(hosts) == 1
        if self.scenario.failure_at == "http":
            return HttpProbeProviderResult(
                status=HttpProbeProviderStatus.FAILURE,
                message="HTTP probing failed.",
            )
        endpoint = HttpProbeEndpoint(
            url="https://app.example.com",
            scheme="https",
            hostname="app.example.com",
            port=443,
            status_code=200,
            ip_address="192.0.2.10",
        )
        return HttpProbeProviderResult(
            endpoints=(endpoint,),
            responsive_hosts=hosts,
            status=(
                HttpProbeProviderStatus.PARTIAL
                if self.scenario.partial_at == "http"
                else HttpProbeProviderStatus.SUCCESS
            ),
            message=(
                "Some probe records were rejected."
                if self.scenario.partial_at == "http"
                else None
            ),
        )


class FakeCrawler:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario

    def crawl(self, hosts: tuple[Host, ...]) -> WebCrawlProviderResult:
        self.scenario.called("crawl")
        assert len(hosts) == 1
        if self.scenario.failure_at == "crawl":
            return WebCrawlProviderResult(
                status=WebCrawlProviderStatus.FAILURE,
                message="Web crawling failed.",
            )
        return WebCrawlProviderResult(
            endpoints=(Endpoint("app.example.com", 443, "https", "/"),),
            status=(
                WebCrawlProviderStatus.PARTIAL
                if self.scenario.partial_at == "crawl"
                else WebCrawlProviderStatus.SUCCESS
            ),
            message=(
                "Some crawl records were rejected."
                if self.scenario.partial_at == "crawl"
                else None
            ),
        )


class FakeTechnologyDetector:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario

    def detect(
        self, endpoints: tuple[Endpoint, ...]
    ) -> TechnologyDetectionProviderResult:
        self.scenario.called("technology")
        assert endpoints == (Endpoint("app.example.com", 443, "https", "/"),)
        if self.scenario.unavailable_technology:
            return TechnologyDetectionProviderResult(
                status=TechnologyDetectionProviderStatus.UNAVAILABLE,
                message="Technology provider is unavailable.",
            )
        if self.scenario.failure_at == "technology":
            return TechnologyDetectionProviderResult(
                status=TechnologyDetectionProviderStatus.FAILURE,
                message="Technology detection failed.",
            )
        return TechnologyDetectionProviderResult(
            technologies=(
                Technology(
                    name="nginx",
                    category="web-server",
                    version="1.24.0",
                    vendor="nginx",
                    source="https://app.example.com/",
                    confidence=100,
                ),
            ),
            status=(
                TechnologyDetectionProviderStatus.PARTIAL
                if self.scenario.partial_at == "technology"
                else TechnologyDetectionProviderStatus.SUCCESS
            ),
            message=(
                "Some technology records were rejected."
                if self.scenario.partial_at == "technology"
                else None
            ),
        )


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
                title="nginx 1.24.0",
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


def _execution(scenario: Scenario):
    return create_default_planned_execution(
        dependencies=CapabilityDependencies(
            subdomain_provider=FakeSubdomains(scenario),
            host_resolver=FakeResolver(scenario),
            http_transport=FakeHttpProbe(scenario),
            web_crawler=FakeCrawler(scenario),
            technology_detector=FakeTechnologyDetector(scenario),
            vulnerability_provider=FakeVulnerabilities(scenario),
        )
    )


def _run(scenario: Scenario):
    execution = _execution(scenario)
    context = Context(target_id="example.com")
    plan = execution.plan(
        goals=(PipelineStateKey.RISK_INTELLIGENCE,),
        context=context,
    )
    return plan, execution.execute(plan=plan, context=context)


def test_default_registry_factory_and_producer_coverage() -> None:
    definitions = create_default_registry()
    factories = create_default_factory_registry(
        dependencies=CapabilityDependencies(
            subdomain_provider=FakeSubdomains(Scenario()),
            host_resolver=FakeResolver(Scenario()),
            http_transport=FakeHttpProbe(Scenario()),
            web_crawler=FakeCrawler(Scenario()),
            technology_detector=FakeTechnologyDetector(Scenario()),
            vulnerability_provider=FakeVulnerabilities(Scenario()),
        )
    )

    assert definitions.ids() == factories.ids == BUILTIN_CAPABILITY_IDS
    assert all(factories.create(item).name == item.value for item in factories.ids)
    assert all(
        len(definitions.producers_for(key)) == 1 for key in PipelineStateKey
    )


def test_complete_fake_pipeline_success_is_deterministic() -> None:
    scenario = Scenario()
    plan, result = _run(scenario)

    assert plan.required_capabilities == FULL_ORDER
    assert result.execution_order == FULL_ORDER
    assert result.executed_capabilities == FULL_ORDER
    assert tuple(item.capability_id for item in result.executions) == tuple(
        step.capability_id for step in plan.steps
    )
    assert result.status is Status.SUCCESS
    assert tuple(result.context.available_state_keys()) == tuple(
        sorted(FULL_STATE)
    )
    assert isinstance(result.context.get(PipelineStateKey.SUBDOMAINS), SubdomainDiscoveryResult)
    assert isinstance(result.context.get(PipelineStateKey.HOSTS), HostResolution)
    assert isinstance(result.context.get(PipelineStateKey.ASSET_INTELLIGENCE), AssetIntelligence)
    assert isinstance(
        result.context.get(PipelineStateKey.VULNERABILITY_INTELLIGENCE),
        VulnerabilityIntelligence,
    )
    assert isinstance(result.context.get(PipelineStateKey.KNOWLEDGE_GRAPH), KnowledgeGraph)
    risk = result.context.get(PipelineStateKey.RISK_INTELLIGENCE)
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
    assert len(result.executions) == len(plan.steps)
    assert "stdout" not in repr(result.executions).lower()


@pytest.mark.parametrize(
    "stage",
    ("subdomain", "resolver", "http", "crawl", "technology"),
)
def test_external_stage_failure_stops_without_downstream_publication(
    stage: str,
) -> None:
    scenario = Scenario(failure_at=stage)
    plan, result = _run(scenario)
    expected_last = {
        "subdomain": "subdomain_discovery",
        "resolver": "host_resolution",
        "http": "http_probe",
        "crawl": "web_crawl",
        "technology": "technology_detection",
    }[stage]
    provided = create_default_registry().require(expected_last).provides

    assert plan.required_capabilities == FULL_ORDER
    assert result.status in {Status.FAILURE, Status.ERROR}
    assert result.executed_capabilities[-1] == expected_last
    assert all(key not in result.context.state for key in provided)
    assert len(result.executions) == len(result.executed_capabilities)
    assert "vulnerability_search" not in scenario.calls


@pytest.mark.parametrize(
    "stage",
    ("subdomain", "http", "crawl", "technology"),
)
def test_usable_partial_evidence_continues_and_remains_partial(
    stage: str,
) -> None:
    scenario = Scenario(partial_at=stage)
    _, result = _run(scenario)

    assert result.status is Status.PARTIAL
    assert result.executed_capabilities == FULL_ORDER
    assert result.context.has(PipelineStateKey.RISK_INTELLIGENCE)
    assert sum(
        execution.result.status is Status.PARTIAL
        for execution in result.executions
    ) == 1


def test_unavailable_technology_stops_as_sanitized_error() -> None:
    scenario = Scenario(unavailable_technology=True)
    _, result = _run(scenario)

    assert result.status is Status.ERROR
    assert result.executed_capabilities[-1] == "technology_detection"
    assert not result.context.has(PipelineStateKey.TECHNOLOGIES)
    assert not result.context.has(PipelineStateKey.RISK_INTELLIGENCE)
    assert "vulnerability_search" not in scenario.calls
    assert "path" not in repr(result.last_result).lower()
    assert "environment" not in repr(result.last_result).lower()


def test_clean_empty_pipeline_publishes_canonical_empty_states_without_tools() -> None:
    scenario = Scenario(empty=True)
    plan, result = _run(scenario)

    assert result.status is Status.SUCCESS
    assert result.executed_capabilities == plan.required_capabilities == FULL_ORDER
    assert scenario.calls == {"subdomain": 1}
    assert result.context.get(PipelineStateKey.SUBDOMAINS).hostnames == ()
    assert result.context.get(PipelineStateKey.HOSTS) == HostResolution()
    for key in (
        PipelineStateKey.ALIVE_HOSTS,
        PipelineStateKey.HTTP_ENDPOINTS,
        PipelineStateKey.ENDPOINTS,
        PipelineStateKey.TECHNOLOGIES,
    ):
        assert result.context.get(key) == ()
    assert result.context.get(PipelineStateKey.RISK_INTELLIGENCE) == RiskIntelligence()
