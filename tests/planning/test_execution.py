"""End-to-end planned execution tests through the existing Pipeline runtime."""

from typing import Any

from redforge.adapters.katana import WebCrawlAdapterResult
from redforge.adapters.subfinder import SubdomainDiscoveryResult
from redforge.adapters.technology_detection import TechnologyDetectionResult
from redforge.domain.endpoint import Endpoint
from redforge.domain.host import Host
from redforge.domain.http_probe import HttpProbeEndpoint
from redforge.domain.knowledge_graph import KnowledgeGraph
from redforge.domain.risk_intelligence import RiskIntelligence
from redforge.domain.technology import Technology
from redforge.planning import (
    CapabilityDependencies,
    CapabilityDescriptor,
    CapabilityFactoryRegistry,
    CapabilityId,
    CapabilityRegistry,
    ExecutionPlanner,
    PipelineBuilder,
    PlannedExecution,
    create_default_planned_execution,
)
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.http_probe import HttpProbeProviderResult
from redforge.sdk.result import Result, StatePublication, Status


class FakeResolver:
    """Resolve every requested hostname without DNS."""

    def resolve(self, hostname: str) -> tuple[str, ...]:  # noqa: ARG002
        return ("192.0.2.10",)


class FakeHttpTransport:
    """Return all resolved hosts as responsive."""

    def probe(self, hosts: tuple[Host, ...]) -> HttpProbeProviderResult:
        endpoints = tuple(
            HttpProbeEndpoint(
                url=f"https://{host.hostname}",
                scheme="https",
                hostname=host.hostname or host.addresses[0].value,
                port=443,
                status_code=200,
            )
            for host in hosts
        )
        return HttpProbeProviderResult(
            endpoints=endpoints,
            responsive_hosts=hosts,
        )


class FakeCrawler:
    """Return one deterministic endpoint without invoking a binary."""

    def crawl(self, hosts: tuple[Host, ...]) -> WebCrawlAdapterResult:  # noqa: ARG002
        return WebCrawlAdapterResult(endpoints=(Endpoint("app.example.com", 443, "https", "/"),))


class FakeDetector:
    """Return one deterministic technology without invoking a binary."""

    def detect(
        self,
        endpoints: tuple[Endpoint, ...],  # noqa: ARG002
    ) -> TechnologyDetectionResult:
        return TechnologyDetectionResult(
            technologies=(
                Technology(
                    name="nginx",
                    category="web-server",
                    source="https://app.example.com/",
                ),
            )
        )


class EmptyVulnerabilityProvider:
    """Typed provider whose empty results avoid all network access."""

    def search_cpe_candidates(
        self,
        name: str,
        version: str,
        vendor: str | None = None,
    ) -> tuple[()]:
        del name, version, vendor
        return ()

    def get_vulnerabilities(self, cpe_name: str) -> tuple[()]:  # noqa: ARG002
        return ()


class ResultCapability(Capability):
    """Configurable fake for status and stopping integration."""

    def __init__(
        self,
        name: str,
        result: Result[Any],
        calls: list[str],
    ) -> None:
        self._name = name
        self._result = result
        self._calls = calls

    @property
    def name(self) -> str:
        return self._name

    def execute(self, context: Context) -> Result[Any]:  # noqa: ARG002
        self._calls.append(self.name)
        return self._result


class PlannedMultiOutputCapability(Capability):
    """One planned capability that explicitly publishes two states."""

    def __init__(self, calls: list[str], name: str = "multi") -> None:
        self._calls = calls
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def execute(self, context: Context) -> Result[None]:  # noqa: ARG002
        self._calls.append(self.name)
        return Result(
            status=Status.SUCCESS,
            data=None,
            publications=(
                StatePublication(PipelineStateKey.HOSTS, ("host",)),
                StatePublication(PipelineStateKey.SUBDOMAINS, ("a.example",)),
            ),
        )


def _default_execution() -> PlannedExecution:
    return create_default_planned_execution(
        dependencies=CapabilityDependencies(
            host_resolver=FakeResolver(),
            http_transport=FakeHttpTransport(),
            web_crawler=FakeCrawler(),
            technology_detector=FakeDetector(),
            vulnerability_provider=EmptyVulnerabilityProvider(),
        )
    )


def _subdomain_context() -> Context:
    return Context(
        target_id="example.com",
        state={
            PipelineStateKey.SUBDOMAINS: SubdomainDiscoveryResult(hostnames=("app.example.com",))
        },
    )


def _custom_execution(
    results: dict[str, Result[Any]],
    calls: list[str],
) -> PlannedExecution:
    descriptors = CapabilityRegistry()
    for descriptor in (
        CapabilityDescriptor(
            name="a",
            provides=(PipelineStateKey.SUBDOMAINS,),
        ),
        CapabilityDescriptor(
            name="b",
            requires=(PipelineStateKey.SUBDOMAINS,),
            provides=(PipelineStateKey.HOSTS,),
        ),
        CapabilityDescriptor(
            name="c",
            requires=(PipelineStateKey.HOSTS,),
            provides=(PipelineStateKey.ALIVE_HOSTS,),
        ),
    ):
        descriptors.register(descriptor)
    factories = CapabilityFactoryRegistry()
    for name in ("a", "b", "c"):
        factories.register(
            name,
            lambda name=name: ResultCapability(name, results[name], calls),
        )
    return PlannedExecution(
        planner=ExecutionPlanner(descriptors),
        builder=PipelineBuilder(
            descriptor_registry=descriptors,
            factory_registry=factories,
        ),
    )


def test_state_presence_not_truthiness_makes_empty_value_available() -> None:
    execution = _default_execution()
    context = Context(
        target_id="example.com",
        state={PipelineStateKey.RISK_INTELLIGENCE: RiskIntelligence()},
    )

    plan = execution.plan(
        goals=(PipelineStateKey.RISK_INTELLIGENCE,),
        context=context,
    )
    result = execution.execute(plan=plan, context=context)

    assert plan.steps == ()
    assert result.status == Status.SUCCESS
    assert result.context is context
    assert result.context.state[PipelineStateKey.RISK_INTELLIGENCE] == RiskIntelligence()
    assert result.executions == ()
    assert result.last_result is None


def test_default_host_http_endpoint_and_technology_paths() -> None:
    expectations = (
        (PipelineStateKey.HOSTS, ("host_resolution",)),
        (
            PipelineStateKey.ALIVE_HOSTS,
            ("host_resolution", "http_probe"),
        ),
        (
            PipelineStateKey.HTTP_ENDPOINTS,
            ("host_resolution", "http_probe"),
        ),
        (
            PipelineStateKey.ENDPOINTS,
            ("host_resolution", "http_probe", "web_crawl"),
        ),
        (
            PipelineStateKey.TECHNOLOGIES,
            (
                "host_resolution",
                "http_probe",
                "web_crawl",
                "technology_detection",
            ),
        ),
    )
    for goal, names in expectations:
        execution = _default_execution()
        context = _subdomain_context()
        plan = execution.plan(goals=(goal,), context=context)
        result = execution.execute(plan=plan, context=context)

        assert plan.required_capabilities == names
        assert result.executed_capabilities == names
        assert result.status == Status.SUCCESS
        assert goal in result.context.state


def test_risk_from_existing_graph_executes_only_risk_capability() -> None:
    execution = _default_execution()
    context = Context(
        target_id="example.com",
        state={PipelineStateKey.KNOWLEDGE_GRAPH: KnowledgeGraph()},
    )

    plan = execution.plan(
        goals=(PipelineStateKey.RISK_INTELLIGENCE,),
        context=context,
    )
    result = execution.execute(plan=plan, context=context)

    assert plan.required_capabilities == ("risk_intelligence",)
    assert result.executed_capabilities == ("risk_intelligence",)
    assert result.status == Status.SUCCESS
    assert PipelineStateKey.RISK_INTELLIGENCE in result.context.state


def test_full_risk_path_is_deterministic_and_has_no_external_io() -> None:
    expected = (
        "asset_intelligence",
        "vulnerability_intelligence",
        "knowledge_graph",
        "risk_intelligence",
    )
    executed: list[tuple[str, ...]] = []
    for _ in range(2):
        execution = _default_execution()
        context = Context(target_id="example.com")
        plan = execution.plan(
            goals=(PipelineStateKey.RISK_INTELLIGENCE,),
            context=context,
        )
        result = execution.execute(plan=plan, context=context)
        executed.append(result.executed_capabilities)

        assert plan.required_capabilities == expected
        assert result.status == Status.SUCCESS
        assert PipelineStateKey.RISK_INTELLIGENCE in result.context.state

    assert executed == [expected, expected]


def test_partial_publishes_data_continues_and_remains_aggregate() -> None:
    calls: list[str] = []
    partial = Result(
        status=Status.PARTIAL,
        data=("partial",),
        errors=["one item failed"],
    )
    success_b = Result(status=Status.SUCCESS, data=("host",))
    success_c = Result(
        status=Status.SUCCESS,
        data=(Host(hostname="alive.example.com"),),
    )
    execution = _custom_execution(
        {"a": partial, "b": success_b, "c": success_c},
        calls,
    )
    context = Context(target_id="example.com")

    result = execution.run(
        goals=(PipelineStateKey.ALIVE_HOSTS,),
        initial_context=context,
    )

    assert calls == ["a", "b", "c"]
    assert result.status == Status.PARTIAL
    assert result.last_result is success_c
    assert result.executions[0].result is partial
    assert result.context.state[PipelineStateKey.SUBDOMAINS] == ("partial",)


def test_failure_stops_and_preserves_initial_and_earlier_state() -> None:
    calls: list[str] = []
    success = Result(status=Status.SUCCESS, data=("subdomain",))
    failure = Result(status=Status.FAILURE, data=("not-published",))
    skipped = Result(
        status=Status.SUCCESS,
        data=(Host(hostname="alive.example.com"),),
    )
    execution = _custom_execution(
        {"a": success, "b": failure, "c": skipped},
        calls,
    )
    context = Context(target_id="example.com", state={"custom": "preserved"})

    result = execution.run(
        goals=(PipelineStateKey.ALIVE_HOSTS,),
        initial_context=context,
    )

    assert calls == ["a", "b"]
    assert result.status == Status.FAILURE
    assert result.last_result is failure
    assert result.context.state["custom"] == "preserved"
    assert PipelineStateKey.SUBDOMAINS in result.context.state
    assert PipelineStateKey.HOSTS not in result.context.state
    assert PipelineStateKey.ALIVE_HOSTS not in result.context.state


def test_error_stops_without_publishing_and_leaves_plan_unchanged() -> None:
    calls: list[str] = []
    success = Result(status=Status.SUCCESS, data=("subdomain",))
    error = Result(
        status=Status.ERROR,
        data=("not-published",),
        errors=["sanitized execution error"],
    )
    skipped = Result(
        status=Status.SUCCESS,
        data=(Host(hostname="alive.example.com"),),
    )
    execution = _custom_execution(
        {"a": success, "b": error, "c": skipped},
        calls,
    )
    context = Context(target_id="example.com")
    plan = execution.plan(
        goals=(PipelineStateKey.ALIVE_HOSTS,),
        context=context,
    )
    original_plan = plan

    result = execution.execute(plan=plan, context=context)

    assert calls == ["a", "b"]
    assert result.status == Status.ERROR
    assert result.last_result is error
    assert PipelineStateKey.HOSTS not in result.context.state
    assert PipelineStateKey.ALIVE_HOSTS not in result.context.state
    assert plan == original_plan


def test_multiple_goals_share_dependencies_and_satisfied_goal_adds_no_step() -> None:
    execution = _default_execution()
    context = _subdomain_context()

    plan = execution.plan(
        goals=(
            PipelineStateKey.SUBDOMAINS,
            PipelineStateKey.ENDPOINTS,
            PipelineStateKey.TECHNOLOGIES,
        ),
        context=context,
    )
    result = execution.execute(plan=plan, context=context)

    assert plan.required_capabilities == (
        "host_resolution",
        "http_probe",
        "web_crawl",
        "technology_detection",
    )
    assert result.executed_capabilities == plan.required_capabilities
    assert all(goal in result.context.state for goal in plan.goals)


def test_reusing_facade_does_not_retain_state_or_history() -> None:
    execution = _default_execution()
    contexts = [_subdomain_context(), _subdomain_context()]
    results = [
        execution.run(
            goals=(PipelineStateKey.HOSTS,),
            initial_context=context,
        )
        for context in contexts
    ]

    assert results[0] is not results[1]
    assert results[0].context is contexts[0]
    assert results[1].context is contexts[1]
    assert results[0].executions is not results[1].executions
    assert results[0].executed_capabilities == results[1].executed_capabilities


def test_planned_execution_publishes_multiple_goals_from_one_step() -> None:
    descriptors = CapabilityRegistry()
    descriptors.register(
        CapabilityDescriptor(
            name="multi",
            provides=(
                PipelineStateKey.HOSTS,
                PipelineStateKey.SUBDOMAINS,
            ),
        )
    )
    calls: list[str] = []
    factories = CapabilityFactoryRegistry()
    factories.register("multi", lambda: PlannedMultiOutputCapability(calls))
    execution = PlannedExecution(
        planner=ExecutionPlanner(descriptors),
        builder=PipelineBuilder(
            descriptor_registry=descriptors,
            factory_registry=factories,
        ),
    )
    context = Context(target_id="example.com")
    plan = execution.plan(
        goals=(PipelineStateKey.HOSTS, PipelineStateKey.SUBDOMAINS),
        context=context,
    )
    original_plan = plan

    result = execution.execute(plan=plan, context=context)

    assert plan.required_capabilities == ("multi",)
    assert plan.required_capability_ids == (CapabilityId("multi"),)
    assert plan == original_plan
    assert calls == ["multi"]
    assert result.status == Status.SUCCESS
    assert result.context.get(PipelineStateKey.HOSTS) == ("host",)
    assert result.context.get(PipelineStateKey.SUBDOMAINS) == ("a.example",)
    assert len(result.executions) == 1
    assert result.executions[0].capability_id == CapabilityId("multi")


def test_custom_multi_output_definition_fans_out_without_legacy_fallback() -> None:
    definitions = CapabilityRegistry(
        (
            CapabilityDescriptor(
                name="source",
                provides=(
                    PipelineStateKey.SUBDOMAINS,
                    PipelineStateKey.HOSTS,
                ),
            ),
            CapabilityDescriptor(
                name="host_consumer",
                requires=(PipelineStateKey.HOSTS,),
                provides=(PipelineStateKey.ENDPOINTS,),
            ),
            CapabilityDescriptor(
                name="subdomain_consumer",
                requires=(PipelineStateKey.SUBDOMAINS,),
                provides=(PipelineStateKey.ALIVE_HOSTS,),
            ),
        )
    )
    calls: list[str] = []
    factories = CapabilityFactoryRegistry()
    factories.register(
        CapabilityId("source"),
        lambda: PlannedMultiOutputCapability(calls, "source"),
    )
    factories.register(
        CapabilityId("host_consumer"),
        lambda: ResultCapability(
            "host_consumer",
            Result(status=Status.SUCCESS, data=("endpoint",)),
            calls,
        ),
    )
    factories.register(
        CapabilityId("subdomain_consumer"),
        lambda: ResultCapability(
            "subdomain_consumer",
            Result(
                status=Status.SUCCESS,
                data=(Host(hostname="alive.example.com"),),
            ),
            calls,
        ),
    )
    execution = PlannedExecution(
        planner=ExecutionPlanner(definitions),
        builder=PipelineBuilder(
            descriptor_registry=definitions,
            factory_registry=factories,
        ),
    )
    context = Context(target_id="example.com")

    plan = execution.plan(
        goals=(PipelineStateKey.ENDPOINTS, PipelineStateKey.ALIVE_HOSTS),
        context=context,
    )
    result = execution.execute(plan=plan, context=context)

    assert plan.required_capability_ids == (
        CapabilityId("source"),
        CapabilityId("host_consumer"),
        CapabilityId("subdomain_consumer"),
    )
    assert calls == ["source", "host_consumer", "subdomain_consumer"]
    assert tuple(item.capability_id for item in result.executions) == (
        CapabilityId("source"),
        CapabilityId("host_consumer"),
        CapabilityId("subdomain_consumer"),
    )
    assert result.status == Status.SUCCESS
    assert result.context.get(PipelineStateKey.HOSTS) == ("host",)
    assert result.context.get(PipelineStateKey.SUBDOMAINS) == ("a.example",)
    assert result.context.get(PipelineStateKey.ENDPOINTS) == ("endpoint",)
    assert result.context.get(PipelineStateKey.ALIVE_HOSTS) == (
        Host(hostname="alive.example.com"),
    )
