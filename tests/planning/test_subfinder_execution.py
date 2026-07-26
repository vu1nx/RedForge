"""End-to-end planned execution with the ToolRunner-backed Subfinder provider."""

from redforge.adapters import SUBFINDER_TOOL_ID
from redforge.planning import (
    SUBDOMAIN_DISCOVERY,
    CapabilityDependencies,
    create_default_planned_execution,
)
from redforge.sdk import (
    Context,
    PipelineStateKey,
    Status,
    SubdomainDiscoveryResult,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from redforge.testing import FakeToolRunner


class RecordingResolver:
    """Deterministic resolver recording normalized downstream input."""

    def __init__(self) -> None:
        self.hostnames: list[str] = []

    def resolve(self, hostname: str) -> tuple[str, ...]:
        self.hostnames.append(hostname)
        return ("192.0.2.10",)


def _fake_with_output(stdout: str) -> FakeToolRunner:
    fake = FakeToolRunner()
    fake.add_result(
        SUBFINDER_TOOL_ID,
        ToolExecutionResult(
            tool_id=SUBFINDER_TOOL_ID,
            status=ToolExecutionStatus.SUCCESS,
            exit_code=0,
            stdout=stdout,
            stderr="",
            duration_seconds=0,
        ),
    )
    return fake


def test_planned_subdomain_goal_uses_one_capability_and_tool_invocation() -> None:
    fake = _fake_with_output(
        '{"host":"B.Example.COM"}\n{"host":"a.example.com."}\n'
    )
    execution = create_default_planned_execution(
        dependencies=CapabilityDependencies(tool_runner=fake)
    )
    context = Context(target_id="example.com")

    plan = execution.plan(
        goals=(PipelineStateKey.SUBDOMAINS,),
        context=context,
    )
    result = execution.execute(plan=plan, context=context)

    assert plan.required_capability_ids == (SUBDOMAIN_DISCOVERY,)
    assert len(plan.steps) == 1
    assert result.status is Status.SUCCESS
    published = result.context.get(PipelineStateKey.SUBDOMAINS)
    assert isinstance(published, SubdomainDiscoveryResult)
    assert published.hostnames == ("a.example.com", "b.example.com")
    assert len(fake.invocations) == 1
    assert fake.invocations[0].tool_id == SUBFINDER_TOOL_ID
    assert fake.invocations[0].arguments[:2] == ("-d", "example.com")
    assert len(result.executions) == 1
    assert result.executions[0].capability_id == SUBDOMAIN_DISCOVERY


def test_host_resolution_consumes_subfinder_state_in_plan_order() -> None:
    fake = _fake_with_output(
        '{"host":"b.example.com"}\n{"host":"a.example.com"}\n'
    )
    resolver = RecordingResolver()
    execution = create_default_planned_execution(
        dependencies=CapabilityDependencies(
            tool_runner=fake,
            host_resolver=resolver,
        )
    )

    result = execution.run(
        goals=(PipelineStateKey.HOSTS,),
        initial_context=Context(target_id="example.com"),
    )

    assert result.executed_capabilities == (
        "subdomain_discovery",
        "host_resolution",
    )
    assert resolver.hostnames == ["a.example.com", "b.example.com"]
    assert len(fake.invocations) == 1
    assert result.status is Status.SUCCESS
    assert PipelineStateKey.HOSTS in result.context.state
    assert len(result.executions) == 2


def test_empty_successful_discovery_allows_empty_host_resolution() -> None:
    fake = _fake_with_output("")
    resolver = RecordingResolver()
    execution = create_default_planned_execution(
        dependencies=CapabilityDependencies(
            tool_runner=fake,
            host_resolver=resolver,
        )
    )

    result = execution.run(
        goals=(PipelineStateKey.HOSTS,),
        initial_context=Context(target_id="example.com"),
    )

    assert result.status is Status.SUCCESS
    assert resolver.hostnames == []
    assert result.executed_capabilities == (
        "subdomain_discovery",
        "host_resolution",
    )
