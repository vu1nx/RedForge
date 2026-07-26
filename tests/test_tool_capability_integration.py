"""Test-only adapter and planned capability integration through ToolRunner."""

from typing import Any

from redforge.planning import (
    CapabilityDefinition,
    CapabilityFactoryRegistry,
    CapabilityId,
    CapabilityRegistry,
    ExecutionPlanner,
    PipelineBuilder,
    PlannedExecution,
)
from redforge.sdk import (
    Capability,
    Context,
    PipelineStateKey,
    Result,
    StatePublication,
    Status,
    ToolDefinition,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolInvocation,
    ToolRunner,
)
from redforge.sdk.subdomain_discovery import SubdomainDiscoveryResult
from redforge.testing import FakeToolRunner


class FakeDiscoveryAdapter:
    """Translate fake tool output into deterministic domain-shaped values."""

    def __init__(
        self,
        definition: ToolDefinition,
        runner: ToolRunner,
    ) -> None:
        self._definition = definition
        self._runner = runner

    def discover(self, target: str) -> tuple[str, ...]:
        result = self._runner.run(
            self._definition,
            ToolInvocation(
                self._definition.tool_id,
                arguments=("--target", target),
            ),
        )
        if result.status is not ToolExecutionStatus.SUCCESS:
            return ()
        return tuple(
            sorted(
                line.strip().lower()
                for line in result.stdout.splitlines()
                if line.strip()
            )
        )


class FakeToolDiscoveryCapability(Capability):
    """Publish parsed fake adapter output through the existing contract."""

    def __init__(self, adapter: FakeDiscoveryAdapter) -> None:
        self._adapter = adapter

    @property
    def name(self) -> str:
        return "fake_tool_discovery"

    def execute(self, context: Context) -> Result[Any]:
        hostnames = self._adapter.discover(context.target_id)
        if not hostnames:
            return Result(
                status=Status.ERROR,
                data=None,
                errors=["external discovery provider failed"],
            )
        return Result(
            status=Status.SUCCESS,
            data=None,
            publications=(
                StatePublication(
                    PipelineStateKey.SUBDOMAINS,
                    SubdomainDiscoveryResult(hostnames=hostnames),
                ),
            ),
        )


def _execution(
    fake: FakeToolRunner,
    tool_definition: ToolDefinition,
) -> PlannedExecution:
    capability_id = CapabilityId("fake_tool_discovery")
    definitions = CapabilityRegistry(
        (
            CapabilityDefinition(
                capability_id=capability_id,
                display_name="Fake Tool Discovery",
                description="Exercises the tool adapter boundary.",
                version="1.0",
                provides=(PipelineStateKey.SUBDOMAINS,),
                tags=("recon",),
            ),
        )
    )
    factories = CapabilityFactoryRegistry()
    factories.register(
        capability_id,
        lambda: FakeToolDiscoveryCapability(
            FakeDiscoveryAdapter(tool_definition, fake)
        ),
    )
    return PlannedExecution(
        planner=ExecutionPlanner(definitions),
        builder=PipelineBuilder(
            descriptor_registry=definitions,
            factory_registry=factories,
        ),
    )


def test_fake_tool_output_flows_through_planned_atomic_publication() -> None:
    tool = ToolDefinition(
        "fake_discovery_provider",
        "Fake Discovery Provider",
        "Produces deterministic test hostnames.",
        "fake",
    )
    fake = FakeToolRunner()
    fake.add_result(
        tool.tool_id,
        ToolExecutionResult(
            tool.tool_id,
            ToolExecutionStatus.SUCCESS,
            0,
            "b.example.com\na.example.com\n",
            "",
            0,
        ),
    )
    execution = _execution(fake, tool)
    context = Context(target_id="example.com")

    result = execution.run(
        goals=(PipelineStateKey.SUBDOMAINS,),
        initial_context=context,
    )

    assert result.status is Status.SUCCESS
    assert result.context.get(PipelineStateKey.SUBDOMAINS) == (
        SubdomainDiscoveryResult(
            hostnames=("a.example.com", "b.example.com")
        )
    )
    assert len(result.executions) == 1
    assert result.executions[0].capability_id == CapabilityId(
        "fake_tool_discovery"
    )
    assert len(fake.invocations) == 1
    assert fake.invocations[0].arguments == ("--target", "example.com")


def test_fake_tool_failure_maps_in_adapter_without_framework_policy() -> None:
    tool = ToolDefinition(
        "fake_discovery_provider",
        "Fake Discovery Provider",
        "Produces deterministic test hostnames.",
        "fake",
    )
    fake = FakeToolRunner()
    fake.add_result(
        tool.tool_id,
        ToolExecutionResult(
            tool.tool_id,
            ToolExecutionStatus.FAILURE,
            2,
            "",
            "bounded provider diagnostic",
            0,
        ),
    )

    result = _execution(fake, tool).run(
        goals=(PipelineStateKey.SUBDOMAINS,),
        initial_context=Context(target_id="example.com"),
    )

    assert result.status is Status.ERROR
    assert PipelineStateKey.SUBDOMAINS not in result.context.state
    assert len(result.executions) == 1
    assert result.executions[0].result.errors == [
        "external discovery provider failed"
    ]
