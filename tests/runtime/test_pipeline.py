"""Tests for sequential pipeline execution."""

from typing import Any

from redforge.domain.target import Target
from redforge.runtime.pipeline import Pipeline, PipelineResult
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


class MockCapability(Capability):
    """Mock capability for pipeline testing."""

    def __init__(
        self,
        name: str,
        *,
        result: Result[Any] | None = None,
    ) -> None:
        self._name = name
        self._result = result
        self.execute_calls: list[Context] = []

    def execute(self, context: Context) -> Result[Any]:
        self.execute_calls.append(context)

        if self._result is None:
            raise ValueError("MockCapability requires result")

        return self._result

    @property
    def name(self) -> str:
        return self._name


def test_successful_pipeline_execution() -> None:
    """Test executing multiple capabilities successfully."""
    first = MockCapability(
        "discover",
        result=Result(status=Status.SUCCESS, data={"hosts": ["www.example.com"]}),
    )
    second = MockCapability(
        "probe",
        result=Result(status=Status.SUCCESS, data=["www.example.com"]),
    )

    pipeline = Pipeline()
    pipeline.add(first)
    pipeline.add(second)

    result = pipeline.run("example.com")

    assert result.status == Status.SUCCESS
    assert result.executed_capabilities == ("discover", "probe")
    assert result.execution_order == ("discover", "probe")
    assert result.last_result == Result(status=Status.SUCCESS, data=["www.example.com"])
    assert result.context.target_id == "example.com"
    assert result.context.state["discover"] == {"hosts": ["www.example.com"]}
    assert result.context.state["probe"] == ["www.example.com"]
    assert first.execute_calls[0] is second.execute_calls[0]


def test_empty_pipeline() -> None:
    """Test running a pipeline with no registered capabilities."""
    pipeline = Pipeline()

    result = pipeline.run(Target(identifier="example.com"))

    assert result.status == Status.SUCCESS
    assert result.executed_capabilities == ()
    assert result.execution_order == ()
    assert result.last_result is None
    assert result.context.target_id == "example.com"
    assert result.context.state == {}


def test_capability_failure_fail_fast() -> None:
    """Test that pipeline stops immediately when a capability returns ERROR."""
    first = MockCapability(
        "discover",
        result=Result(status=Status.SUCCESS, data={"hosts": ["www.example.com"]}),
    )
    second = MockCapability(
        "probe",
        result=Result(status=Status.ERROR, data=[], errors=["probe failed"]),
    )
    third = MockCapability(
        "skipped",
        result=Result(status=Status.SUCCESS, data={"ignored": True}),
    )

    pipeline = Pipeline()
    pipeline.add(first)
    pipeline.add(second)
    pipeline.add(third)

    result = pipeline.run("example.com")

    assert result.status == Status.ERROR
    assert result.executed_capabilities == ("discover", "probe")
    assert result.execution_order == ("discover", "probe", "skipped")
    assert result.last_result == Result(status=Status.ERROR, data=[], errors=["probe failed"])
    assert third.execute_calls == []
    assert result.context.state["probe"] == []


def test_state_propagation() -> None:
    """Test that each capability output is stored in shared pipeline state."""
    first = MockCapability(
        "discover",
        result=Result(status=Status.SUCCESS, data={"items": ["a.example.com"]}),
    )
    second = MockCapability(
        "enrich",
        result=Result(status=Status.SUCCESS, data={"items": ["alive"]}),
    )

    pipeline = Pipeline()
    pipeline.add(first)
    pipeline.add(second)

    result = pipeline.run("example.com")

    assert result.context.state["discover"] == {"items": ["a.example.com"]}
    assert result.context.state["enrich"] == {"items": ["alive"]}
    assert second.execute_calls[0].state["discover"] == {"items": ["a.example.com"]}


def test_execution_order() -> None:
    """Test that capabilities execute in registration order."""
    calls: list[str] = []

    class RecordingCapability(Capability):
        def __init__(self, capability_name: str) -> None:
            self._name = capability_name

        def execute(self, context: Context) -> Result[dict[str, str]]:  # noqa: ARG002
            calls.append(self._name)
            return Result(status=Status.SUCCESS, data={"name": self._name})

        @property
        def name(self) -> str:
            return self._name

    pipeline = Pipeline()
    pipeline.add(RecordingCapability("first"))
    pipeline.add(RecordingCapability("second"))
    pipeline.add(RecordingCapability("third"))

    result = pipeline.run("example.com")

    assert calls == ["first", "second", "third"]
    assert result.execution_order == ("first", "second", "third")
    assert result.executed_capabilities == ("first", "second", "third")


def test_pipeline_result_fields() -> None:
    """Test that PipelineResult contains expected execution metadata."""
    capability = MockCapability(
        "discover",
        result=Result(status=Status.SUCCESS, data={"count": 1}),
    )

    pipeline = Pipeline()
    pipeline.add(capability)

    result = pipeline.run("example.com")

    assert isinstance(result, PipelineResult)
    assert result.status == Status.SUCCESS
    assert result.executed_capabilities == ("discover",)
    assert result.execution_order == ("discover",)
    assert result.last_result == Result(status=Status.SUCCESS, data={"count": 1})
    assert result.context.target_id == "example.com"


def test_known_capability_output_keys() -> None:
    """Test centralized output keys for built-in capabilities."""
    subdomain = MockCapability(
        "subdomain_discovery",
        result=Result(status=Status.SUCCESS, data={"subdomains": ["www.example.com"]}),
    )
    http_probe = MockCapability(
        "http_probe",
        result=Result(status=Status.SUCCESS, data=["www.example.com"]),
    )
    technology_detection = MockCapability(
        "technology_detection",
        result=Result(status=Status.SUCCESS, data=["nginx"]),
    )
    asset_intelligence = MockCapability(
        "asset_intelligence",
        result=Result(status=Status.SUCCESS, data={"assets": ["example.com"]}),
    )

    pipeline = Pipeline()
    pipeline.add(subdomain)
    pipeline.add(http_probe)
    pipeline.add(technology_detection)
    pipeline.add(asset_intelligence)

    result = pipeline.run("example.com")

    assert PipelineStateKey.SUBDOMAINS in result.context.state
    assert PipelineStateKey.ALIVE_HOSTS in result.context.state
    assert result.context.state[PipelineStateKey.SUBDOMAINS] == {
        "subdomains": ["www.example.com"]
    }
    assert result.context.state[PipelineStateKey.ALIVE_HOSTS] == ["www.example.com"]
    assert result.context.state[PipelineStateKey.TECHNOLOGIES] == ["nginx"]
    assert result.context.state[PipelineStateKey.ASSET_INTELLIGENCE] == {
        "assets": ["example.com"]
    }
