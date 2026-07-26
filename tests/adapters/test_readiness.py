"""Static tool readiness adapter tests without process execution."""

from redforge.adapters import ToolRunnerReadinessProbe
from redforge.application import ReadinessReason, ReadinessStatus
from redforge.sdk import (
    ToolDefinition,
    ToolExecutionResult,
    ToolInvocation,
)


class StaticRunner:
    def __init__(self, available: bool) -> None:
        self.available = available
        self.availability_calls = 0
        self.run_calls = 0

    def is_available(self, definition: ToolDefinition) -> bool:  # noqa: ARG002
        self.availability_calls += 1
        return self.available

    def run(
        self,
        definition: ToolDefinition,  # noqa: ARG002
        invocation: ToolInvocation,  # noqa: ARG002
    ) -> ToolExecutionResult:
        self.run_calls += 1
        raise AssertionError("readiness must not execute a tool")


def _definition() -> ToolDefinition:
    return ToolDefinition(
        tool_id="offline_tool",
        display_name="Offline Tool",
        description="Test-only static readiness definition.",
        executable="offline-tool",
    )


def test_tool_runner_readiness_uses_only_static_availability() -> None:
    runner = StaticRunner(available=True)

    outcome = ToolRunnerReadinessProbe(runner).check(
        _definition()
    )

    assert outcome.status is ReadinessStatus.READY
    assert runner.availability_calls == 1
    assert runner.run_calls == 0


def test_tool_runner_readiness_maps_missing_executable() -> None:
    runner = StaticRunner(available=False)

    outcome = ToolRunnerReadinessProbe(runner).check(
        _definition()
    )

    assert outcome.status is ReadinessStatus.UNAVAILABLE
    assert outcome.reason is ReadinessReason.EXECUTABLE_UNAVAILABLE
    assert runner.run_calls == 0
