"""Static and identity-aware readiness adapter tests without real tools."""

from redforge.adapters import ToolRunnerReadinessProbe, ToolRunnerVersionProbe
from redforge.application import ReadinessReason, ReadinessStatus
from redforge.doctor import ToolVersionProbeStatus
from redforge.sdk import (
    ToolDefinition,
    ToolExecutableResolution,
    ToolExecutableResolutionStatus,
    ToolExecutionResult,
    ToolId,
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


class _Resolver:
    def __init__(self, result: ToolExecutableResolution) -> None:
        self.result = result

    def resolve(
        self,
        definition: ToolDefinition,  # noqa: ARG002
    ) -> ToolExecutableResolution:
        return self.result


def test_version_probe_maps_resolved_identity_and_sanitized_version() -> None:
    probe = ToolRunnerVersionProbe(
        _Resolver(
            ToolExecutableResolution(
                ToolId("offline_tool"),
                ToolExecutableResolutionStatus.RESOLVED,
                executable_candidate="offline-tool",
                version="v1.9.0",
            )
        )
    )

    result = probe.probe(_definition())

    assert result.status is ToolVersionProbeStatus.DETECTED
    assert result.version == "v1.9.0"


def test_version_probe_distinguishes_identity_outcomes() -> None:
    expected = (
        (
            ToolExecutableResolutionStatus.UNAVAILABLE,
            ToolVersionProbeStatus.UNAVAILABLE,
        ),
        (
            ToolExecutableResolutionStatus.INCOMPATIBLE,
            ToolVersionProbeStatus.INCOMPATIBLE,
        ),
        (
            ToolExecutableResolutionStatus.ERROR,
            ToolVersionProbeStatus.ERROR,
        ),
    )

    for resolution_status, version_status in expected:
        result = ToolRunnerVersionProbe(
            _Resolver(
                ToolExecutableResolution(
                    ToolId("offline_tool"),
                    resolution_status,
                )
            )
        ).probe(_definition())

        assert result.status is version_status
        assert result.version is None
