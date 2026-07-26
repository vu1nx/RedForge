"""Concrete static readiness probes for adapter composition."""

from typing import cast

from redforge.sdk.readiness import (
    ReadinessProbeResult,
    ReadinessReason,
    ReadinessStatus,
)
from redforge.sdk.tool import ToolDefinition, ToolRunner


class ToolRunnerReadinessProbe:
    """Use the runner's static resolution boundary without executing a tool."""

    def __init__(self, runner: ToolRunner) -> None:
        if not callable(
            getattr(cast(object, runner), "is_available", None)
        ):
            raise TypeError("tool readiness requires a ToolRunner")
        self._runner = runner

    def check(self, definition: ToolDefinition) -> ReadinessProbeResult:
        """Map static executable resolution to a sanitized readiness result."""
        if not isinstance(cast(object, definition), ToolDefinition):
            raise TypeError("tool readiness requires a ToolDefinition")
        try:
            available = self._runner.is_available(definition)
        except OSError:
            return ReadinessProbeResult(
                status=ReadinessStatus.ERROR,
                reason=ReadinessReason.PROBE_FAILED,
            )
        if available:
            return ReadinessProbeResult(status=ReadinessStatus.READY)
        return ReadinessProbeResult(
            status=ReadinessStatus.UNAVAILABLE,
            reason=ReadinessReason.EXECUTABLE_UNAVAILABLE,
        )
