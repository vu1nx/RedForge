"""Concrete static readiness probes for adapter composition."""

from typing import cast

from redforge.doctor import (
    ToolVersionProbeResult,
    ToolVersionProbeStatus,
)
from redforge.sdk.readiness import (
    ReadinessProbeResult,
    ReadinessReason,
    ReadinessStatus,
)
from redforge.sdk.tool import (
    ToolDefinition,
    ToolExecutableResolutionStatus,
    ToolExecutableResolver,
    ToolRunner,
)


class ToolRunnerReadinessProbe:
    """Use the runner's static resolution boundary without executing a tool."""

    def __init__(self, runner: ToolRunner) -> None:
        if not callable(
            getattr(cast(object, runner), "is_available", None)
        ):
            raise TypeError("tool readiness requires a ToolRunner")
        self._runner = runner

    @property
    def runner(self) -> ToolRunner:
        """Return the explicitly composed runner port."""
        return self._runner

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


class ToolRunnerVersionProbe:
    """Map target-free executable identity resolution to Doctor evidence."""

    def __init__(self, resolver: ToolExecutableResolver) -> None:
        if not callable(getattr(cast(object, resolver), "resolve", None)):
            raise TypeError("tool version probe requires a resolver")
        self._resolver = resolver

    def probe(self, definition: ToolDefinition) -> ToolVersionProbeResult:
        """Resolve identity metadata without target or scan arguments."""
        if not isinstance(cast(object, definition), ToolDefinition):
            raise TypeError("tool version probe requires a ToolDefinition")
        try:
            result = self._resolver.resolve(definition)
        except Exception:
            return ToolVersionProbeResult(ToolVersionProbeStatus.ERROR)
        if result.status is ToolExecutableResolutionStatus.RESOLVED:
            if result.version is None:
                return ToolVersionProbeResult(
                    ToolVersionProbeStatus.UNAVAILABLE
                )
            return ToolVersionProbeResult(
                ToolVersionProbeStatus.DETECTED,
                result.version,
            )
        status = {
            ToolExecutableResolutionStatus.UNAVAILABLE: (
                ToolVersionProbeStatus.UNAVAILABLE
            ),
            ToolExecutableResolutionStatus.INCOMPATIBLE: (
                ToolVersionProbeStatus.INCOMPATIBLE
            ),
            ToolExecutableResolutionStatus.ERROR: (
                ToolVersionProbeStatus.ERROR
            ),
        }[result.status]
        return ToolVersionProbeResult(status)
