"""Provider-neutral one-shot application scan orchestration."""

from dataclasses import dataclass, field
from typing import cast

from redforge.application.preflight import (
    PreflightResult,
    ReadinessRegistry,
    ScanPreflight,
    ScanPreflightError,
)
from redforge.application.scan_config import (
    PreparedScan,
    ScanConfig,
    create_initial_context,
    prepare_scan,
)
from redforge.application.scan_limits import create_scan_limit_policy
from redforge.observability import (
    DiagnosticEvent,
    DiagnosticEventSink,
    DiagnosticEventType,
    DiagnosticFields,
    DiagnosticSeverity,
    NullDiagnosticEventSink,
    emit_safely,
)
from redforge.planning.builder import PipelineBuilder
from redforge.planning.execution import PlannedExecution
from redforge.planning.factories import CapabilityFactoryRegistry
from redforge.planning.models import ExecutionPlan
from redforge.planning.planner import ExecutionPlanner
from redforge.planning.registry import CapabilityRegistry
from redforge.runtime.execution_policy import (
    ExecutionPolicyViolation,
    MonotonicClock,
    SystemMonotonicClock,
)
from redforge.runtime.pipeline import (
    CapabilityExecution,
    PipelineResult,
)
from redforge.sdk.context import Context
from redforge.sdk.readiness import ReadinessStatus
from redforge.sdk.result import Status


def is_scan_result_accepted(
    status: Status,
    *,
    allow_partial_results: bool,
) -> bool:
    """Evaluate application acceptance without changing runtime status."""
    if not isinstance(cast(object, status), Status):
        raise TypeError("scan acceptance requires a runtime Status")
    if not isinstance(cast(object, allow_partial_results), bool):
        raise TypeError("partial-result policy must be boolean")
    return status is Status.SUCCESS or (
        status is Status.PARTIAL and allow_partial_results
    )


@dataclass(frozen=True, slots=True, repr=False)
class ScanResult:
    """Immutable application outcome preserving the complete runtime result."""

    config: ScanConfig = field(repr=False)
    plan: ExecutionPlan = field(repr=False)
    preflight: PreflightResult = field(repr=False)
    pipeline_result: PipelineResult = field(repr=False)
    accepted: bool

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.config), ScanConfig):
            raise TypeError("scan result config is invalid")
        if not isinstance(cast(object, self.plan), ExecutionPlan):
            raise TypeError("scan result plan is invalid")
        if not isinstance(cast(object, self.preflight), PreflightResult):
            raise TypeError("scan result preflight is invalid")
        if not self.preflight.ready:
            raise ValueError("scan result requires a ready preflight")
        if not isinstance(cast(object, self.pipeline_result), PipelineResult):
            raise TypeError("scan runtime result is invalid")
        if not isinstance(cast(object, self.accepted), bool):
            raise TypeError("scan acceptance is invalid")

    @property
    def final_context(self) -> Context:
        """Return the runtime's final Context without copying state."""
        return self.pipeline_result.context

    @property
    def runtime_status(self) -> Status:
        """Return the unmodified aggregate runtime status."""
        return self.pipeline_result.status

    @property
    def execution_history(self) -> tuple[CapabilityExecution, ...]:
        """Return immutable capability execution history."""
        return self.pipeline_result.executions

    @property
    def policy_violation(self) -> ExecutionPolicyViolation | None:
        """Return the terminal typed limit/deadline violation, when present."""
        if not self.execution_history:
            return None
        return self.execution_history[-1].policy_violation

    def __repr__(self) -> str:
        """Return a concise representation without target or runtime evidence."""
        return (
            "ScanResult("
            f"runtime_status={self.runtime_status!r}, "
            f"accepted={self.accepted!r}, "
            f"planned_steps={len(self.plan.steps)}"
            ")"
        )


class ScanOrchestrator:
    """Stateless application service for one prepared, built, and executed scan."""

    __slots__ = (
        "_capability_registry",
        "_clock",
        "_factory_registry",
        "_preflight",
        "_sink",
    )

    def __init__(
        self,
        *,
        capability_registry: CapabilityRegistry,
        factory_registry: CapabilityFactoryRegistry,
        clock: MonotonicClock | None = None,
        readiness_registry: ReadinessRegistry | None = None,
        diagnostic_sink: DiagnosticEventSink | None = None,
    ) -> None:
        if not isinstance(
            cast(object, capability_registry), CapabilityRegistry
        ):
            raise TypeError("ScanOrchestrator requires a CapabilityRegistry")
        if not isinstance(
            cast(object, factory_registry), CapabilityFactoryRegistry
        ):
            raise TypeError(
                "ScanOrchestrator requires a CapabilityFactoryRegistry"
            )
        self._capability_registry = capability_registry
        self._factory_registry = factory_registry
        self._clock = (
            clock if clock is not None else SystemMonotonicClock()
        )
        self._preflight = ScanPreflight(readiness_registry)
        self._sink = (
            diagnostic_sink
            if diagnostic_sink is not None
            else NullDiagnosticEventSink()
        )

    def run(self, config: ScanConfig) -> ScanResult:
        """Prepare and execute one isolated scan through the existing runtime."""
        self._emit(
            DiagnosticEventType.SCAN_PREPARATION_STARTED,
            DiagnosticSeverity.INFO,
            "Scan preparation started",
        )
        prepared: PreparedScan = prepare_scan(
            config=config,
            registry=self._capability_registry,
        )
        self._emit(
            DiagnosticEventType.SCAN_PREPARATION_COMPLETED,
            DiagnosticSeverity.INFO,
            "Scan preparation completed",
            DiagnosticFields(planned_steps=len(prepared.plan.steps)),
        )
        self._emit(
            DiagnosticEventType.SCAN_PREFLIGHT_STARTED,
            DiagnosticSeverity.INFO,
            "Scan preflight started",
        )
        preflight = self._preflight.run(
            prepared_scan=prepared,
            factory_registry=self._factory_registry,
        )
        checks_failed = sum(
            check.status is not ReadinessStatus.READY
            for check in preflight.checks
        )
        if not preflight.ready:
            self._emit(
                DiagnosticEventType.SCAN_PREFLIGHT_FAILED,
                DiagnosticSeverity.WARNING,
                "Scan preflight failed",
                DiagnosticFields(
                    ready=False,
                    preflight_checks_total=len(preflight.checks),
                    preflight_checks_failed=checks_failed,
                ),
            )
            raise ScanPreflightError(preflight)
        self._emit(
            DiagnosticEventType.SCAN_PREFLIGHT_COMPLETED,
            DiagnosticSeverity.INFO,
            "Scan preflight completed",
            DiagnosticFields(
                ready=True,
                preflight_checks_total=len(preflight.checks),
                preflight_checks_failed=checks_failed,
            ),
        )
        planned_execution = PlannedExecution(
            planner=ExecutionPlanner(self._capability_registry),
            builder=PipelineBuilder(
                descriptor_registry=self._capability_registry,
                factory_registry=self._factory_registry,
            ),
        )
        self._emit(
            DiagnosticEventType.SCAN_BUILD_STARTED,
            DiagnosticSeverity.INFO,
            "Scan build started",
        )
        pipeline = planned_execution.build(prepared.plan)
        self._emit(
            DiagnosticEventType.SCAN_BUILD_COMPLETED,
            DiagnosticSeverity.INFO,
            "Scan build completed",
            DiagnosticFields(planned_steps=len(prepared.plan.steps)),
        )
        policy = create_scan_limit_policy(
            config.limits,
            clock=self._clock,
        )
        context = create_initial_context(config)
        self._emit(
            DiagnosticEventType.SCAN_EXECUTION_STARTED,
            DiagnosticSeverity.INFO,
            "Scan execution started",
        )
        pipeline_result = pipeline.run(
            context,
            policy=policy,
            diagnostic_sink=self._sink,
        )
        self._emit(
            DiagnosticEventType.SCAN_EXECUTION_COMPLETED,
            DiagnosticSeverity.INFO,
            "Scan execution completed",
            DiagnosticFields(
                runtime_status=pipeline_result.status.name,
                history_count=len(pipeline_result.executions),
            ),
        )
        accepted = is_scan_result_accepted(
            pipeline_result.status,
            allow_partial_results=config.allow_partial_results,
        )
        result = ScanResult(
            config=config,
            plan=prepared.plan,
            preflight=preflight,
            pipeline_result=pipeline_result,
            accepted=accepted,
        )
        self._emit(
            DiagnosticEventType.SCAN_RESULT_CREATED,
            DiagnosticSeverity.INFO,
            "Scan result created",
            DiagnosticFields(
                runtime_status=result.runtime_status.name,
                accepted=result.accepted,
                history_count=len(result.execution_history),
            ),
        )
        return result

    def _emit(
        self,
        event_type: DiagnosticEventType,
        severity: DiagnosticSeverity,
        message: str,
        fields: DiagnosticFields | None = None,
    ) -> None:
        emit_safely(
            self._sink,
            DiagnosticEvent(
                event_type=event_type,
                severity=severity,
                message=message,
                fields=fields or DiagnosticFields(),
            ),
        )
