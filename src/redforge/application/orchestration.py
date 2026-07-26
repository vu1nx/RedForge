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
    )

    def __init__(
        self,
        *,
        capability_registry: CapabilityRegistry,
        factory_registry: CapabilityFactoryRegistry,
        clock: MonotonicClock | None = None,
        readiness_registry: ReadinessRegistry | None = None,
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

    def run(self, config: ScanConfig) -> ScanResult:
        """Prepare and execute one isolated scan through the existing runtime."""
        prepared: PreparedScan = prepare_scan(
            config=config,
            registry=self._capability_registry,
        )
        preflight = self._preflight.run(
            prepared_scan=prepared,
            factory_registry=self._factory_registry,
        )
        if not preflight.ready:
            raise ScanPreflightError(preflight)
        planned_execution = PlannedExecution(
            planner=ExecutionPlanner(self._capability_registry),
            builder=PipelineBuilder(
                descriptor_registry=self._capability_registry,
                factory_registry=self._factory_registry,
            ),
        )
        policy = create_scan_limit_policy(
            config.limits,
            clock=self._clock,
        )
        context = create_initial_context(config)
        pipeline_result = planned_execution.execute(
            plan=prepared.plan,
            context=context,
            policy=policy,
        )
        accepted = is_scan_result_accepted(
            pipeline_result.status,
            allow_partial_results=config.allow_partial_results,
        )
        return ScanResult(
            config=config,
            plan=prepared.plan,
            preflight=preflight,
            pipeline_result=pipeline_result,
            accepted=accepted,
        )
