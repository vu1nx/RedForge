"""Sequential pipeline for capability execution."""

from dataclasses import dataclass
from typing import Any, TypeGuard, cast

from redforge.domain.target import Target
from redforge.runtime.pipeline_state import CAPABILITY_OUTPUT_KEYS
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status

_STATUS_PRECEDENCE: dict[Status, int] = {
    Status.SUCCESS: 0,
    Status.PARTIAL: 1,
    Status.FAILURE: 2,
    Status.ERROR: 3,
}


def combine_status(current: Status, observed: Status) -> Status:
    """Return the more severe of two capability outcomes."""
    return (
        current
        if _STATUS_PRECEDENCE[current] >= _STATUS_PRECEDENCE[observed]
        else observed
    )


def _is_valid_result(value: object) -> TypeGuard[Result[Any]]:
    """Return whether a capability value satisfies the runtime Result contract."""
    return isinstance(value, Result) and isinstance(
        cast(object, value.status), Status
    )


@dataclass(frozen=True, slots=True)
class CapabilityExecution:
    """One capability result preserved in pipeline execution order."""

    capability_name: str
    """Stable registered capability name."""

    result: Result[Any]
    """Original capability result, including diagnostics and metadata."""


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Immutable result of a pipeline execution."""

    status: Status
    """Final status of the pipeline execution."""

    executed_capabilities: tuple[str, ...]
    """Names of capabilities that were executed."""

    context: Context
    """Final context after pipeline execution."""

    last_result: Result[Any] | None
    """Result from the last executed capability."""

    execution_order: tuple[str, ...]
    """Registered capability execution order."""

    executions: tuple[CapabilityExecution, ...]
    """Immutable history containing one entry per executed capability."""


class Pipeline:
    """Lightweight sequential orchestrator for capability execution.

    Capabilities are executed in registration order. Each capability receives
    the same Context instance, and usable SUCCESS or PARTIAL output is stored in
    Context.state for downstream capabilities.
    """

    def __init__(self) -> None:
        """Initialize an empty pipeline."""
        self._capabilities: list[Capability] = []

    def add(self, capability: Capability) -> None:
        """Register a capability for sequential execution.

        Args:
            capability: Capability instance to append to the pipeline.
        """
        if any(item.name == capability.name for item in self._capabilities):
            raise ValueError(f"duplicate capability name: '{capability.name}'")
        self._capabilities.append(capability)

    def run(self, target: Target | str) -> PipelineResult:
        """Execute registered capabilities sequentially.

        Args:
            target: Target identifier or Target domain object.

        Returns:
            PipelineResult containing final status, context, and execution details.
        """
        target_id = target.identifier if isinstance(target, Target) else target
        state: dict[str, Any] = {}
        context = Context(target_id=target_id, state=state)
        execution_order = tuple(capability.name for capability in self._capabilities)

        if not self._capabilities:
            return PipelineResult(
                status=Status.SUCCESS,
                executed_capabilities=(),
                context=context,
                last_result=None,
                execution_order=execution_order,
                executions=(),
            )

        executions: list[CapabilityExecution] = []
        last_result: Result[Any] | None = None
        aggregate_status = Status.SUCCESS

        for capability in self._capabilities:
            try:
                candidate = cast(object, capability.execute(context))
            except Exception:
                result: Result[Any] = Result(
                    status=Status.ERROR,
                    data=None,
                    errors=[
                        f"Capability '{capability.name}' failed with an "
                        "unexpected execution error"
                    ],
                    metadata={"error_kind": "unexpected_execution_error"},
                )
            else:
                if _is_valid_result(candidate):
                    result = candidate
                else:
                    result = Result(
                        status=Status.ERROR,
                        data=None,
                        errors=[
                            f"Capability '{capability.name}' returned an invalid result"
                        ],
                        metadata={"error_kind": "invalid_capability_result"},
                    )

            last_result = result
            executions.append(
                CapabilityExecution(
                    capability_name=capability.name,
                    result=result,
                )
            )
            aggregate_status = combine_status(aggregate_status, result.status)

            if result.status in {Status.SUCCESS, Status.PARTIAL}:
                state_key = CAPABILITY_OUTPUT_KEYS.get(
                    capability.name, capability.name
                )
                state[state_key] = result.data

            if result.status in {Status.FAILURE, Status.ERROR}:
                break

        return PipelineResult(
            status=aggregate_status,
            executed_capabilities=tuple(
                execution.capability_name for execution in executions
            ),
            context=context,
            last_result=last_result,
            execution_order=execution_order,
            executions=tuple(executions),
        )
