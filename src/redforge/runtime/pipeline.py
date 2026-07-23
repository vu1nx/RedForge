"""Sequential pipeline for capability execution."""

from dataclasses import dataclass
from typing import Any

from redforge.domain.target import Target
from redforge.runtime.pipeline_state import CAPABILITY_OUTPUT_KEYS
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


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


class Pipeline:
    """Lightweight sequential orchestrator for capability execution.

    Capabilities are executed in registration order. Each capability receives
    the same Context instance, and successful output is stored in Context.state
    for downstream capabilities.
    """

    def __init__(self) -> None:
        """Initialize an empty pipeline."""
        self._capabilities: list[Capability] = []

    def add(self, capability: Capability) -> None:
        """Register a capability for sequential execution.

        Args:
            capability: Capability instance to append to the pipeline.
        """
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
            )

        executed: list[str] = []
        last_result: Result[Any] | None = None

        for capability in self._capabilities:
            result = capability.execute(context)
            last_result = result
            executed.append(capability.name)

            state_key = CAPABILITY_OUTPUT_KEYS.get(capability.name, capability.name)
            state[state_key] = result.data

            if result.status == Status.ERROR:
                return PipelineResult(
                    status=Status.ERROR,
                    executed_capabilities=tuple(executed),
                    context=context,
                    last_result=last_result,
                    execution_order=execution_order,
                )

        return PipelineResult(
            status=Status.SUCCESS,
            executed_capabilities=tuple(executed),
            context=context,
            last_result=last_result,
            execution_order=execution_order,
        )
