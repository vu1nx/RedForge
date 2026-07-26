"""High-level planning, building, and existing-runtime execution facade."""

from collections.abc import Iterable
from typing import cast

from redforge.planning.builder import PipelineBuilder
from redforge.planning.default_registry import create_default_registry
from redforge.planning.errors import InvalidPlanningInputError
from redforge.planning.factories import (
    CapabilityDependencies,
    create_default_factory_registry,
)
from redforge.planning.models import ExecutionPlan, state_keys
from redforge.planning.planner import ExecutionPlanner
from redforge.runtime.execution_policy import ExecutionPolicy
from redforge.runtime.pipeline import Pipeline, PipelineResult
from redforge.sdk.context import Context


class PlannedExecution:
    """Coordinate pure planning and building while delegating execution to Pipeline."""

    def __init__(
        self,
        *,
        planner: ExecutionPlanner,
        builder: PipelineBuilder,
    ) -> None:
        if not isinstance(cast(object, planner), ExecutionPlanner):
            raise TypeError("PlannedExecution requires an ExecutionPlanner")
        if not isinstance(cast(object, builder), PipelineBuilder):
            raise TypeError("PlannedExecution requires a PipelineBuilder")
        self._planner = planner
        self._builder = builder

    def plan(
        self, *, goals: Iterable[str], context: Context
    ) -> ExecutionPlan:
        """Plan goals from canonical state keys actually present in context."""
        context_value = cast(object, context)
        if not isinstance(context_value, Context):
            raise TypeError("PlannedExecution requires a Context")
        canonical = set(state_keys())
        available = tuple(
            key for key in context.available_state_keys() if key in canonical
        )
        return self._planner.plan(goals=goals, available_state=available)

    def build(self, plan: ExecutionPlan) -> Pipeline:
        """Build but do not execute a fresh pipeline for an inspectable plan."""
        return self._builder.build(plan)

    def execute(
        self,
        *,
        plan: ExecutionPlan,
        context: Context,
        policy: ExecutionPolicy | None = None,
    ) -> PipelineResult:
        """Build and execute a plan through the existing Pipeline runtime."""
        if type(cast(object, plan)) is not ExecutionPlan:
            raise InvalidPlanningInputError(
                "PlannedExecution requires an immutable ExecutionPlan"
            )
        context_value = cast(object, context)
        if not isinstance(context_value, Context):
            raise TypeError("PlannedExecution requires a Context")
        if not set(plan.available_state).issubset(context.state):
            raise InvalidPlanningInputError(
                "execution context is missing plan-available state"
            )
        pipeline = self.build(plan)
        if policy is None:
            return pipeline.run(context)
        return pipeline.run(context, policy=policy)

    def run(
        self,
        *,
        goals: Iterable[str],
        initial_context: Context,
        policy: ExecutionPolicy | None = None,
    ) -> PipelineResult:
        """Plan, build, and execute one isolated run."""
        plan = self.plan(goals=goals, context=initial_context)
        return self.execute(
            plan=plan,
            context=initial_context,
            policy=policy,
        )


def create_default_planned_execution(
    *,
    dependencies: CapabilityDependencies | None = None,
) -> PlannedExecution:
    """Construct the default integration graph without performing external I/O."""
    descriptors = create_default_registry()
    planner = ExecutionPlanner(descriptors)
    factories = create_default_factory_registry(dependencies=dependencies)
    builder = PipelineBuilder(
        descriptor_registry=descriptors,
        factory_registry=factories,
    )
    return PlannedExecution(planner=planner, builder=builder)
