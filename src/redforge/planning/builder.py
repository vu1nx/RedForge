"""Defensive translation of typed execution plans into runtime pipelines."""

from typing import cast

from redforge.planning.errors import (
    CapabilityDescriptorMismatchError,
    InvalidPlanningInputError,
    MissingCapabilityFactoryError,
    UnknownCapabilityError,
)
from redforge.planning.factories import CapabilityFactoryRegistry
from redforge.planning.models import ExecutionPlan, ExecutionStep
from redforge.planning.registry import CapabilityRegistry
from redforge.runtime.pipeline import Pipeline
from redforge.sdk.capability_id import CapabilityId
from redforge.sdk.state import PipelineStateKey


class PipelineBuilder:
    """Build fresh pipelines from canonical typed plan steps."""

    def __init__(
        self,
        *,
        descriptor_registry: CapabilityRegistry,
        factory_registry: CapabilityFactoryRegistry,
    ) -> None:
        if not isinstance(cast(object, descriptor_registry), CapabilityRegistry):
            raise TypeError("PipelineBuilder requires a CapabilityRegistry")
        if not isinstance(
            cast(object, factory_registry), CapabilityFactoryRegistry
        ):
            raise TypeError("PipelineBuilder requires a CapabilityFactoryRegistry")
        factory_registry.validate_against(descriptor_registry)
        self._definitions = descriptor_registry
        self._factories = factory_registry

    def build(self, plan: ExecutionPlan) -> Pipeline:
        """Validate a plan and construct a fresh, unexecuted Pipeline."""
        steps, output_contracts = self._validate(plan)
        missing = next(
            (
                step.capability_id
                for step in steps
                if not self._factories.has(step.capability_id)
            ),
            None,
        )
        if missing is not None:
            raise MissingCapabilityFactoryError(missing.value)

        capabilities = tuple(
            self._factories.create(step.capability_id) for step in steps
        )
        pipeline = Pipeline(output_contracts=output_contracts)
        for step, capability in zip(steps, capabilities, strict=True):
            pipeline.add(capability, capability_id=step.capability_id)
        return pipeline

    def _validate(
        self, plan: ExecutionPlan
    ) -> tuple[
        tuple[ExecutionStep, ...],
        dict[CapabilityId, tuple[PipelineStateKey, ...]],
    ]:
        if type(cast(object, plan)) is not ExecutionPlan:
            raise InvalidPlanningInputError(
                "PipelineBuilder requires an immutable ExecutionPlan"
            )
        goals = cast(object, plan.goals)
        available_state = cast(object, plan.available_state)
        steps_value = cast(object, plan.steps)
        if not all(
            isinstance(value, tuple)
            for value in (goals, available_state, steps_value)
        ):
            raise InvalidPlanningInputError("execution plan must remain immutable")
        ExecutionPlan(
            goals=plan.goals,
            available_state=plan.available_state,
            steps=plan.steps,
        )

        expected_positions = tuple(range(len(plan.steps)))
        if tuple(step.position for step in plan.steps) != expected_positions:
            raise InvalidPlanningInputError(
                "step positions must be contiguous from zero"
            )
        capability_ids = tuple(step.capability_id for step in plan.steps)
        if len(capability_ids) != len(set(capability_ids)):
            raise InvalidPlanningInputError(
                "execution plan contains duplicate capabilities"
            )

        available = set(plan.available_state)
        output_contracts: dict[
            CapabilityId, tuple[PipelineStateKey, ...]
        ] = {}
        for step in plan.steps:
            try:
                definition = self._definitions.require(step.capability_id)
            except UnknownCapabilityError:
                raise CapabilityDescriptorMismatchError(
                    step.capability_name, "planning definition"
                ) from None
            if (
                step.requires != definition.requires
                or step.provides != definition.provides
            ):
                raise CapabilityDescriptorMismatchError(
                    step.capability_name, "execution-step definition"
                )
            if not set(definition.requires).issubset(available):
                raise CapabilityDescriptorMismatchError(
                    step.capability_name, "dependency order"
                )
            output_contracts[step.capability_id] = definition.provides
            available.update(definition.provides)

        if not set(plan.goals).issubset(available):
            raise InvalidPlanningInputError(
                "execution plan does not satisfy every goal"
            )
        return plan.steps, output_contracts
