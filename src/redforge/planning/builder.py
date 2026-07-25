"""Defensive translation of immutable execution plans into runtime pipelines."""

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
from redforge.runtime.pipeline_state import CAPABILITY_OUTPUT_CONTRACTS
from redforge.sdk.state import PipelineStateKey


class PipelineBuilder:
    """Build fresh pipelines from canonical plan steps without executing them."""

    def __init__(
        self,
        *,
        descriptor_registry: CapabilityRegistry,
        factory_registry: CapabilityFactoryRegistry,
    ) -> None:
        if not isinstance(cast(object, descriptor_registry), CapabilityRegistry):
            raise TypeError("PipelineBuilder requires a CapabilityRegistry")
        if not isinstance(cast(object, factory_registry), CapabilityFactoryRegistry):
            raise TypeError("PipelineBuilder requires a CapabilityFactoryRegistry")
        self._descriptors = descriptor_registry
        self._factories = factory_registry

    def build(self, plan: ExecutionPlan) -> Pipeline:
        """Validate a plan and construct a fresh, unexecuted Pipeline."""
        steps, output_contracts = self._validate(plan)
        missing = next(
            (
                step.capability_name
                for step in steps
                if not self._factories.has(step.capability_name)
            ),
            None,
        )
        if missing is not None:
            raise MissingCapabilityFactoryError(missing)

        capabilities = tuple(self._factories.create(step.capability_name) for step in steps)
        pipeline = Pipeline(output_contracts=output_contracts)
        for capability in capabilities:
            pipeline.add(capability)
        return pipeline

    def _validate(
        self, plan: ExecutionPlan
    ) -> tuple[
        tuple[ExecutionStep, ...],
        dict[str, tuple[PipelineStateKey, ...]],
    ]:
        if type(cast(object, plan)) is not ExecutionPlan:
            raise InvalidPlanningInputError("PipelineBuilder requires an immutable ExecutionPlan")
        goals = cast(object, plan.goals)
        available_state = cast(object, plan.available_state)
        steps_value = cast(object, plan.steps)
        if not all(isinstance(value, tuple) for value in (goals, available_state, steps_value)):
            raise InvalidPlanningInputError("execution plan must remain immutable")
        ExecutionPlan(
            goals=plan.goals,
            available_state=plan.available_state,
            steps=plan.steps,
        )

        expected_positions = tuple(range(len(plan.steps)))
        if tuple(step.position for step in plan.steps) != expected_positions:
            raise InvalidPlanningInputError("step positions must be contiguous from zero")
        names = tuple(step.capability_name for step in plan.steps)
        if len(names) != len(set(names)):
            raise InvalidPlanningInputError("execution plan contains duplicate capabilities")

        available = set(plan.available_state)
        output_contracts: dict[str, tuple[PipelineStateKey, ...]] = {}
        for step in plan.steps:
            try:
                descriptor = self._descriptors.get(step.capability_name)
            except UnknownCapabilityError:
                raise CapabilityDescriptorMismatchError(
                    step.capability_name, "planning descriptor"
                ) from None
            if step.requires != descriptor.requires or step.provides != descriptor.provides:
                raise CapabilityDescriptorMismatchError(
                    step.capability_name, "execution-step descriptor"
                )
            if not set(descriptor.requires).issubset(available):
                raise CapabilityDescriptorMismatchError(step.capability_name, "dependency order")
            output_keys = tuple(PipelineStateKey(key) for key in descriptor.provides)
            mapped_keys = CAPABILITY_OUTPUT_CONTRACTS.get(step.capability_name)
            if mapped_keys is not None and mapped_keys != output_keys:
                raise CapabilityDescriptorMismatchError(
                    step.capability_name, "runtime output-state mapping"
                )
            output_contracts[step.capability_name] = output_keys
            available.update(descriptor.provides)

        if not set(plan.goals).issubset(available):
            raise InvalidPlanningInputError("execution plan does not satisfy every goal")
        return plan.steps, output_contracts
