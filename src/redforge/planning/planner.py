"""Pure deterministic dependency expansion and topological planning."""

import heapq
from collections.abc import Iterable
from typing import cast

from redforge.planning.errors import (
    AmbiguousProducerError,
    DependencyCycleError,
    InvalidPlanningInputError,
    MissingProducerError,
)
from redforge.planning.models import (
    ExecutionPlan,
    ExecutionStep,
    validate_state_key,
)
from redforge.planning.registry import CapabilityRegistry
from redforge.sdk.capability_definition import CapabilityDefinition
from redforge.sdk.capability_id import CapabilityId
from redforge.sdk.state import PipelineStateKey


def _normalize_state_input(
    values: Iterable[str], *, allow_empty: bool, field_name: str
) -> tuple[PipelineStateKey, ...]:
    if isinstance(values, str):
        raise InvalidPlanningInputError(f"{field_name} must be a collection")
    try:
        normalized = tuple(validate_state_key(item) for item in values)
    except TypeError as error:
        raise InvalidPlanningInputError(f"{field_name} must be iterable") from error
    result = tuple(sorted(set(normalized)))
    if not allow_empty and not result:
        raise InvalidPlanningInputError("at least one planning goal is required")
    return result


class ExecutionPlanner:
    """Create immutable plans without constructing or executing capabilities."""

    def __init__(self, registry: CapabilityRegistry) -> None:
        registry_value = cast(object, registry)
        if not isinstance(registry_value, CapabilityRegistry):
            raise TypeError("ExecutionPlanner requires a CapabilityRegistry")
        self._registry = registry

    def plan(
        self,
        *,
        goals: Iterable[str],
        available_state: Iterable[str] = (),
    ) -> ExecutionPlan:
        """Expand required state and return a deterministic topological plan."""
        normalized_goals = _normalize_state_input(
            goals, allow_empty=False, field_name="goals"
        )
        normalized_available = _normalize_state_input(
            available_state,
            allow_empty=True,
            field_name="available state",
        )
        available = set(normalized_available)
        selected: dict[CapabilityId, CapabilityDefinition] = {}
        visiting: list[CapabilityId] = []
        completed: set[CapabilityId] = set()

        def producer_for(state_key: str) -> CapabilityDefinition:
            producers = self._registry.producers_for(state_key)
            if not producers:
                raise MissingProducerError(state_key)
            if len(producers) > 1:
                raise AmbiguousProducerError(
                    state_key,
                    tuple(producer.capability_id.value for producer in producers),
                )
            return next(iter(producers))

        def visit(definition: CapabilityDefinition) -> None:
            capability_id = definition.capability_id
            if capability_id in completed:
                return
            if capability_id in visiting:
                start = visiting.index(capability_id)
                cycle = (*visiting[start:], capability_id)
                raise DependencyCycleError(
                    tuple(item.value for item in cycle)
                )
            visiting.append(capability_id)
            selected[capability_id] = definition
            for requirement in definition.requires:
                if requirement not in available:
                    visit(producer_for(requirement))
            visiting.pop()
            completed.add(capability_id)

        for goal in normalized_goals:
            if goal not in available:
                visit(producer_for(goal))

        ordered = self._topological_order(selected, available)
        steps = tuple(
            ExecutionStep(
                position=position,
                capability_id=definition.capability_id,
                requires=definition.requires,
                provides=definition.provides,
            )
            for position, definition in enumerate(ordered)
        )
        return ExecutionPlan(
            goals=normalized_goals,
            available_state=normalized_available,
            steps=steps,
        )

    def _topological_order(
        self,
        selected: dict[CapabilityId, CapabilityDefinition],
        available: set[PipelineStateKey],
    ) -> tuple[CapabilityDefinition, ...]:
        dependencies: dict[CapabilityId, set[CapabilityId]] = {
            name: set() for name in selected
        }
        dependents: dict[CapabilityId, set[CapabilityId]] = {
            name: set() for name in selected
        }
        for name, descriptor in selected.items():
            for requirement in descriptor.requires:
                if requirement in available:
                    continue
                producer = self._single_selected_producer(
                    requirement, selected
                )
                dependencies[name].add(producer.capability_id)
                dependents[producer.capability_id].add(name)

        ready = [name for name, items in dependencies.items() if not items]
        heapq.heapify(ready)
        ordered: list[CapabilityDefinition] = []
        while ready:
            name = heapq.heappop(ready)
            ordered.append(selected[name])
            for dependent in sorted(dependents[name]):
                dependencies[dependent].discard(name)
                if not dependencies[dependent]:
                    heapq.heappush(ready, dependent)
        if len(ordered) != len(selected):
            unresolved = min(
                set(selected) - {item.capability_id for item in ordered}
            )
            raise DependencyCycleError((unresolved.value, unresolved.value))
        return tuple(ordered)

    def _single_selected_producer(
        self,
        state_key: str,
        selected: dict[CapabilityId, CapabilityDefinition],
    ) -> CapabilityDefinition:
        producers = tuple(
            descriptor
            for descriptor in selected.values()
            if state_key in descriptor.provides
        )
        if not producers:
            raise MissingProducerError(state_key)
        if len(producers) > 1:
            names = tuple(
                sorted(item.capability_id.value for item in producers)
            )
            raise AmbiguousProducerError(state_key, names)
        return next(iter(producers))
