"""Algorithm tests for pure deterministic execution planning."""

from collections.abc import Iterable

import pytest  # type: ignore[reportMissingImports]

from redforge.planning import (
    AmbiguousProducerError,
    CapabilityDescriptor,
    CapabilityRegistry,
    DependencyCycleError,
    ExecutionPlanner,
    InvalidPlanningInputError,
    MissingProducerError,
)
from redforge.runtime.pipeline_state import PipelineStateKey


def _registry(*descriptors: CapabilityDescriptor) -> CapabilityRegistry:
    registry = CapabilityRegistry()
    for descriptor in descriptors:
        registry.register(descriptor)
    return registry


def _dag_registry() -> CapabilityRegistry:
    return _registry(
        CapabilityDescriptor("a", provides=(PipelineStateKey.HOSTS,)),
        CapabilityDescriptor(
            "b",
            requires=(PipelineStateKey.HOSTS,),
            provides=(PipelineStateKey.ENDPOINTS,),
        ),
        CapabilityDescriptor(
            "c",
            requires=(PipelineStateKey.HOSTS,),
            provides=(PipelineStateKey.TECHNOLOGIES,),
        ),
        CapabilityDescriptor(
            "d",
            requires=(
                PipelineStateKey.ENDPOINTS,
                PipelineStateKey.TECHNOLOGIES,
            ),
            provides=(PipelineStateKey.ASSET_INTELLIGENCE,),
        ),
    )


def _names(goals: Iterable[str], available: Iterable[str] = ()) -> tuple[str, ...]:
    return ExecutionPlanner(_dag_registry()).plan(
        goals=goals, available_state=available
    ).required_capabilities


def test_shared_dependency_and_multi_input_topological_order() -> None:
    assert _names((PipelineStateKey.ASSET_INTELLIGENCE,)) == (
        "a",
        "b",
        "c",
        "d",
    )
    assert _names(
        (PipelineStateKey.ASSET_INTELLIGENCE,),
        (PipelineStateKey.HOSTS,),
    ) == ("b", "c", "d")


def test_goal_and_input_order_do_not_change_plan_equality() -> None:
    planner = ExecutionPlanner(_dag_registry())
    first = planner.plan(
        goals=(
            PipelineStateKey.TECHNOLOGIES,
            PipelineStateKey.ENDPOINTS,
        ),
        available_state=(PipelineStateKey.HOSTS,),
    )
    second = planner.plan(
        goals=(item for item in (
            PipelineStateKey.ENDPOINTS,
            PipelineStateKey.TECHNOLOGIES,
            PipelineStateKey.ENDPOINTS,
        )),
        available_state={
            PipelineStateKey.HOSTS,
            PipelineStateKey.HOSTS,
        },
    )
    assert first == second
    assert first.required_capabilities == ("b", "c")


def test_registration_order_does_not_change_plan() -> None:
    descriptors = _dag_registry().descriptors
    forward = ExecutionPlanner(_registry(*descriptors)).plan(
        goals=(PipelineStateKey.ASSET_INTELLIGENCE,)
    )
    reverse = ExecutionPlanner(_registry(*reversed(descriptors))).plan(
        goals=(PipelineStateKey.ASSET_INTELLIGENCE,)
    )
    assert forward == reverse


def test_already_satisfied_goal_produces_empty_plan() -> None:
    plan = ExecutionPlanner(_dag_registry()).plan(
        goals=(PipelineStateKey.ENDPOINTS,),
        available_state=(PipelineStateKey.ENDPOINTS,),
    )
    assert plan.is_empty


def test_one_capability_with_multiple_outputs_appears_once() -> None:
    registry = _registry(
        CapabilityDescriptor(
            "multi",
            provides=(
                PipelineStateKey.HOSTS,
                PipelineStateKey.ENDPOINTS,
            ),
        )
    )
    plan = ExecutionPlanner(registry).plan(
        goals=(PipelineStateKey.ENDPOINTS, PipelineStateKey.HOSTS)
    )
    assert plan.required_capabilities == ("multi",)


def test_missing_goal_and_transitive_producers_fail() -> None:
    with pytest.raises(MissingProducerError) as goal_error:
        ExecutionPlanner(CapabilityRegistry()).plan(
            goals=(PipelineStateKey.HOSTS,)
        )
    assert goal_error.value.state_key == PipelineStateKey.HOSTS

    registry = _registry(
        CapabilityDescriptor(
            "dependent",
            requires=(PipelineStateKey.SUBDOMAINS,),
            provides=(PipelineStateKey.HOSTS,),
        )
    )
    with pytest.raises(MissingProducerError) as dependency_error:
        ExecutionPlanner(registry).plan(goals=(PipelineStateKey.HOSTS,))
    assert dependency_error.value.state_key == PipelineStateKey.SUBDOMAINS


def test_ambiguous_producer_names_are_sorted() -> None:
    registry = _registry(
        CapabilityDescriptor("z", provides=(PipelineStateKey.HOSTS,)),
        CapabilityDescriptor("a", provides=(PipelineStateKey.HOSTS,)),
    )
    with pytest.raises(AmbiguousProducerError) as error:
        ExecutionPlanner(registry).plan(goals=(PipelineStateKey.HOSTS,))
    assert error.value.candidates == ("a", "z")


@pytest.mark.parametrize(
    ("descriptors", "expected"),
    [
        (
            (
                CapabilityDescriptor(
                    "self_cycle",
                    requires=(PipelineStateKey.HOSTS,),
                    provides=(PipelineStateKey.HOSTS,),
                ),
            ),
            ("self_cycle", "self_cycle"),
        ),
        (
            (
                CapabilityDescriptor(
                    "a",
                    requires=(PipelineStateKey.ENDPOINTS,),
                    provides=(PipelineStateKey.HOSTS,),
                ),
                CapabilityDescriptor(
                    "b",
                    requires=(PipelineStateKey.HOSTS,),
                    provides=(PipelineStateKey.ENDPOINTS,),
                ),
            ),
            ("a", "b", "a"),
        ),
        (
            (
                CapabilityDescriptor(
                    "a",
                    requires=(PipelineStateKey.TECHNOLOGIES,),
                    provides=(PipelineStateKey.HOSTS,),
                ),
                CapabilityDescriptor(
                    "b",
                    requires=(PipelineStateKey.HOSTS,),
                    provides=(PipelineStateKey.ENDPOINTS,),
                ),
                CapabilityDescriptor(
                    "c",
                    requires=(PipelineStateKey.ENDPOINTS,),
                    provides=(PipelineStateKey.TECHNOLOGIES,),
                ),
            ),
            ("a", "c", "b", "a"),
        ),
    ],
)
def test_cycles_are_reported_with_deterministic_paths(
    descriptors: tuple[CapabilityDescriptor, ...],
    expected: tuple[str, ...],
) -> None:
    with pytest.raises(DependencyCycleError) as error:
        ExecutionPlanner(_registry(*descriptors)).plan(
            goals=(PipelineStateKey.HOSTS,)
        )
    assert error.value.cycle_path == expected


def test_unrelated_cycle_does_not_block_valid_goal() -> None:
    registry = _registry(
        CapabilityDescriptor("valid", provides=(PipelineStateKey.HOSTS,)),
        CapabilityDescriptor(
            "cycle_a",
            requires=(PipelineStateKey.TECHNOLOGIES,),
            provides=(PipelineStateKey.ENDPOINTS,),
        ),
        CapabilityDescriptor(
            "cycle_b",
            requires=(PipelineStateKey.ENDPOINTS,),
            provides=(PipelineStateKey.TECHNOLOGIES,),
        ),
    )
    plan = ExecutionPlanner(registry).plan(goals=(PipelineStateKey.HOSTS,))
    assert plan.required_capabilities == ("valid",)


@pytest.mark.parametrize(
    "goals",
    [(), [], "hosts", (None,), ("unknown",)],
)
def test_invalid_goal_inputs_are_rejected(goals: object) -> None:
    with pytest.raises(InvalidPlanningInputError):
        ExecutionPlanner(_dag_registry()).plan(
            goals=goals  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("available", ["hosts", (None,), ("unknown",)])
def test_invalid_available_state_inputs_are_rejected(available: object) -> None:
    with pytest.raises(InvalidPlanningInputError):
        ExecutionPlanner(_dag_registry()).plan(
            goals=(PipelineStateKey.HOSTS,),
            available_state=available,  # type: ignore[arg-type]
        )
