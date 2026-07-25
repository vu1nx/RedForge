"""Tests for immutable execution-planning models."""

from dataclasses import FrozenInstanceError

import pytest  # type: ignore[reportMissingImports]

from redforge.planning import (
    CapabilityDefinition,
    CapabilityDescriptor,
    CapabilityId,
    ExecutionPlan,
    ExecutionStep,
)
from redforge.planning.errors import InvalidPlanningInputError
from redforge.runtime.pipeline_state import PipelineStateKey


def test_definition_is_immutable_slotted_and_normalized() -> None:
    definition = CapabilityDefinition(
        capability_id=CapabilityId("example_capability"),
        display_name="Example Capability",
        description="Produces deterministic endpoint records.",
        version="1.0",
        requires=[PipelineStateKey.SUBDOMAINS, PipelineStateKey.HOSTS],
        provides=(PipelineStateKey.ENDPOINTS,),
        tags=["Recon", "analysis"],
    )

    assert definition.requires == (
        PipelineStateKey.HOSTS,
        PipelineStateKey.SUBDOMAINS,
    )
    assert definition.tags == ("analysis", "recon")
    assert not hasattr(definition, "__dict__")
    with pytest.raises(FrozenInstanceError):
        definition.version = "2.0"  # type: ignore[misc]


@pytest.mark.parametrize(
    "name",
    ["", " Upper", "upper-case", "with space", "UPPER"],
)
def test_legacy_descriptor_rejects_invalid_names(name: str) -> None:
    with pytest.raises(ValueError):
        CapabilityDescriptor(name, provides=(PipelineStateKey.HOSTS,))


def test_definition_normalizes_mutable_and_rejects_duplicate_or_empty_outputs() -> None:
    normalized = CapabilityDescriptor(
        "mutable",
        provides=[PipelineStateKey.HOSTS],
    )
    assert normalized.provides == (PipelineStateKey.HOSTS,)
    with pytest.raises(ValueError):
        CapabilityDescriptor(
            "duplicate",
            provides=(PipelineStateKey.HOSTS, PipelineStateKey.HOSTS),
        )
    with pytest.raises(ValueError):
        CapabilityDescriptor("empty")


def test_execution_plan_validates_and_exposes_derived_immutable_state() -> None:
    step = ExecutionStep(
        position=0,
        capability_name="host_resolution",
        requires=(PipelineStateKey.SUBDOMAINS,),
        provides=(PipelineStateKey.HOSTS,),
    )
    plan = ExecutionPlan(
        goals=(PipelineStateKey.HOSTS,),
        available_state=(PipelineStateKey.SUBDOMAINS,),
        steps=(step,),
    )

    assert plan.required_capabilities == ("host_resolution",)
    assert plan.required_capability_ids == (CapabilityId("host_resolution"),)
    assert step.capability_id == CapabilityId("host_resolution")
    assert plan.produced_state == (PipelineStateKey.HOSTS,)
    assert not plan.is_empty
    assert not hasattr(plan, "__dict__")
    with pytest.raises(FrozenInstanceError):
        plan.steps = ()  # type: ignore[misc]


def test_empty_plan_is_valid_when_goal_is_available() -> None:
    plan = ExecutionPlan(
        goals=(PipelineStateKey.ENDPOINTS,),
        available_state=(PipelineStateKey.ENDPOINTS,),
    )
    assert plan.is_empty


def test_malformed_plan_models_are_rejected() -> None:
    with pytest.raises(InvalidPlanningInputError):
        ExecutionPlan(goals=(), available_state=())
    with pytest.raises(InvalidPlanningInputError):
        ExecutionStep(
            position=-1,
            capability_name="step",
            requires=(),
            provides=(PipelineStateKey.HOSTS,),
        )
    with pytest.raises(InvalidPlanningInputError):
        ExecutionPlan(
            goals=(PipelineStateKey.HOSTS,),
            available_state=(),
            steps=(),
        )
    with pytest.raises(InvalidPlanningInputError):
        ExecutionPlan(
            goals=(PipelineStateKey.HOSTS,),
            available_state=(),
            steps=(object(),),  # type: ignore[arg-type]
        )
