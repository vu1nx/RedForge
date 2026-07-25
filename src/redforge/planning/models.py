"""Immutable declarative execution-planning models."""

from dataclasses import dataclass
from typing import cast

from redforge.planning.errors import InvalidPlanningInputError
from redforge.sdk.capability_definition import (
    CapabilityDefinition,
    CapabilityDescriptor,
)
from redforge.sdk.capability_id import CapabilityId, normalize_capability_id
from redforge.sdk.state import PipelineStateKey


def state_keys() -> tuple[PipelineStateKey, ...]:
    """Return every canonical pipeline state key in deterministic order."""
    return tuple(sorted(PipelineStateKey))


def validate_state_key(value: object) -> PipelineStateKey:
    """Return a canonical state key or raise a focused validation error."""
    try:
        return PipelineStateKey(cast(str, value))
    except (TypeError, ValueError):
        raise InvalidPlanningInputError(
            "planning state key is invalid"
        ) from None


def _validate_state_tuple(
    value: object, *, field_name: str, require_sorted: bool = False
) -> tuple[PipelineStateKey, ...]:
    if not isinstance(value, tuple):
        raise InvalidPlanningInputError(f"{field_name} must be an immutable tuple")
    items = tuple(
        validate_state_key(item)
        for item in cast(tuple[object, ...], value)
    )
    if len(items) != len(set(items)):
        raise InvalidPlanningInputError(f"{field_name} contains duplicate state keys")
    if require_sorted and items != tuple(sorted(items)):
        raise InvalidPlanningInputError(f"{field_name} must be deterministically ordered")
    return items


@dataclass(frozen=True, slots=True, init=False)
class ExecutionStep:
    """One capability execution position in a deterministic plan."""

    position: int
    capability_id: CapabilityId
    requires: tuple[PipelineStateKey, ...]
    provides: tuple[PipelineStateKey, ...]

    def __init__(
        self,
        position: int,
        capability_id: CapabilityId | str | None = None,
        requires: tuple[PipelineStateKey | str, ...] = (),
        provides: tuple[PipelineStateKey | str, ...] = (),
        *,
        capability_name: str | None = None,
    ) -> None:
        """Create a typed step, accepting legacy ``capability_name=``."""
        position_value = cast(object, position)
        if (
            not isinstance(position_value, int)
            or isinstance(position_value, bool)
            or position_value < 0
        ):
            raise InvalidPlanningInputError(
                "step position must be a non-negative integer"
            )
        if capability_id is not None and capability_name is not None:
            raise InvalidPlanningInputError(
                "use capability_id or legacy capability_name, not both"
            )
        identity_input = (
            capability_id if capability_id is not None else capability_name
        )
        if identity_input is None:
            raise InvalidPlanningInputError("step capability identity is required")
        try:
            identity = normalize_capability_id(identity_input)
        except (TypeError, ValueError) as error:
            raise InvalidPlanningInputError(
                "step capability identity is invalid"
            ) from error
        required = _validate_state_tuple(
            requires, field_name="step requires", require_sorted=True
        )
        provided = _validate_state_tuple(
            provides, field_name="step provides", require_sorted=True
        )
        if not provided:
            raise InvalidPlanningInputError("execution step must provide state")
        object.__setattr__(self, "position", position)
        object.__setattr__(self, "capability_id", identity)
        object.__setattr__(self, "requires", required)
        object.__setattr__(self, "provides", provided)

    @property
    def capability_name(self) -> str:
        """Return the legacy serialized capability identity."""
        return self.capability_id.value


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """Immutable dependency-ordered plan that does not execute capabilities."""

    goals: tuple[PipelineStateKey, ...]
    available_state: tuple[PipelineStateKey, ...]
    steps: tuple[ExecutionStep, ...] = ()

    def __post_init__(self) -> None:
        goals = _validate_state_tuple(
            self.goals, field_name="goals", require_sorted=True
        )
        if not goals:
            raise InvalidPlanningInputError("at least one planning goal is required")
        available = _validate_state_tuple(
            self.available_state,
            field_name="available state",
            require_sorted=True,
        )
        steps_value = cast(object, self.steps)
        if not isinstance(steps_value, tuple):
            raise InvalidPlanningInputError("steps must be an immutable tuple")
        if not all(
            isinstance(step, ExecutionStep)
            for step in cast(tuple[object, ...], steps_value)
        ):
            raise InvalidPlanningInputError(
                "steps must contain ExecutionStep values only"
            )
        if tuple(step.position for step in self.steps) != tuple(range(len(self.steps))):
            raise InvalidPlanningInputError("step positions must be contiguous from zero")
        names = tuple(step.capability_name for step in self.steps)
        if len(names) != len(set(names)):
            raise InvalidPlanningInputError("execution plan contains duplicate capabilities")

        accumulated = set(available)
        for step in self.steps:
            if not set(step.requires).issubset(accumulated):
                raise InvalidPlanningInputError(
                    "execution step has an unsatisfied required state"
                )
            accumulated.update(step.provides)
        if not set(goals).issubset(accumulated):
            raise InvalidPlanningInputError("execution plan does not satisfy every goal")

    @property
    def required_capabilities(self) -> tuple[str, ...]:
        """Return legacy serialized capability identities in execution order."""
        return tuple(step.capability_name for step in self.steps)

    @property
    def required_capability_ids(self) -> tuple[CapabilityId, ...]:
        """Return typed planned capability identities in execution order."""
        return tuple(step.capability_id for step in self.steps)

    @property
    def produced_state(self) -> tuple[PipelineStateKey, ...]:
        """Return all state provided by plan steps."""
        return tuple(
            sorted({state for step in self.steps for state in step.provides})
        )

    @property
    def is_empty(self) -> bool:
        """Return whether no capability execution is required."""
        return not self.steps


__all__ = [
    "CapabilityDefinition",
    "CapabilityDescriptor",
    "ExecutionPlan",
    "ExecutionStep",
    "state_keys",
    "validate_state_key",
]
