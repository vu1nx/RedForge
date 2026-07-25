"""Immutable declarative execution-planning models."""

from dataclasses import dataclass
from typing import cast

from redforge.planning.errors import InvalidPlanningInputError
from redforge.runtime.pipeline_state import PipelineStateKey


def state_keys() -> tuple[str, ...]:
    """Return every canonical pipeline state key in deterministic order."""
    return tuple(
        sorted(
            value
            for name, value in vars(PipelineStateKey).items()
            if name.isupper() and isinstance(value, str)
        )
    )


_STATE_KEYS = frozenset(state_keys())


def validate_state_key(value: object) -> str:
    """Return a canonical state key or raise a focused validation error."""
    if not isinstance(value, str) or value not in _STATE_KEYS:
        raise InvalidPlanningInputError("planning state key is invalid")
    return value


def _validate_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip().lower()
        or any(not (character.isalnum() or character == "_") for character in value)
    ):
        raise InvalidPlanningInputError("capability name is invalid")
    return value


def _validate_state_tuple(
    value: object, *, field_name: str, require_sorted: bool = False
) -> tuple[str, ...]:
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


@dataclass(frozen=True, slots=True)
class CapabilityDescriptor:
    """Declarative required and provided state for one capability."""

    name: str
    requires: tuple[str, ...] = ()
    provides: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_name(self.name)
        requires = _validate_state_tuple(self.requires, field_name="requires")
        provides = _validate_state_tuple(self.provides, field_name="provides")
        if not provides:
            raise InvalidPlanningInputError(
                "capability descriptor must provide at least one state key"
            )
        object.__setattr__(self, "requires", tuple(sorted(requires)))
        object.__setattr__(self, "provides", tuple(sorted(provides)))


@dataclass(frozen=True, slots=True)
class ExecutionStep:
    """One capability execution position in a deterministic plan."""

    position: int
    capability_name: str
    requires: tuple[str, ...]
    provides: tuple[str, ...]

    def __post_init__(self) -> None:
        position = cast(object, self.position)
        if not isinstance(position, int) or isinstance(position, bool) or position < 0:
            raise InvalidPlanningInputError("step position must be a non-negative integer")
        _validate_name(self.capability_name)
        _validate_state_tuple(
            self.requires, field_name="step requires", require_sorted=True
        )
        provides = _validate_state_tuple(
            self.provides, field_name="step provides", require_sorted=True
        )
        if not provides:
            raise InvalidPlanningInputError("execution step must provide state")


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """Immutable dependency-ordered plan that does not execute capabilities."""

    goals: tuple[str, ...]
    available_state: tuple[str, ...]
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
        """Return planned capability names in execution order."""
        return tuple(step.capability_name for step in self.steps)

    @property
    def produced_state(self) -> tuple[str, ...]:
        """Return all state provided by plan steps."""
        return tuple(
            sorted({state for step in self.steps for state in step.provides})
        )

    @property
    def is_empty(self) -> bool:
        """Return whether no capability execution is required."""
        return not self.steps
