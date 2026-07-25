"""Result of capability execution."""

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, cast

from redforge.sdk.state import PipelineStateKey


class Status(StrEnum):
    """Status of a capability execution."""

    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"
    PARTIAL = "partial"


@dataclass(frozen=True, slots=True)
class StatePublication:
    """One immutable typed value to publish into pipeline state."""

    key: PipelineStateKey
    value: object

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.key), PipelineStateKey):
            raise TypeError("state publication key must be a PipelineStateKey")


@dataclass(frozen=True, slots=True)
class Result[T]:
    """Result of a capability execution.

    Contains the outcome, data, and metadata from executing a capability.
    """

    status: Status
    """Status of the capability execution."""

    data: T
    """Data produced by the capability execution."""

    errors: list[str] = field(default_factory=list)  # type: ignore[reportUnknownVariableType]
    """Errors encountered during execution."""

    metadata: dict[str, Any] = field(default_factory=dict)  # type: ignore[reportUnknownVariableType]
    """Additional metadata about the execution result."""

    publications: tuple[StatePublication, ...] = ()
    """Explicit immutable state values produced by this execution."""

    def __post_init__(self) -> None:
        publications_value = cast(object, self.publications)
        if isinstance(publications_value, (str, bytes)) or not isinstance(
            publications_value, Iterable
        ):
            raise TypeError("publications must be an iterable")
        publications = tuple(cast(Iterable[object], publications_value))
        if not all(isinstance(item, StatePublication) for item in publications):
            raise TypeError("publications must contain StatePublication values")
        typed_publications = cast(tuple[StatePublication, ...], publications)
        keys = tuple(item.key for item in typed_publications)
        if len(keys) != len(set(keys)):
            raise ValueError("result contains duplicate state publications")
        object.__setattr__(self, "publications", typed_publications)
