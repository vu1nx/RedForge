"""Result of capability execution."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    """Status of a capability execution."""

    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"
    PARTIAL = "partial"


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
