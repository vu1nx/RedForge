"""Context for capability execution."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Context:
    """Runtime context for capability execution.

    The context provides access to runtime state, configuration,
    and shared resources during capability execution.
    """

    target_id: str
    """Identifier of the target being processed."""

    config: dict[str, Any] = field(default_factory=dict)  # type: ignore[reportUnknownVariableType]
    """Configuration parameters for the capability."""

    state: dict[str, Any] = field(default_factory=dict)  # type: ignore[reportUnknownVariableType]
    """Shared state accessible across capabilities."""

    metadata: dict[str, Any] = field(default_factory=dict)  # type: ignore[reportUnknownVariableType]
    """Additional metadata about the execution context."""

    def available_state_keys(self) -> tuple[str, ...]:
        """Return state keys that are present, independently of value truthiness."""
        return tuple(sorted(self.state))
