"""Context for capability execution."""

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, cast

from redforge.sdk.result import StatePublication


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

    def has(self, key: str) -> bool:
        """Return whether a state key is present, independently of its value."""
        return key in self.state

    def get(self, key: str) -> Any:
        """Return a state value or None when it is absent."""
        return self.state.get(key)

    def publish(self, publication: StatePublication) -> None:
        """Publish one validated state value."""
        self.publish_many((publication,))

    def publish_many(self, publications: Iterable[StatePublication]) -> None:
        """Validate a complete batch, then replace state values atomically."""
        publications_value = cast(object, publications)
        if isinstance(publications_value, (str, bytes)):
            raise TypeError("publications must be a collection")
        try:
            batch = tuple(publications)
        except TypeError as error:
            raise TypeError("publications must be iterable") from error
        batch_value = cast(tuple[object, ...], cast(object, batch))
        if not all(isinstance(item, StatePublication) for item in batch_value):
            raise TypeError("publications must contain StatePublication values")
        typed_batch = cast(tuple[StatePublication, ...], batch_value)
        keys = tuple(item.key for item in typed_batch)
        if len(keys) != len(set(keys)):
            raise ValueError("publication batch contains duplicate state keys")
        updates: dict[str, Any] = {
            publication.key: publication.value for publication in typed_batch
        }
        self.state.update(updates)
