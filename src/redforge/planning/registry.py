"""Deterministic Registry v2 for immutable capability definitions."""

from collections.abc import Iterable
from typing import cast

from redforge.planning.errors import UnknownCapabilityError
from redforge.sdk.capability_definition import CapabilityDefinition
from redforge.sdk.capability_id import CapabilityId, normalize_capability_id
from redforge.sdk.state import PipelineStateKey


class CapabilityRegistry:
    """Mutation-controlled registry with immutable deterministic query results."""

    def __init__(
        self, definitions: Iterable[CapabilityDefinition] = ()
    ) -> None:
        self._by_id: dict[CapabilityId, CapabilityDefinition] = {}
        for definition in definitions:
            self.register(definition)

    def register(self, definition: CapabilityDefinition) -> None:
        """Register one immutable definition without silent replacement."""
        definition_value = cast(object, definition)
        if not isinstance(definition_value, CapabilityDefinition):
            raise TypeError("registry accepts CapabilityDefinition values only")
        capability_id = definition.capability_id
        if capability_id in self._by_id:
            raise ValueError(f"duplicate capability definition: '{capability_id}'")
        self._by_id[capability_id] = definition

    def get(
        self, capability_id: CapabilityId | str
    ) -> CapabilityDefinition | None:
        """Return a definition or None for an unknown valid identity."""
        identity = normalize_capability_id(capability_id)
        return self._by_id.get(identity)

    def require(
        self, capability_id: CapabilityId | str
    ) -> CapabilityDefinition:
        """Return a definition or raise a focused unknown-capability error."""
        identity = normalize_capability_id(capability_id)
        definition = self._by_id.get(identity)
        if definition is None:
            raise UnknownCapabilityError(identity.value)
        return definition

    def contains(self, capability_id: CapabilityId | str) -> bool:
        """Return whether an identity has a registered definition."""
        return self.get(capability_id) is not None

    def all(self) -> tuple[CapabilityDefinition, ...]:
        """Return definitions ordered by stable capability identity."""
        return tuple(self._by_id[item] for item in sorted(self._by_id))

    def ids(self) -> tuple[CapabilityId, ...]:
        """Return typed identities in deterministic order."""
        return tuple(sorted(self._by_id))

    def by_tag(self, tag: str) -> tuple[CapabilityDefinition, ...]:
        """Return definitions carrying one normalized descriptive tag."""
        if not isinstance(cast(object, tag), str):
            return ()
        normalized = tag.strip().lower()
        if not normalized:
            return ()
        return tuple(
            definition
            for definition in self.all()
            if normalized in definition.tags
        )

    def producers_for(
        self, state_key: PipelineStateKey | str
    ) -> tuple[CapabilityDefinition, ...]:
        """Return deterministic definitions that may provide one state key."""
        try:
            key = PipelineStateKey(state_key)
        except (TypeError, ValueError):
            return ()
        return tuple(
            definition
            for definition in self.all()
            if key in definition.provides
        )

    @property
    def descriptors(self) -> tuple[CapabilityDefinition, ...]:
        """Return the legacy immutable descriptor view."""
        return self.all()
