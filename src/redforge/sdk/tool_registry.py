"""Deterministic registry for immutable external tool definitions."""

from collections.abc import Iterable
from typing import cast

from redforge.sdk.tool import ToolDefinition, ToolId, normalize_tool_id


class UnknownToolError(LookupError):
    """Raised when a required valid tool identity is not registered."""

    def __init__(self, tool_id: ToolId) -> None:
        self.tool_id = tool_id
        super().__init__(f"Unknown tool '{tool_id}'")


class ToolRegistry:
    """Mutation-controlled registry exposing immutable deterministic snapshots."""

    def __init__(self, definitions: Iterable[ToolDefinition] = ()) -> None:
        self._by_id: dict[ToolId, ToolDefinition] = {}
        for definition in definitions:
            self.register(definition)

    def register(self, definition: ToolDefinition) -> None:
        """Register one static definition without executing or replacing it."""
        if not isinstance(cast(object, definition), ToolDefinition):
            raise TypeError("tool registry accepts ToolDefinition values only")
        if definition.tool_id in self._by_id:
            raise ValueError(f"duplicate tool definition: '{definition.tool_id}'")
        self._by_id[definition.tool_id] = definition

    def get(self, tool_id: ToolId | str) -> ToolDefinition | None:
        """Return a definition or None for an unknown valid identity."""
        return self._by_id.get(normalize_tool_id(tool_id))

    def require(self, tool_id: ToolId | str) -> ToolDefinition:
        """Return a definition or raise a focused lookup error."""
        identity = normalize_tool_id(tool_id)
        definition = self._by_id.get(identity)
        if definition is None:
            raise UnknownToolError(identity)
        return definition

    def contains(self, tool_id: ToolId | str) -> bool:
        """Return whether a valid identity is registered."""
        return self.get(tool_id) is not None

    def all(self) -> tuple[ToolDefinition, ...]:
        """Return definitions ordered by stable identity."""
        return tuple(self._by_id[tool_id] for tool_id in sorted(self._by_id))

    def ids(self) -> tuple[ToolId, ...]:
        """Return registered typed identities in deterministic order."""
        return tuple(sorted(self._by_id))

    def by_tag(self, tag: str) -> tuple[ToolDefinition, ...]:
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
