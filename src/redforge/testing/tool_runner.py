"""Deterministic in-memory implementation of the ToolRunner port."""

from collections import deque
from typing import cast

from redforge.sdk.tool import (
    ToolDefinition,
    ToolExecutionResult,
    ToolId,
    ToolInvocation,
    normalize_tool_id,
)


class FakeToolRunner:
    """Return queued evidence and retain immutable invocation snapshots."""

    def __init__(self) -> None:
        self._results: dict[ToolId, deque[ToolExecutionResult]] = {}
        self._invocations: list[ToolInvocation] = []

    @property
    def invocations(self) -> tuple[ToolInvocation, ...]:
        """Return an immutable snapshot of recorded safe invocation objects."""
        return tuple(self._invocations)

    def add_result(
        self,
        tool_id: ToolId | str,
        result: ToolExecutionResult,
    ) -> None:
        """Queue one deterministic result for a typed tool identity."""
        identity = normalize_tool_id(tool_id)
        if not isinstance(cast(object, result), ToolExecutionResult):
            raise TypeError("fake runner requires ToolExecutionResult values")
        if result.tool_id != identity:
            raise ValueError("fake result identity does not match queue identity")
        self._results.setdefault(identity, deque()).append(result)

    def is_available(self, definition: ToolDefinition) -> bool:
        """Return whether at least one result is currently configured."""
        if not isinstance(cast(object, definition), ToolDefinition):
            raise TypeError("fake tool runner requires a ToolDefinition")
        return bool(self._results.get(definition.tool_id))

    def run(
        self,
        definition: ToolDefinition,
        invocation: ToolInvocation,
    ) -> ToolExecutionResult:
        """Record a matching invocation and return the next queued result."""
        if not isinstance(cast(object, definition), ToolDefinition):
            raise TypeError("fake tool runner requires a ToolDefinition")
        if not isinstance(cast(object, invocation), ToolInvocation):
            raise TypeError("fake tool runner requires a ToolInvocation")
        if definition.tool_id != invocation.tool_id:
            raise ValueError("fake invocation identity does not match definition")
        queue = self._results.get(definition.tool_id)
        if not queue:
            raise RuntimeError(
                f"unexpected invocation for tool '{definition.tool_id}'"
            )
        self._invocations.append(invocation)
        return queue.popleft()
