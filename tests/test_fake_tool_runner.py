"""Tests for the deterministic FakeToolRunner."""

import pytest  # type: ignore[reportMissingImports]

from redforge.sdk import (
    ToolDefinition,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolId,
    ToolInvocation,
)
from redforge.testing import FakeToolRunner


def _definition() -> ToolDefinition:
    return ToolDefinition(
        "fake",
        "Fake",
        "Fake test tool.",
        "fake",
    )


def _result(stdout: str) -> ToolExecutionResult:
    return ToolExecutionResult(
        ToolId("fake"),
        ToolExecutionStatus.SUCCESS,
        0,
        stdout,
        "",
        0,
    )


def test_fake_returns_queued_results_and_records_immutable_snapshot() -> None:
    fake = FakeToolRunner()
    definition = _definition()
    first = _result("first")
    second = _result("second")
    fake.add_result(definition.tool_id, first)
    fake.add_result(definition.tool_id, second)
    invocation = ToolInvocation(
        definition.tool_id,
        environment={"SECRET": "do-not-render"},
    )

    assert fake.is_available(definition)
    assert fake.run(definition, invocation) is first
    snapshot = fake.invocations
    assert fake.run(definition, invocation) is second
    assert snapshot == (invocation,)
    assert fake.invocations == (invocation, invocation)
    assert "do-not-render" not in repr(fake.invocations)
    assert not fake.is_available(definition)


def test_fake_rejects_unexpected_and_mismatched_invocations() -> None:
    fake = FakeToolRunner()
    definition = _definition()

    with pytest.raises(RuntimeError, match="unexpected invocation"):
        fake.run(definition, ToolInvocation(definition.tool_id))
    with pytest.raises(ValueError, match="identity"):
        fake.run(definition, ToolInvocation("different"))
    with pytest.raises(ValueError, match="identity"):
        fake.add_result("different", _result("value"))
