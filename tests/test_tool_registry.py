"""Tests for the deterministic external ToolRegistry."""

import pytest  # type: ignore[reportMissingImports]

from redforge.sdk import (
    ToolDefinition,
    ToolId,
    ToolRegistry,
    UnknownToolError,
)


def _definition(name: str, *tags: str) -> ToolDefinition:
    return ToolDefinition(
        tool_id=name,
        display_name=name.replace("_", " ").title(),
        description=f"{name} test provider.",
        executable=name,
        tags=tags,
    )


def test_registry_lookup_order_queries_and_immutable_snapshots() -> None:
    second = _definition("second", "active", "recon")
    first = _definition("first", "recon")
    registry = ToolRegistry((second, first))

    assert registry.get("first") is first
    assert registry.require(ToolId("second")) is second
    assert registry.contains("first")
    assert registry.ids() == (ToolId("first"), ToolId("second"))
    assert registry.all() == (first, second)
    assert registry.by_tag("RECON") == (first, second)
    assert registry.by_tag("unknown") == ()
    assert isinstance(registry.all(), tuple)


def test_registry_rejects_duplicates_and_non_definitions() -> None:
    registry = ToolRegistry((_definition("same"),))
    with pytest.raises(ValueError, match="duplicate"):
        registry.register(_definition("same"))
    with pytest.raises(TypeError):
        registry.register(object())  # type: ignore[arg-type]


def test_registry_unknown_and_malformed_lookup_behavior() -> None:
    registry = ToolRegistry()

    assert registry.get("missing") is None
    with pytest.raises(UnknownToolError, match="Unknown tool"):
        registry.require("missing")
    with pytest.raises(ValueError, match="tool ID"):
        registry.get("Malformed ID")


def test_registry_registration_has_no_execution_side_effect() -> None:
    definition = _definition("never_executed")
    registry = ToolRegistry()

    registry.register(definition)

    assert registry.all() == (definition,)
    assert not hasattr(registry, "run")
