"""Composable immutable-definition tool registry factories."""

from redforge.adapters.subfinder import SUBFINDER_TOOL
from redforge.sdk.tool_registry import ToolRegistry


def create_default_tool_registry() -> ToolRegistry:
    """Return a fresh registry of supported external tool definitions."""
    return ToolRegistry((SUBFINDER_TOOL,))
