"""Tests for real RedForge planning declarations."""

from redforge.planning import ExecutionPlanner, create_default_registry
from redforge.runtime.pipeline_state import PipelineStateKey


def _plan(goal: str, *available: str) -> tuple[str, ...]:
    return ExecutionPlanner(create_default_registry()).plan(
        goals=(goal,),
        available_state=available,
    ).required_capabilities


def test_host_resolution_from_discovered_names() -> None:
    assert _plan(
        PipelineStateKey.HOSTS,
        PipelineStateKey.SUBDOMAINS,
    ) == ("host_resolution",)


def test_endpoint_goal_uses_actual_http_and_crawl_boundaries() -> None:
    assert _plan(
        PipelineStateKey.ENDPOINTS,
        PipelineStateKey.SUBDOMAINS,
    ) == ("host_resolution", "http_probe", "web_crawl")


def test_available_endpoint_goal_is_empty() -> None:
    assert _plan(
        PipelineStateKey.ENDPOINTS,
        PipelineStateKey.ENDPOINTS,
    ) == ()


def test_risk_from_available_graph_requires_only_risk_intelligence() -> None:
    assert _plan(
        PipelineStateKey.RISK_INTELLIGENCE,
        PipelineStateKey.KNOWLEDGE_GRAPH,
    ) == ("risk_intelligence",)


def test_full_risk_contract_uses_minimum_current_required_state_closure() -> None:
    assert _plan(PipelineStateKey.RISK_INTELLIGENCE) == (
        "asset_intelligence",
        "vulnerability_intelligence",
        "knowledge_graph",
        "risk_intelligence",
    )
