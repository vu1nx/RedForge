"""Tests for real RedForge planning declarations."""

import pytest  # type: ignore[reportMissingImports]

from redforge.planning import (
    BUILTIN_CAPABILITY_IDS,
    CapabilityId,
    ExecutionPlanner,
    create_default_registry,
)
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
        "subdomain_discovery",
        "host_resolution",
        "http_probe",
        "web_crawl",
        "technology_detection",
        "asset_intelligence",
        "vulnerability_intelligence",
        "knowledge_graph",
        "risk_intelligence",
    )


def test_default_definitions_have_complete_stable_metadata() -> None:
    registry = create_default_registry()

    assert registry.ids() == BUILTIN_CAPABILITY_IDS
    assert all(definition.display_name for definition in registry.all())
    assert all(definition.description for definition in registry.all())
    assert all(definition.version == "1.0" for definition in registry.all())
    assert all(definition.tags for definition in registry.all())
    assert registry.require(CapabilityId("http_probe")).provides == (
        PipelineStateKey.ALIVE_HOSTS,
        PipelineStateKey.HTTP_ENDPOINTS,
    )
    assert registry.require(CapabilityId("web_crawl")).requires == (
        PipelineStateKey.ALIVE_HOSTS,
    )
    assert registry.require(CapabilityId("asset_intelligence")).requires == (
        PipelineStateKey.ALIVE_HOSTS,
        PipelineStateKey.ENDPOINTS,
        PipelineStateKey.HOSTS,
        PipelineStateKey.SUBDOMAINS,
        PipelineStateKey.TECHNOLOGIES,
    )


def test_http_probe_is_the_single_producer_for_both_probe_outputs() -> None:
    registry = create_default_registry()

    assert tuple(
        item.capability_id
        for item in registry.producers_for(PipelineStateKey.ALIVE_HOSTS)
    ) == (CapabilityId("http_probe"),)
    assert tuple(
        item.capability_id
        for item in registry.producers_for(PipelineStateKey.HTTP_ENDPOINTS)
    ) == (CapabilityId("http_probe"),)

    plan = ExecutionPlanner(registry).plan(
        goals=(
            PipelineStateKey.ALIVE_HOSTS,
            PipelineStateKey.HTTP_ENDPOINTS,
        ),
        available_state=(PipelineStateKey.HOSTS,),
    )
    assert plan.required_capabilities == ("http_probe",)


@pytest.mark.parametrize(
    ("goal", "expected_last"),
    (
        (PipelineStateKey.SUBDOMAINS, "subdomain_discovery"),
        (PipelineStateKey.HOSTS, "host_resolution"),
        (PipelineStateKey.ALIVE_HOSTS, "http_probe"),
        (PipelineStateKey.HTTP_ENDPOINTS, "http_probe"),
        (PipelineStateKey.ENDPOINTS, "web_crawl"),
        (PipelineStateKey.TECHNOLOGIES, "technology_detection"),
        (PipelineStateKey.ASSET_INTELLIGENCE, "asset_intelligence"),
        (
            PipelineStateKey.VULNERABILITY_INTELLIGENCE,
            "vulnerability_intelligence",
        ),
        (PipelineStateKey.VULNERABILITIES, "vulnerability_detection"),
        (PipelineStateKey.KNOWLEDGE_GRAPH, "knowledge_graph"),
        (PipelineStateKey.RISK_INTELLIGENCE, "risk_intelligence"),
    ),
)
def test_every_canonical_goal_has_a_deterministic_dependency_closure(
    goal: PipelineStateKey,
    expected_last: str,
) -> None:
    plan = ExecutionPlanner(create_default_registry()).plan(goals=(goal,))

    assert plan.required_capabilities[-1] == expected_last
    assert len(plan.required_capability_ids) == len(
        set(plan.required_capability_ids)
    )


def test_complete_final_state_set_reuses_each_capability_once() -> None:
    plan = ExecutionPlanner(create_default_registry()).plan(
        goals=tuple(PipelineStateKey)
    )

    assert plan.required_capabilities == (
        "subdomain_discovery",
        "host_resolution",
        "http_probe",
        "vulnerability_detection",
        "web_crawl",
        "technology_detection",
        "asset_intelligence",
        "vulnerability_intelligence",
        "knowledge_graph",
        "risk_intelligence",
    )
