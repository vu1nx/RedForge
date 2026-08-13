"""Tests for the deterministic Capability Registry v2."""

import pytest  # type: ignore[reportMissingImports]

from redforge.planning import (
    CapabilityDefinition,
    CapabilityDescriptor,
    CapabilityId,
    CapabilityRegistry,
    UnknownCapabilityError,
    create_default_registry,
)
from redforge.runtime.pipeline_state import PipelineStateKey


def _descriptor(name: str, provided: str) -> CapabilityDefinition:
    return CapabilityDescriptor(name=name, provides=(provided,))


def test_registration_lookup_order_and_immutable_views() -> None:
    registry = CapabilityRegistry()
    second = _descriptor("second", PipelineStateKey.ENDPOINTS)
    first = _descriptor("first", PipelineStateKey.HOSTS)
    registry.register(second)
    registry.register(first)

    assert registry.get("first") is first
    assert registry.require(CapabilityId("first")) is first
    assert registry.contains("first")
    assert registry.ids() == (CapabilityId("first"), CapabilityId("second"))
    assert registry.all() == (first, second)
    assert registry.descriptors == (first, second)
    assert isinstance(registry.descriptors, tuple)
    assert registry.producers_for(PipelineStateKey.HOSTS) == (first,)


def test_duplicate_names_and_non_descriptors_are_rejected() -> None:
    registry = CapabilityRegistry()
    registry.register(_descriptor("duplicate", PipelineStateKey.HOSTS))
    with pytest.raises(ValueError, match="duplicate capability definition"):
        registry.register(_descriptor("duplicate", PipelineStateKey.ENDPOINTS))
    with pytest.raises(TypeError):
        registry.register(object())  # type: ignore[arg-type]


def test_unknown_capability_uses_focused_error() -> None:
    assert CapabilityRegistry().get("missing") is None
    with pytest.raises(UnknownCapabilityError, match="Unknown capability"):
        CapabilityRegistry().require("missing")
    with pytest.raises(ValueError, match="capability ID is invalid"):
        CapabilityRegistry().get("Malformed ID")


def test_multiple_producers_are_returned_deterministically() -> None:
    registry = CapabilityRegistry()
    registry.register(_descriptor("z_provider", PipelineStateKey.HOSTS))
    registry.register(_descriptor("a_provider", PipelineStateKey.HOSTS))

    assert tuple(
        item.name for item in registry.producers_for(PipelineStateKey.HOSTS)
    ) == ("a_provider", "z_provider")


def test_default_registry_contains_only_existing_descriptor_contracts() -> None:
    registry = create_default_registry()

    assert tuple(item.name for item in registry.descriptors) == (
        "asset_intelligence",
        "finding_correlation",
        "host_resolution",
        "http_probe",
        "knowledge_graph",
        "risk_intelligence",
        "subdomain_discovery",
        "technology_detection",
        "vulnerability_detection",
        "vulnerability_enrichment",
        "vulnerability_intelligence",
        "web_crawl",
    )
    assert all(isinstance(item, CapabilityDescriptor) for item in registry.descriptors)


def test_tag_and_producer_queries_are_deterministic_and_immutable() -> None:
    first = CapabilityDefinition(
        capability_id=CapabilityId("first"),
        display_name="First",
        description="First producer.",
        version="1.0",
        provides=(PipelineStateKey.HOSTS, PipelineStateKey.SUBDOMAINS),
        tags=("recon", "passive"),
    )
    second = CapabilityDefinition(
        capability_id=CapabilityId("second"),
        display_name="Second",
        description="Second producer.",
        version="1.0",
        provides=(PipelineStateKey.HOSTS,),
        tags=("active", "recon"),
    )
    registry = CapabilityRegistry((second, first))

    assert registry.by_tag("RECON") == (first, second)
    assert registry.by_tag("unknown") == ()
    assert registry.producers_for(PipelineStateKey.HOSTS) == (first, second)
    assert registry.producers_for("not_a_state") == ()
    assert isinstance(registry.by_tag("recon"), tuple)
