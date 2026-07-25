"""Tests for the deterministic descriptor registry."""

import pytest  # type: ignore[reportMissingImports]

from redforge.planning import (
    CapabilityDescriptor,
    CapabilityRegistry,
    UnknownCapabilityError,
    create_default_registry,
)
from redforge.runtime.pipeline_state import PipelineStateKey


def _descriptor(name: str, provided: str) -> CapabilityDescriptor:
    return CapabilityDescriptor(name=name, provides=(provided,))


def test_registration_lookup_order_and_immutable_views() -> None:
    registry = CapabilityRegistry()
    second = _descriptor("second", PipelineStateKey.ENDPOINTS)
    first = _descriptor("first", PipelineStateKey.HOSTS)
    registry.register(second)
    registry.register(first)

    assert registry.get("first") is first
    assert registry.descriptors == (first, second)
    assert isinstance(registry.descriptors, tuple)
    assert registry.producers_for(PipelineStateKey.HOSTS) == (first,)


def test_duplicate_names_and_non_descriptors_are_rejected() -> None:
    registry = CapabilityRegistry()
    registry.register(_descriptor("duplicate", PipelineStateKey.HOSTS))
    with pytest.raises(ValueError, match="duplicate capability descriptor"):
        registry.register(_descriptor("duplicate", PipelineStateKey.ENDPOINTS))
    with pytest.raises(TypeError):
        registry.register(object())  # type: ignore[arg-type]


def test_unknown_capability_uses_focused_error() -> None:
    with pytest.raises(UnknownCapabilityError, match="Unknown capability"):
        CapabilityRegistry().get("missing")


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
        "host_resolution",
        "http_probe",
        "knowledge_graph",
        "risk_intelligence",
        "subdomain_discovery",
        "technology_detection",
        "vulnerability_intelligence",
        "web_crawl",
    )
    assert all(isinstance(item, CapabilityDescriptor) for item in registry.descriptors)
