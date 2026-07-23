"""Tests for capability discovery and registration system."""

from redforge.capabilities.health import HealthCapability
from redforge.capabilities.subdomain_discovery import SubdomainDiscovery
from redforge.runtime import (
    CapabilityRegistry,
    DuplicateCapabilityError,
    Runtime,
    register_capabilities,
)


def test_register_multiple_capabilities() -> None:
    """Test registering multiple capabilities at once."""
    registry = CapabilityRegistry()
    capabilities = [HealthCapability(), SubdomainDiscovery()]

    register_capabilities(registry, capabilities)

    assert registry.is_registered("health")
    assert registry.is_registered("subdomain_discovery")
    assert len(registry.list_names()) == 2


def test_register_capabilities_via_runtime() -> None:
    """Test registering capabilities through the Runtime method."""
    runtime = Runtime()
    capabilities = [HealthCapability(), SubdomainDiscovery()]

    runtime.register_capabilities(capabilities)

    assert runtime.registry.is_registered("health")
    assert runtime.registry.is_registered("subdomain_discovery")


def test_duplicate_registration_raises_error() -> None:
    """Test that duplicate registration raises an error."""
    registry = CapabilityRegistry()
    capabilities = [HealthCapability(), HealthCapability()]

    try:
        register_capabilities(registry, capabilities)
        raise AssertionError("Expected DuplicateCapabilityError")
    except DuplicateCapabilityError as e:
        assert e.name == "health"


def test_lookup_after_registration() -> None:
    """Test that capabilities can be looked up after registration."""
    registry = CapabilityRegistry()
    health_cap = HealthCapability()
    subdomain_cap = SubdomainDiscovery()

    register_capabilities(registry, [health_cap, subdomain_cap])

    retrieved_health = registry.get("health")
    retrieved_subdomain = registry.get("subdomain_discovery")

    assert retrieved_health is health_cap
    assert retrieved_subdomain is subdomain_cap


def test_empty_registration_list() -> None:
    """Test that an empty registration list is handled correctly."""
    registry = CapabilityRegistry()

    register_capabilities(registry, [])

    assert len(registry.list_names()) == 0


def test_partial_registration_on_duplicate() -> None:
    """Test that registration stops on first duplicate."""
    registry = CapabilityRegistry()
    health_cap1 = HealthCapability()
    subdomain_cap = SubdomainDiscovery()
    health_cap2 = HealthCapability()

    capabilities = [health_cap1, subdomain_cap, health_cap2]

    try:
        register_capabilities(registry, capabilities)
        raise AssertionError("Expected DuplicateCapabilityError")
    except DuplicateCapabilityError:
        pass

    # First two should be registered, third should not
    assert registry.is_registered("health")
    assert registry.is_registered("subdomain_discovery")
    # The health capability registered should be the first one
    assert registry.get("health") is health_cap1
