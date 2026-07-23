"""Tests for HealthCapability."""

from redforge.capabilities.health import HealthCapability
from redforge.runtime import CapabilityRegistry, DuplicateCapabilityError
from redforge.sdk.context import Context
from redforge.sdk.result import Status


def test_capability_name() -> None:
    """Test that the capability has the correct name."""
    capability = HealthCapability()
    assert capability.name == "health"


def test_capability_execution() -> None:
    """Test that the capability executes successfully."""
    capability = HealthCapability()
    context = Context(target_id="test-target")
    result = capability.execute(context)

    assert result.status == Status.SUCCESS
    assert result.data["message"] == "Runtime and SDK are operational"
    assert result.data["target_id"] == "test-target"
    assert len(result.errors) == 0


def test_capability_registration() -> None:
    """Test that the capability can be registered in the registry."""
    registry = CapabilityRegistry()
    capability = HealthCapability()

    registry.register(capability)
    assert registry.is_registered("health")


def test_capability_lookup() -> None:
    """Test that the capability can be retrieved from the registry."""
    registry = CapabilityRegistry()
    capability = HealthCapability()

    registry.register(capability)
    retrieved_capability = registry.get("health")

    assert retrieved_capability is capability
    assert retrieved_capability.name == "health"


def test_duplicate_registration_raises_error() -> None:
    """Test that registering a duplicate capability raises an error."""
    registry = CapabilityRegistry()
    capability1 = HealthCapability()
    capability2 = HealthCapability()

    registry.register(capability1)

    try:
        registry.register(capability2)
        raise AssertionError("Expected DuplicateCapabilityError")
    except DuplicateCapabilityError as e:
        assert e.name == "health"


def test_capability_execution_via_registry() -> None:
    """Test end-to-end execution via the registry."""
    registry = CapabilityRegistry()
    capability = HealthCapability()

    registry.register(capability)
    retrieved_capability = registry.get("health")

    context = Context(target_id="test-target")
    result = retrieved_capability.execute(context)

    assert result.status == Status.SUCCESS
    assert result.data["message"] == "Runtime and SDK are operational"
