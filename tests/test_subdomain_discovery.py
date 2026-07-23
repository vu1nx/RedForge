"""Tests for SubdomainDiscovery capability."""

from unittest.mock import MagicMock, patch

from redforge.capabilities.subdomain_discovery import SubdomainDiscovery
from redforge.sdk.context import Context
from redforge.sdk.result import Status


@patch("redforge.adapters.subfinder.SubfinderAdapter.discover_subdomains")
def test_subdomain_discovery_success(mock_discover: MagicMock) -> None:
    """Test successful subdomain discovery."""
    mock_discover.return_value = ["www.example.com", "api.example.com"]

    capability = SubdomainDiscovery(binary_path="subfinder")
    context = Context(target_id="example.com")
    result = capability.execute(context)

    assert result.status == Status.SUCCESS
    assert result.data["subdomains"] == ["www.example.com", "api.example.com"]
    assert result.data["count"] == 2
    assert result.data["target_id"] == "example.com"
    assert len(result.errors) == 0

    mock_discover.assert_called_once_with("example.com")


@patch("redforge.adapters.subfinder.SubfinderAdapter.discover_subdomains")
def test_subdomain_discovery_adapter_error(mock_discover: MagicMock) -> None:
    """Test subdomain discovery when adapter raises an error."""
    from redforge.adapters.subfinder import SubfinderAdapterError

    mock_discover.side_effect = SubfinderAdapterError("Subfinder not found")

    capability = SubdomainDiscovery(binary_path="subfinder")
    context = Context(target_id="example.com")
    result = capability.execute(context)

    assert result.status == Status.ERROR
    assert len(result.errors) == 1
    assert "Subfinder not found" in result.errors[0]
    assert result.data["target_id"] == "example.com"


def test_subdomain_discovery_name() -> None:
    """Test that the capability has the correct name."""
    capability = SubdomainDiscovery()
    assert capability.name == "subdomain_discovery"


@patch("redforge.adapters.subfinder.SubfinderAdapter.discover_subdomains")
def test_subdomain_discovery_empty_results(mock_discover: MagicMock) -> None:
    """Test subdomain discovery with no results."""
    mock_discover.return_value = []

    capability = SubdomainDiscovery(binary_path="subfinder")
    context = Context(target_id="example.com")
    result = capability.execute(context)

    assert result.status == Status.SUCCESS
    assert result.data["subdomains"] == []
    assert result.data["count"] == 0
