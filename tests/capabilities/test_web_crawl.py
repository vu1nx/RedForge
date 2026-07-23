"""Tests for WebCrawlCapability."""

from ipaddress import IPv4Address
from unittest.mock import MagicMock, patch

from redforge.adapters.katana import KatanaAdapterError
from redforge.capabilities.web_crawl import WebCrawlCapability
from redforge.domain.endpoint import Endpoint
from redforge.domain.host import Host
from redforge.sdk.context import Context
from redforge.sdk.result import Status


def _sample_alive_hosts() -> list[Host]:
    return [
        Host(address=IPv4Address("93.184.216.34"), hostname="www.example.com"),
        Host(address=IPv4Address("93.184.216.35"), hostname="api.example.com"),
    ]


def _sample_endpoints() -> list[Endpoint]:
    return [
        Endpoint(host="www.example.com", port=443, protocol="https", path="/"),
        Endpoint(host="www.example.com", port=443, protocol="https", path="/about"),
        Endpoint(host="api.example.com", port=80, protocol="http", path="/"),
    ]


@patch("redforge.adapters.katana.KatanaAdapter.crawl_hosts")
def test_web_crawl_success(mock_crawl: MagicMock) -> None:
    """Test successful web crawling through the capability."""
    endpoints = _sample_endpoints()
    mock_crawl.return_value = endpoints

    capability = WebCrawlCapability(binary_path="katana")
    context = Context(target_id="example.com", state={"alive_hosts": _sample_alive_hosts()})
    result = capability.execute(context)

    assert result.status == Status.SUCCESS
    assert result.data == endpoints
    assert len(result.errors) == 0

    # Verify that hosts were converted to URLs for the adapter
    mock_crawl.assert_called_once()
    call_args = mock_crawl.call_args[0][0]
    assert "http://www.example.com" in call_args
    assert "https://www.example.com" in call_args
    assert "http://api.example.com" in call_args
    assert "https://api.example.com" in call_args


@patch("redforge.adapters.katana.KatanaAdapter.crawl_hosts")
def test_web_crawl_adapter_error(mock_crawl: MagicMock) -> None:
    """Test web crawling when the adapter raises an error."""
    mock_crawl.side_effect = KatanaAdapterError("Katana not found")

    capability = WebCrawlCapability(binary_path="katana")
    context = Context(target_id="example.com", state={"alive_hosts": _sample_alive_hosts()})
    result = capability.execute(context)

    assert result.status == Status.ERROR
    assert result.data == []
    assert len(result.errors) == 1
    assert "Katana not found" in result.errors[0]


def test_web_crawl_empty_result() -> None:
    """Test web crawling with no alive hosts in pipeline state."""
    capability = WebCrawlCapability(binary_path="katana")
    context = Context(target_id="example.com", state={"alive_hosts": []})
    result = capability.execute(context)

    assert result.status == Status.SUCCESS
    assert result.data == []
    assert len(result.errors) == 0


def test_web_crawl_name() -> None:
    """Test that the capability has the correct name."""
    capability = WebCrawlCapability()
    assert capability.name == "web_crawl"


@patch("redforge.adapters.katana.KatanaAdapter.crawl_hosts")
def test_web_crawl_returns_typed_result(mock_crawl: MagicMock) -> None:
    """Test that the capability returns a typed Result object."""
    endpoints = _sample_endpoints()
    mock_crawl.return_value = endpoints

    capability = WebCrawlCapability(binary_path="katana")
    context = Context(target_id="example.com", state={"alive_hosts": _sample_alive_hosts()})
    result = capability.execute(context)

    assert isinstance(result.data, list)
    assert all(isinstance(endpoint, Endpoint) for endpoint in result.data)
    assert result.data[0].host == "www.example.com"
    assert result.data[0].port == 443
    assert result.data[0].protocol == "https"


@patch("redforge.adapters.katana.KatanaAdapter.crawl_hosts")
def test_web_crawl_empty_endpoint_list(mock_crawl: MagicMock) -> None:
    """Test web crawling when adapter returns empty endpoint list."""
    mock_crawl.return_value = []

    capability = WebCrawlCapability(binary_path="katana")
    context = Context(target_id="example.com", state={"alive_hosts": _sample_alive_hosts()})
    result = capability.execute(context)

    assert result.status == Status.SUCCESS
    assert result.data == []
    assert len(result.errors) == 0


def test_web_crawl_invalid_state_type() -> None:
    """Test web crawling with invalid state type."""
    capability = WebCrawlCapability(binary_path="katana")
    context = Context(target_id="example.com", state={"alive_hosts": "not a list"})
    result = capability.execute(context)

    assert result.status == Status.SUCCESS
    assert result.data == []
    assert len(result.errors) == 0
