"""Tests for HttpProbeCapability."""

from ipaddress import IPv4Address
from unittest.mock import MagicMock, patch

from redforge.adapters.httpx import HttpxAdapterError
from redforge.capabilities.http_probe import HttpProbeCapability
from redforge.domain.host import Host
from redforge.sdk.context import Context
from redforge.sdk.result import Status


def _sample_hosts() -> list[Host]:
    return [
        Host(address=IPv4Address("93.184.216.34"), hostname="www.example.com"),
        Host(address=IPv4Address("93.184.216.35"), hostname="api.example.com"),
    ]


@patch("redforge.adapters.httpx.HttpxAdapter.probe_hosts")
def test_http_probe_success(mock_probe: MagicMock) -> None:
    """Test successful HTTP probing through the capability."""
    alive_hosts = [_sample_hosts()[0]]
    mock_probe.return_value = alive_hosts

    capability = HttpProbeCapability(binary_path="httpx")
    context = Context(target_id="example.com", state={"hosts": _sample_hosts()})
    result = capability.execute(context)

    assert result.status == Status.SUCCESS
    assert result.data == alive_hosts
    assert len(result.errors) == 0

    mock_probe.assert_called_once_with(_sample_hosts())


@patch("redforge.adapters.httpx.HttpxAdapter.probe_hosts")
def test_http_probe_adapter_error(mock_probe: MagicMock) -> None:
    """Test HTTP probing when the adapter raises an error."""
    mock_probe.side_effect = HttpxAdapterError("httpx not found")

    capability = HttpProbeCapability(binary_path="httpx")
    context = Context(target_id="example.com", state={"hosts": _sample_hosts()})
    result = capability.execute(context)

    assert result.status == Status.ERROR
    assert result.data == []
    assert len(result.errors) == 1
    assert "httpx not found" in result.errors[0]


def test_http_probe_empty_result() -> None:
    """Test HTTP probing with no hosts in pipeline state."""
    capability = HttpProbeCapability(binary_path="httpx")
    context = Context(target_id="example.com", state={"hosts": []})
    result = capability.execute(context)

    assert result.status == Status.SUCCESS
    assert result.data == []
    assert len(result.errors) == 0


def test_http_probe_name() -> None:
    """Test that the capability has the correct name."""
    capability = HttpProbeCapability()
    assert capability.name == "http_probe"


@patch("redforge.adapters.httpx.HttpxAdapter.probe_hosts")
def test_http_probe_returns_typed_result(mock_probe: MagicMock) -> None:
    """Test that the capability returns a typed Result object."""
    alive_hosts = _sample_hosts()
    mock_probe.return_value = alive_hosts

    capability = HttpProbeCapability(binary_path="httpx")
    context = Context(target_id="example.com", state={"hosts": _sample_hosts()})
    result = capability.execute(context)

    assert isinstance(result.data, list)
    assert all(isinstance(host, Host) for host in result.data)
    assert result.data[0].hostname == "www.example.com"
    assert result.data[0].address == IPv4Address("93.184.216.34")
