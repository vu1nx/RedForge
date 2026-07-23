"""Tests for HttpxAdapter."""

import json
from ipaddress import IPv4Address
from subprocess import CalledProcessError
from unittest.mock import MagicMock, patch

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.httpx import (
    HttpxAdapter,
    HttpxExecutionError,
    HttpxNotFoundError,
    HttpxParseError,
)
from redforge.domain.host import Host


def _sample_json_line(
    *,
    input_host: str = "www.example.com",
    host_ip: str = "93.184.216.34",
    failed: bool = False,
) -> str:
    return json.dumps(
        {
            "url": f"https://{input_host}",
            "input": input_host,
            "host": host_ip,
            "host_ip": host_ip,
            "port": "443",
            "scheme": "https",
            "status_code": 200,
            "failed": failed,
        }
    )


@patch("shutil.which")
def test_verify_binary_success(mock_which: MagicMock) -> None:
    """Test that binary verification succeeds when binary exists."""
    mock_which.return_value = "/usr/bin/httpx"

    adapter = HttpxAdapter(binary_path="httpx")
    adapter.verify_binary()

    mock_which.assert_called_once_with("httpx")


@patch("shutil.which")
def test_verify_binary_not_found(mock_which: MagicMock) -> None:
    """Test that binary verification fails when binary does not exist."""
    mock_which.return_value = None

    adapter = HttpxAdapter(binary_path="httpx")

    with pytest.raises(HttpxNotFoundError) as exc_info:
        adapter.verify_binary()

    assert "httpx binary not found" in str(exc_info.value)


@patch("subprocess.run")
@patch("shutil.which")
def test_probe_hosts_success(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test successful HTTP probing."""
    mock_which.return_value = "/usr/bin/httpx"
    mock_result = MagicMock()
    mock_result.stdout = "\n".join(
        [
            _sample_json_line(input_host="www.example.com", host_ip="93.184.216.34"),
            _sample_json_line(input_host="api.example.com", host_ip="93.184.216.35"),
        ]
    )
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    adapter = HttpxAdapter(binary_path="httpx")
    hosts = [
        Host(address=IPv4Address("93.184.216.34"), hostname="www.example.com"),
        Host(address=IPv4Address("93.184.216.35"), hostname="api.example.com"),
    ]
    alive_hosts = adapter.probe_hosts(hosts)

    assert len(alive_hosts) == 2
    assert alive_hosts[0].hostname == "www.example.com"
    assert alive_hosts[0].address == IPv4Address("93.184.216.34")
    assert alive_hosts[1].hostname == "api.example.com"
    assert alive_hosts[1].address == IPv4Address("93.184.216.35")

    mock_run.assert_called_once_with(
        ["httpx", "-l", "-", "-json", "-silent", "-ip"],
        input="www.example.com\napi.example.com",
        capture_output=True,
        text=True,
        check=True,
    )


@patch("subprocess.run")
@patch("shutil.which")
def test_probe_hosts_execution_failure(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test HTTP probing when httpx execution fails."""
    mock_which.return_value = "/usr/bin/httpx"
    mock_error = CalledProcessError(1, "httpx", stderr="Error occurred")
    mock_run.side_effect = mock_error

    adapter = HttpxAdapter(binary_path="httpx")
    hosts = [Host(address=IPv4Address("93.184.216.34"), hostname="www.example.com")]

    with pytest.raises(HttpxExecutionError) as exc_info:
        adapter.probe_hosts(hosts)

    assert exc_info.value.returncode == 1


@patch("subprocess.run")
@patch("shutil.which")
def test_probe_hosts_malformed_json(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test HTTP probing when httpx returns malformed JSON."""
    mock_which.return_value = "/usr/bin/httpx"
    mock_result = MagicMock()
    mock_result.stdout = "{not valid json"
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    adapter = HttpxAdapter(binary_path="httpx")
    hosts = [Host(address=IPv4Address("93.184.216.34"), hostname="www.example.com")]

    with pytest.raises(HttpxParseError):
        adapter.probe_hosts(hosts)


@patch("subprocess.run")
@patch("shutil.which")
def test_probe_hosts_empty_output(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test HTTP probing with empty output."""
    mock_which.return_value = "/usr/bin/httpx"
    mock_result = MagicMock()
    mock_result.stdout = ""
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    adapter = HttpxAdapter(binary_path="httpx")
    hosts = [Host(address=IPv4Address("93.184.216.34"), hostname="www.example.com")]
    alive_hosts = adapter.probe_hosts(hosts)

    assert alive_hosts == []


@patch("shutil.which")
def test_probe_hosts_empty_input(mock_which: MagicMock) -> None:
    """Test HTTP probing with an empty host list skips subprocess execution."""
    adapter = HttpxAdapter(binary_path="httpx")
    alive_hosts = adapter.probe_hosts([])

    assert alive_hosts == []
    mock_which.assert_not_called()
