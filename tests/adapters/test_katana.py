"""Tests for KatanaAdapter."""

import json
from subprocess import CalledProcessError
from unittest.mock import MagicMock, patch

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.katana import (
    KatanaAdapter,
    KatanaExecutionError,
    KatanaNotFoundError,
    KatanaParseError,
)


def _sample_json_line(*, url: str = "https://www.example.com") -> str:
    return json.dumps({"url": url})


@patch("shutil.which")
def test_verify_binary_success(mock_which: MagicMock) -> None:
    """Test that binary verification succeeds when binary exists."""
    mock_which.return_value = "/usr/bin/katana"

    adapter = KatanaAdapter(binary_path="katana")
    adapter.verify_binary()

    mock_which.assert_called_once_with("katana")


@patch("shutil.which")
def test_verify_binary_not_found(mock_which: MagicMock) -> None:
    """Test that binary verification fails when binary does not exist."""
    mock_which.return_value = None

    adapter = KatanaAdapter(binary_path="katana")

    with pytest.raises(KatanaNotFoundError) as exc_info:
        adapter.verify_binary()

    assert "Katana binary not found" in str(exc_info.value)


@patch("subprocess.run")
@patch("shutil.which")
def test_crawl_hosts_success(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test successful web crawling."""
    mock_which.return_value = "/usr/bin/katana"
    mock_result = MagicMock()
    mock_result.stdout = "\n".join(
        [
            _sample_json_line(url="https://www.example.com"),
            _sample_json_line(url="https://www.example.com/about"),
            _sample_json_line(url="http://api.example.com"),
        ]
    )
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    adapter = KatanaAdapter(binary_path="katana")
    hosts = ["https://www.example.com", "http://api.example.com"]
    endpoints = adapter.crawl_hosts(hosts)

    assert len(endpoints) == 3
    assert endpoints[0].host == "www.example.com"
    assert endpoints[0].port == 443
    assert endpoints[0].protocol == "https"
    assert endpoints[0].path == "/"
    assert endpoints[1].host == "www.example.com"
    assert endpoints[1].port == 443
    assert endpoints[1].protocol == "https"
    assert endpoints[1].path == "/about"
    assert endpoints[2].host == "api.example.com"
    assert endpoints[2].port == 80
    assert endpoints[2].protocol == "http"

    mock_run.assert_called_once()


@patch("subprocess.run")
@patch("shutil.which")
def test_crawl_hosts_execution_failure(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test web crawling when Katana execution fails."""
    mock_which.return_value = "/usr/bin/katana"
    mock_error = CalledProcessError(1, "katana", stderr="Error occurred")
    mock_run.side_effect = mock_error

    adapter = KatanaAdapter(binary_path="katana")
    hosts = ["https://www.example.com"]

    with pytest.raises(KatanaExecutionError) as exc_info:
        adapter.crawl_hosts(hosts)

    assert exc_info.value.returncode == 1


@patch("subprocess.run")
@patch("shutil.which")
def test_crawl_hosts_malformed_json(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test web crawling when Katana returns malformed JSON."""
    mock_which.return_value = "/usr/bin/katana"
    mock_result = MagicMock()
    mock_result.stdout = "{not valid json"
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    adapter = KatanaAdapter(binary_path="katana")
    hosts = ["https://www.example.com"]

    with pytest.raises(KatanaParseError):
        adapter.crawl_hosts(hosts)


@patch("subprocess.run")
@patch("shutil.which")
def test_crawl_hosts_empty_output(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test web crawling with empty output."""
    mock_which.return_value = "/usr/bin/katana"
    mock_result = MagicMock()
    mock_result.stdout = ""
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    adapter = KatanaAdapter(binary_path="katana")
    hosts = ["https://www.example.com"]
    endpoints = adapter.crawl_hosts(hosts)

    assert endpoints == []


@patch("shutil.which")
def test_crawl_hosts_empty_input(mock_which: MagicMock) -> None:
    """Test web crawling with an empty host list skips subprocess execution."""
    adapter = KatanaAdapter(binary_path="katana")
    endpoints = adapter.crawl_hosts([])

    assert endpoints == []
    mock_which.assert_not_called()


@patch("subprocess.run")
@patch("shutil.which")
def test_crawl_hosts_duplicate_endpoints(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test that duplicate endpoints are deduplicated."""
    mock_which.return_value = "/usr/bin/katana"
    mock_result = MagicMock()
    mock_result.stdout = "\n".join(
        [
            _sample_json_line(url="https://www.example.com"),
            _sample_json_line(url="https://www.example.com"),
        ]
    )
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    adapter = KatanaAdapter(binary_path="katana")
    hosts = ["https://www.example.com"]
    endpoints = adapter.crawl_hosts(hosts)

    assert len(endpoints) == 1


@patch("subprocess.run")
@patch("shutil.which")
def test_crawl_hosts_url_parsing_with_port(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test URL parsing with custom port."""
    mock_which.return_value = "/usr/bin/katana"
    mock_result = MagicMock()
    mock_result.stdout = _sample_json_line(url="https://www.example.com:8443")
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    adapter = KatanaAdapter(binary_path="katana")
    hosts = ["https://www.example.com:8443"]
    endpoints = adapter.crawl_hosts(hosts)

    assert len(endpoints) == 1
    assert endpoints[0].host == "www.example.com"
    assert endpoints[0].port == 8443
    assert endpoints[0].protocol == "https"
