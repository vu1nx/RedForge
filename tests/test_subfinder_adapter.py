"""Tests for SubfinderAdapter."""

from unittest.mock import MagicMock, patch

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.subfinder import (
    SubfinderAdapter,
    SubfinderExecutionError,
    SubfinderNotFoundError,
)


@patch("shutil.which")
def test_verify_binary_success(mock_which: MagicMock) -> None:
    """Test that binary verification succeeds when binary exists."""
    mock_which.return_value = "/usr/bin/subfinder"

    adapter = SubfinderAdapter(binary_path="subfinder")
    adapter.verify_binary()

    mock_which.assert_called_once_with("subfinder")


@patch("shutil.which")
def test_verify_binary_not_found(mock_which: MagicMock) -> None:
    """Test that binary verification fails when binary does not exist."""
    mock_which.return_value = None

    adapter = SubfinderAdapter(binary_path="subfinder")

    with pytest.raises(SubfinderNotFoundError) as exc_info:
        adapter.verify_binary()

    assert "Subfinder binary not found" in str(exc_info.value)


@patch("subprocess.run")
@patch("shutil.which")
def test_discover_subdomains_success(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test successful subdomain discovery."""
    mock_which.return_value = "/usr/bin/subfinder"
    mock_result = MagicMock()
    mock_result.stdout = "www.example.com\napi.example.com\nadmin.example.com\n"
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    adapter = SubfinderAdapter(binary_path="subfinder")
    subdomains = adapter.discover_subdomains("example.com")

    assert len(subdomains) == 3
    assert "www.example.com" in subdomains
    assert "api.example.com" in subdomains
    assert "admin.example.com" in subdomains

    mock_run.assert_called_once_with(
        ["subfinder", "-d", "example.com", "-silent"],
        capture_output=True,
        text=True,
        check=True,
    )


@patch("subprocess.run")
@patch("shutil.which")
def test_discover_subdomains_empty_output(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test subdomain discovery with empty output."""
    mock_which.return_value = "/usr/bin/subfinder"
    mock_result = MagicMock()
    mock_result.stdout = ""
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    adapter = SubfinderAdapter(binary_path="subfinder")
    subdomains = adapter.discover_subdomains("example.com")

    assert len(subdomains) == 0


@patch("subprocess.run")
@patch("shutil.which")
def test_discover_subdomains_execution_failure(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test subdomain discovery when Subfinder execution fails."""
    from subprocess import CalledProcessError

    mock_which.return_value = "/usr/bin/subfinder"
    mock_error = CalledProcessError(1, "subfinder", stderr="Error occurred")
    mock_run.side_effect = mock_error

    adapter = SubfinderAdapter(binary_path="subfinder")

    with pytest.raises(SubfinderExecutionError):
        adapter.discover_subdomains("example.com")


@patch("subprocess.run")
@patch("shutil.which")
def test_discover_subdomains_non_zero_exit(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test subdomain discovery when Subfinder returns non-zero exit code."""
    from subprocess import CalledProcessError

    mock_which.return_value = "/usr/bin/subfinder"
    mock_error = CalledProcessError(2, "subfinder", stderr="Command failed")
    mock_run.side_effect = mock_error

    adapter = SubfinderAdapter(binary_path="subfinder")

    with pytest.raises(SubfinderExecutionError) as exc_info:
        adapter.discover_subdomains("example.com")

    assert exc_info.value.returncode == 2


@patch("subprocess.run")
@patch("shutil.which")
def test_discover_subdomains_with_whitespace(mock_which: MagicMock, mock_run: MagicMock) -> None:
    """Test subdomain discovery with whitespace in output."""
    mock_which.return_value = "/usr/bin/subfinder"
    mock_result = MagicMock()
    mock_result.stdout = "  www.example.com  \n\n  api.example.com  \n"
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    adapter = SubfinderAdapter(binary_path="subfinder")
    subdomains = adapter.discover_subdomains("example.com")

    assert len(subdomains) == 2
    assert subdomains == ["www.example.com", "api.example.com"]
