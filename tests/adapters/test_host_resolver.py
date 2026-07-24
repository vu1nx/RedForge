"""Tests for the standard-library host resolver adapter."""

import socket
from unittest.mock import MagicMock, patch

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.host_resolver import HostResolverError, StandardHostResolver


def _record(family: int, value: str) -> tuple[int, int, int, str, tuple[str, int]]:
    return (family, socket.SOCK_STREAM, 6, "", (value, 0))


@patch("socket.getaddrinfo")
def test_resolver_canonicalizes_deduplicates_and_sorts(mock_getaddrinfo: MagicMock) -> None:
    mock_getaddrinfo.return_value = [
        _record(socket.AF_INET6, "2001:0db8::1"),
        _record(socket.AF_INET, "192.0.2.2"),
        _record(socket.AF_INET, "192.0.2.1"),
        _record(socket.AF_INET6, "2001:db8::1"),
    ]

    result = StandardHostResolver().resolve("example.com")

    assert result == ("192.0.2.1", "192.0.2.2", "2001:db8::1")
    mock_getaddrinfo.assert_called_once_with(
        "example.com",
        None,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
    )


@patch("socket.getaddrinfo")
def test_resolver_ignores_malformed_records_when_valid_remain(
    mock_getaddrinfo: MagicMock,
) -> None:
    mock_getaddrinfo.return_value = [
        _record(socket.AF_INET, "malformed"),
        _record(socket.AF_INET, "192.0.2.1"),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ()),  # type: ignore[list-item]
    ]

    assert StandardHostResolver().resolve("example.com") == ("192.0.2.1",)


@patch("socket.getaddrinfo")
def test_expected_dns_failure_is_sanitized(mock_getaddrinfo: MagicMock) -> None:
    mock_getaddrinfo.side_effect = socket.gaierror("secret resolver detail")

    with pytest.raises(HostResolverError) as error:
        StandardHostResolver().resolve("example.invalid")

    assert str(error.value) == "hostname resolution failed"
    assert "secret" not in str(error.value)


@patch("socket.getaddrinfo")
def test_no_valid_addresses_is_expected_resolution_failure(
    mock_getaddrinfo: MagicMock,
) -> None:
    mock_getaddrinfo.return_value = [_record(socket.AF_INET, "malformed")]

    with pytest.raises(HostResolverError):
        StandardHostResolver().resolve("example.com")
