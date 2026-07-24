"""Tests for the typed Subdomain Discovery boundary."""

from dataclasses import dataclass

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.errors import AdapterUnavailableError
from redforge.adapters.subfinder import SubdomainDiscoveryResult
from redforge.capabilities.subdomain_discovery import SubdomainDiscovery
from redforge.sdk.context import Context
from redforge.sdk.result import Status


@dataclass
class FakeProvider:
    response: object

    def discover(self, domain: str) -> SubdomainDiscoveryResult:  # noqa: ARG002
        if isinstance(self.response, Exception):
            raise self.response
        return self.response  # type: ignore[return-value]


def test_provider_order_and_duplicates_are_normalized_deterministically() -> None:
    provider = FakeProvider(
        SubdomainDiscoveryResult(
            hostnames=("www.example.com", "api.example.com", "www.example.com")
        )
    )

    result = SubdomainDiscovery(provider=provider).execute(
        Context(target_id="example.com")
    )

    assert result.status == Status.SUCCESS
    assert result.data == SubdomainDiscoveryResult(
        hostnames=("api.example.com", "www.example.com")
    )
    assert result.metadata == {"count": 2, "target_id": "example.com"}


def test_empty_provider_result_is_success() -> None:
    result = SubdomainDiscovery(
        provider=FakeProvider(SubdomainDiscoveryResult())
    ).execute(Context(target_id="example.com"))

    assert result.status == Status.SUCCESS
    assert result.data == SubdomainDiscoveryResult()


def test_expected_provider_failure_is_sanitized_failure() -> None:
    result = SubdomainDiscovery(
        provider=FakeProvider(
            AdapterUnavailableError(
                "api-key=super-secret-token C:\\private\\provider"
            )
        )
    ).execute(Context(target_id="example.com"))

    assert result.status == Status.FAILURE
    assert result.data == SubdomainDiscoveryResult()
    assert result.errors == ["Subdomain provider is unavailable"]
    assert "secret" not in repr(result)
    assert "private" not in repr(result)


@pytest.mark.parametrize("invalid", [None, {}, "invalid"])
def test_invalid_provider_returns_are_sanitized_errors(invalid: object) -> None:
    result = SubdomainDiscovery(provider=FakeProvider(invalid)).execute(
        Context(target_id="example.com")
    )

    assert result.status == Status.ERROR
    assert result.data == SubdomainDiscoveryResult()
    assert result.errors == ["Subdomain provider returned an invalid result"]


def test_unexpected_provider_exception_is_sanitized_error() -> None:
    result = SubdomainDiscovery(
        provider=FakeProvider(RuntimeError("/home/user/private/provider"))
    ).execute(Context(target_id="example.com"))

    assert result.status == Status.ERROR
    assert "private" not in repr(result)


def test_name() -> None:
    assert SubdomainDiscovery(provider=FakeProvider(SubdomainDiscoveryResult())).name == (
        "subdomain_discovery"
    )
