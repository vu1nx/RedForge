"""Tests for the tool-agnostic Subdomain Discovery capability."""

from dataclasses import dataclass

import pytest  # type: ignore[reportMissingImports]

from redforge.capabilities.subdomain_discovery import SubdomainDiscovery
from redforge.sdk import (
    Context,
    SubdomainDiscoveryResult,
    SubdomainDiscoveryStatus,
)
from redforge.sdk.result import Status


@dataclass
class FakeProvider:
    response: object
    calls: int = 0
    target: str | None = None

    def discover(self, domain: str) -> SubdomainDiscoveryResult:
        self.calls += 1
        self.target = domain
        if isinstance(self.response, Exception):
            raise self.response
        return self.response  # type: ignore[return-value]


def test_success_normalizes_duplicates_and_maps_provider_once() -> None:
    provider = FakeProvider(
        SubdomainDiscoveryResult(
            hostnames=(
                "www.example.com",
                "api.example.com",
                "www.example.com",
            )
        )
    )

    result = SubdomainDiscovery(provider=provider).execute(
        Context(target_id="example.com")
    )

    assert provider.calls == 1
    assert provider.target == "example.com"
    assert result.status is Status.SUCCESS
    assert result.data.hostnames == (
        "api.example.com",
        "www.example.com",
    )
    assert result.metadata["count"] == 2


def test_empty_provider_success_remains_success() -> None:
    result = SubdomainDiscovery(
        provider=FakeProvider(SubdomainDiscoveryResult())
    ).execute(Context(target_id="example.com"))

    assert result.status is Status.SUCCESS
    assert result.data.hostnames == ()


def test_partial_with_findings_publishes_usable_data() -> None:
    result = SubdomainDiscovery(
        provider=FakeProvider(
            SubdomainDiscoveryResult(
                hostnames=("api.example.com",),
                status=SubdomainDiscoveryStatus.PARTIAL,
                message="Provider returned partial findings.",
            )
        )
    ).execute(Context(target_id="example.com"))

    assert result.status is Status.PARTIAL
    assert result.data.hostnames == ("api.example.com",)
    assert result.errors == ["Provider returned partial findings."]


def test_partial_without_findings_becomes_failure() -> None:
    result = SubdomainDiscovery(
        provider=FakeProvider(
            SubdomainDiscoveryResult(
                status=SubdomainDiscoveryStatus.PARTIAL,
                message="Provider timed out.",
            )
        )
    ).execute(Context(target_id="example.com"))

    assert result.status is Status.FAILURE
    assert result.data.hostnames == ()


@pytest.mark.parametrize(
    ("provider_status", "capability_status"),
    (
        (SubdomainDiscoveryStatus.FAILURE, Status.FAILURE),
        (SubdomainDiscoveryStatus.ERROR, Status.ERROR),
        (SubdomainDiscoveryStatus.UNAVAILABLE, Status.ERROR),
    ),
)
def test_non_usable_provider_statuses_publish_no_usable_result(
    provider_status: SubdomainDiscoveryStatus,
    capability_status: Status,
) -> None:
    result = SubdomainDiscovery(
        provider=FakeProvider(
            SubdomainDiscoveryResult(
                status=provider_status,
                message="Sanitized provider failure.",
            )
        )
    ).execute(Context(target_id="example.com"))

    assert result.status is capability_status
    assert result.data.hostnames == ()
    assert result.errors == ["Sanitized provider failure."]


@pytest.mark.parametrize("invalid", [None, {}, "invalid"])
def test_invalid_provider_returns_are_sanitized_errors(invalid: object) -> None:
    result = SubdomainDiscovery(provider=FakeProvider(invalid)).execute(
        Context(target_id="example.com")
    )

    assert result.status is Status.ERROR
    assert result.errors == ["Subdomain provider returned an invalid result"]


def test_unexpected_provider_exception_is_sanitized_error() -> None:
    result = SubdomainDiscovery(
        provider=FakeProvider(RuntimeError("/home/user/private/provider"))
    ).execute(Context(target_id="example.com"))

    assert result.status is Status.ERROR
    assert "private" not in repr(result)


def test_manual_default_is_safe_unavailable_without_tool_execution() -> None:
    result = SubdomainDiscovery().execute(Context(target_id="example.com"))

    assert result.status is Status.ERROR
    assert result.data.status is SubdomainDiscoveryStatus.UNAVAILABLE


def test_name_remains_capability_identity() -> None:
    assert SubdomainDiscovery().name == "subdomain_discovery"
