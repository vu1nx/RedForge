"""Tests for the tool-agnostic HTTP probe capability."""

from dataclasses import dataclass
from ipaddress import IPv4Address

import pytest  # type: ignore[reportMissingImports]

from redforge.capabilities.http_probe import HttpProbeCapability
from redforge.domain.host import Host, HostResolution
from redforge.sdk import Context, PipelineStateKey, Status
from redforge.sdk.http_probe import (
    HttpProbeProviderResult,
    HttpProbeProviderStatus,
)


@dataclass
class FakeProvider:
    response: object
    calls: list[tuple[Host, ...]]

    def probe(self, hosts: tuple[Host, ...]) -> HttpProbeProviderResult:
        self.calls.append(hosts)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response  # type: ignore[return-value]


def _hosts() -> tuple[Host, ...]:
    return (
        Host(address=IPv4Address("192.0.2.1"), hostname="www.example.com"),
        Host(address=IPv4Address("192.0.2.2"), hostname="api.example.com"),
    )


def _context(hosts: tuple[Host, ...] | None = None) -> Context:
    return Context(
        target_id="example.com",
        state={
            PipelineStateKey.HOSTS: HostResolution(
                hosts=_hosts() if hosts is None else hosts
            ),
        },
    )


def test_success_calls_provider_once_and_publishes_immutable_hosts() -> None:
    provider = FakeProvider(
        HttpProbeProviderResult(
            responsive_hosts=tuple(reversed(_hosts())),
        ),
        [],
    )

    result = HttpProbeCapability(provider=provider).execute(_context())

    assert result.status is Status.SUCCESS
    assert provider.calls == [_hosts()]
    assert isinstance(result.data, tuple)
    assert tuple(host.hostname for host in result.data) == (
        "api.example.com",
        "www.example.com",
    )


def test_empty_host_state_skips_provider_and_publishes_empty_tuple() -> None:
    provider = FakeProvider(HttpProbeProviderResult(), [])

    result = HttpProbeCapability(provider=provider).execute(_context(()))

    assert result.status is Status.SUCCESS
    assert result.data == ()
    assert provider.calls == []


def test_untyped_host_state_preserves_manual_compatibility_path() -> None:
    provider = FakeProvider(HttpProbeProviderResult(), [])
    context = Context(
        target_id="example.com",
        state={PipelineStateKey.HOSTS: ["unvalidated.example.com"]},
    )

    result = HttpProbeCapability(provider=provider).execute(context)

    assert result.status is Status.SUCCESS
    assert result.data == ()
    assert provider.calls == []


def test_partial_with_hosts_publishes_and_continues() -> None:
    provider = FakeProvider(
        HttpProbeProviderResult(
            responsive_hosts=(_hosts()[0],),
            status=HttpProbeProviderStatus.PARTIAL,
            message="HTTPX output contained incomplete or rejected records.",
        ),
        [],
    )

    result = HttpProbeCapability(provider=provider).execute(_context())

    assert result.status is Status.PARTIAL
    assert result.data == (_hosts()[0],)


def test_partial_without_hosts_is_failure() -> None:
    result = HttpProbeCapability(
        provider=FakeProvider(
            HttpProbeProviderResult(
                status=HttpProbeProviderStatus.PARTIAL,
                message="HTTP probing completed partially.",
            ),
            [],
        )
    ).execute(_context())

    assert result.status is Status.FAILURE
    assert result.data == ()


@pytest.mark.parametrize(
    ("provider_status", "capability_status"),
    (
        (HttpProbeProviderStatus.FAILURE, Status.FAILURE),
        (HttpProbeProviderStatus.UNAVAILABLE, Status.ERROR),
        (HttpProbeProviderStatus.ERROR, Status.ERROR),
    ),
)
def test_non_publishable_provider_statuses(
    provider_status: HttpProbeProviderStatus,
    capability_status: Status,
) -> None:
    result = HttpProbeCapability(
        provider=FakeProvider(
            HttpProbeProviderResult(
                status=provider_status,
                message="HTTP probe provider failed.",
            ),
            [],
        )
    ).execute(_context())

    assert result.status is capability_status
    assert result.data == ()


@pytest.mark.parametrize("invalid", (None, {}, "invalid"))
def test_invalid_provider_returns_are_sanitized_errors(invalid: object) -> None:
    result = HttpProbeCapability(
        provider=FakeProvider(invalid, [])
    ).execute(_context())

    assert result.status is Status.ERROR
    assert result.errors == ["HTTP probe provider returned an invalid result"]


def test_unexpected_provider_exception_is_sanitized() -> None:
    result = HttpProbeCapability(
        provider=FakeProvider(
            RuntimeError("Authorization: Bearer secret C:\\private\\httpx"),
            [],
        )
    ).execute(_context())

    assert result.status is Status.ERROR
    assert "Bearer" not in repr(result)
    assert "private" not in repr(result)


def test_manual_default_is_safe_and_reports_unavailable() -> None:
    result = HttpProbeCapability().execute(_context())

    assert result.status is Status.ERROR
    assert result.errors == ["HTTP probe provider is unavailable."]


def test_capability_identity_is_unchanged() -> None:
    assert HttpProbeCapability().name == "http_probe"
