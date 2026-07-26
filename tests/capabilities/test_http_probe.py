"""Tests for the tool-agnostic HTTP probe capability."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import cast

import pytest  # type: ignore[reportMissingImports]

from redforge.capabilities.http_probe import HttpProbeCapability
from redforge.domain.host import Host, HostResolution
from redforge.domain.http_probe import HttpProbeEndpoint
from redforge.runtime.pipeline import Pipeline
from redforge.sdk import Capability, Context, PipelineStateKey, Result, Status
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


class RecordingDownstream(Capability):
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, context: Context) -> Result[None]:
        assert context.has(PipelineStateKey.ALIVE_HOSTS)
        assert context.has(PipelineStateKey.HTTP_ENDPOINTS)
        self.calls += 1
        return Result(status=Status.SUCCESS, data=None)

    @property
    def name(self) -> str:
        return "recording_downstream"


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


def _endpoint(
    url: str,
    *,
    hostname: str,
    scheme: str = "https",
    port: int = 443,
    ip_address: str | None = None,
    status_code: int = 200,
) -> HttpProbeEndpoint:
    return HttpProbeEndpoint(
        url=url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        status_code=status_code,
        ip_address=ip_address,
    )


def _published(result: Result[object], key: PipelineStateKey) -> object:
    return next(
        item.value for item in result.publications if item.key is key
    )


def test_success_calls_provider_once_and_publishes_both_immutable_states() -> None:
    https = _endpoint(
        "https://www.example.com",
        hostname="www.example.com",
        ip_address="192.0.2.1",
    )
    http = _endpoint(
        "http://www.example.com",
        hostname="www.example.com",
        scheme="http",
        port=80,
        ip_address="192.0.2.1",
    )
    provider = FakeProvider(
        HttpProbeProviderResult(
            endpoints=(https, http),
            responsive_hosts=tuple(reversed(_hosts())),
        ),
        [],
    )

    result = HttpProbeCapability(provider=provider).execute(_context())

    assert result.status is Status.SUCCESS
    assert provider.calls == [_hosts()]
    assert result.data is None
    assert _published(result, PipelineStateKey.ALIVE_HOSTS) == (_hosts()[0],)
    assert _published(result, PipelineStateKey.HTTP_ENDPOINTS) == (http, https)
    assert len(result.publications) == 2


def test_empty_host_state_skips_provider_and_publishes_both_empty_tuples() -> None:
    provider = FakeProvider(HttpProbeProviderResult(), [])

    result = HttpProbeCapability(provider=provider).execute(_context(()))

    assert result.status is Status.SUCCESS
    assert result.data is None
    assert tuple(item.value for item in result.publications) == ((), ())
    assert provider.calls == []


def test_untyped_host_state_preserves_manual_compatibility_path() -> None:
    provider = FakeProvider(HttpProbeProviderResult(), [])
    context = Context(
        target_id="example.com",
        state={PipelineStateKey.HOSTS: ["unvalidated.example.com"]},
    )

    result = HttpProbeCapability(provider=provider).execute(context)

    assert result.status is Status.SUCCESS
    assert tuple(item.value for item in result.publications) == ((), ())
    assert provider.calls == []


def test_partial_with_endpoints_publishes_both_and_continues() -> None:
    endpoint = _endpoint(
        "https://www.example.com",
        hostname="www.example.com",
        ip_address="192.0.2.1",
    )
    provider = FakeProvider(
        HttpProbeProviderResult(
            endpoints=(endpoint,),
            responsive_hosts=(_hosts()[0],),
            status=HttpProbeProviderStatus.PARTIAL,
            message="HTTPX output contained incomplete or rejected records.",
        ),
        [],
    )

    result = HttpProbeCapability(provider=provider).execute(_context())

    assert result.status is Status.PARTIAL
    assert _published(result, PipelineStateKey.ALIVE_HOSTS) == (_hosts()[0],)
    assert _published(result, PipelineStateKey.HTTP_ENDPOINTS) == (endpoint,)


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
    assert result.data is None
    assert result.publications == ()


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
    assert result.data is None
    assert result.publications == ()


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


def test_multiple_host_kinds_are_derived_and_sorted_deterministically() -> None:
    hosts = (
        Host(address=IPv6Address("2001:db8::10")),
        Host(address=IPv4Address("192.0.2.10")),
        Host(hostname="www.example.com"),
        Host(hostname="api.example.com"),
    )
    endpoints = (
        _endpoint(
            "https://[2001:db8::10]",
            hostname="2001:db8::10",
            ip_address="2001:db8::10",
        ),
        _endpoint(
            "https://www.example.com",
            hostname="www.example.com",
        ),
        _endpoint(
            "https://192.0.2.10",
            hostname="192.0.2.10",
            ip_address="192.0.2.10",
        ),
        _endpoint(
            "https://api.example.com",
            hostname="api.example.com",
        ),
    )
    result = HttpProbeCapability(
        provider=FakeProvider(HttpProbeProviderResult(endpoints=endpoints), [])
    ).execute(_context(hosts))

    alive = cast(
        tuple[Host, ...],
        _published(result, PipelineStateKey.ALIVE_HOSTS),
    )
    assert tuple(host.hostname for host in alive) == (
        None,
        None,
        "api.example.com",
        "www.example.com",
    )
    assert tuple(
        host.addresses[0].value for host in alive[:2]
    ) == ("192.0.2.10", "2001:db8::10")
    assert _published(result, PipelineStateKey.HTTP_ENDPOINTS) == tuple(
        sorted(endpoints, key=lambda item: (item.scheme, item.hostname, item.port))
    )


def test_conflicting_duplicate_endpoint_evidence_is_rejected() -> None:
    first = _endpoint(
        "https://www.example.com",
        hostname="www.example.com",
        status_code=200,
    )
    conflicting = _endpoint(
        "https://www.example.com",
        hostname="www.example.com",
        status_code=404,
    )

    result = HttpProbeCapability(
        provider=FakeProvider(
            HttpProbeProviderResult(endpoints=(first, conflicting)),
            [],
        )
    ).execute(_context())

    assert result.status is Status.ERROR
    assert result.publications == ()
    assert result.errors == [
        "HTTP probe provider returned invalid endpoint evidence"
    ]


def test_manual_pipeline_publishes_both_outputs_with_one_history_entry() -> None:
    endpoint = _endpoint(
        "https://www.example.com",
        hostname="www.example.com",
        ip_address="192.0.2.1",
    )
    provider = FakeProvider(
        HttpProbeProviderResult(endpoints=(endpoint,)),
        [],
    )
    pipeline = Pipeline()
    pipeline.add(HttpProbeCapability(provider=provider))
    context = _context()

    result = pipeline.run(context)

    assert result.status is Status.SUCCESS
    assert provider.calls == [_hosts()]
    assert result.context.get(PipelineStateKey.ALIVE_HOSTS) == (_hosts()[0],)
    assert result.context.get(PipelineStateKey.HTTP_ENDPOINTS) == (endpoint,)
    assert len(result.executions) == 1
    assert result.executions[0].capability_name == "http_probe"


def test_partial_publication_continues_to_downstream_once() -> None:
    endpoint = _endpoint(
        "https://www.example.com",
        hostname="www.example.com",
        ip_address="192.0.2.1",
    )
    provider = FakeProvider(
        HttpProbeProviderResult(
            endpoints=(endpoint,),
            status=HttpProbeProviderStatus.PARTIAL,
            message="HTTP probing timed out with partial findings.",
        ),
        [],
    )
    downstream = RecordingDownstream()
    pipeline = Pipeline()
    pipeline.add(HttpProbeCapability(provider=provider))
    pipeline.add(downstream)

    result = pipeline.run(_context())

    assert result.status is Status.PARTIAL
    assert provider.calls == [_hosts()]
    assert downstream.calls == 1
    assert len(result.executions) == 2
    assert result.executions[0].result.status is Status.PARTIAL
