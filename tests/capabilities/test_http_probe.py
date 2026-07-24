"""Tests for the typed HTTP Probe boundary."""

from dataclasses import dataclass
from ipaddress import IPv4Address

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.errors import AdapterUnavailableError
from redforge.adapters.httpx import HttpProbeAdapterResult
from redforge.capabilities.http_probe import HttpProbeCapability
from redforge.domain.host import Host, HostResolution
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.context import Context
from redforge.sdk.result import Status


@dataclass
class FakeTransport:
    response: object
    calls: list[tuple[Host, ...]]

    def probe(self, hosts: tuple[Host, ...]) -> HttpProbeAdapterResult:
        self.calls.append(hosts)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response  # type: ignore[return-value]


def _hosts() -> tuple[Host, ...]:
    return (
        Host(address=IPv4Address("192.0.2.1"), hostname="www.example.com"),
        Host(address=IPv4Address("192.0.2.2"), hostname="api.example.com"),
    )


def _context() -> Context:
    return Context(
        target_id="example.com",
        state={
            PipelineStateKey.HOSTS: HostResolution(hosts=_hosts()),
        },
    )


def test_capability_uses_typed_transport_and_deterministic_hosts() -> None:
    transport = FakeTransport(
        HttpProbeAdapterResult(hosts=tuple(reversed(_hosts()))),
        [],
    )

    result = HttpProbeCapability(transport=transport).execute(_context())

    assert result.status == Status.SUCCESS
    assert transport.calls == [_hosts()]
    assert [host.hostname for host in result.data] == [
        "api.example.com",
        "www.example.com",
    ]


def test_empty_or_untyped_host_state_skips_transport() -> None:
    transport = FakeTransport(HttpProbeAdapterResult(), [])
    capability = HttpProbeCapability(transport=transport)

    empty = capability.execute(
        Context(
            target_id="example.com",
            state={PipelineStateKey.HOSTS: HostResolution()},
        )
    )
    untyped = capability.execute(
        Context(
            target_id="example.com",
            state={PipelineStateKey.HOSTS: ["unvalidated.example.com"]},
        )
    )

    assert empty.status == untyped.status == Status.SUCCESS
    assert empty.data == untyped.data == []
    assert transport.calls == []


def test_expected_transport_failure_is_sanitized_failure() -> None:
    transport = FakeTransport(
        AdapterUnavailableError(
            "Authorization: Bearer hidden-token C:\\private\\provider"
        ),
        [],
    )

    result = HttpProbeCapability(transport=transport).execute(_context())

    assert result.status == Status.FAILURE
    assert "hidden-token" not in repr(result)
    assert "private" not in repr(result)


@pytest.mark.parametrize("invalid", [None, {}, "invalid"])
def test_invalid_transport_returns_are_sanitized_errors(invalid: object) -> None:
    result = HttpProbeCapability(
        transport=FakeTransport(invalid, [])
    ).execute(_context())

    assert result.status == Status.ERROR
    assert result.errors == ["HTTP probe adapter returned an invalid result"]


def test_unexpected_transport_exception_is_sanitized_error() -> None:
    result = HttpProbeCapability(
        transport=FakeTransport(
            RuntimeError("https://user:password@example.com"),
            [],
        )
    ).execute(_context())

    assert result.status == Status.ERROR
    assert "password" not in repr(result)


def test_name() -> None:
    assert HttpProbeCapability(
        transport=FakeTransport(HttpProbeAdapterResult(), [])
    ).name == "http_probe"
