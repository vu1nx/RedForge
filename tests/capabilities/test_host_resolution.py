"""Tests for deterministic Host Resolution."""

from dataclasses import dataclass, field
from typing import cast

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.host_resolver import HostResolverError
from redforge.capabilities.host_resolution import (
    HostResolutionCapability,
    normalize_hostname,
)
from redforge.domain.host import HostResolution, IPVersion
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.context import Context
from redforge.sdk.result import Status
from redforge.sdk.subdomain_discovery import SubdomainDiscoveryResult


@dataclass
class FakeResolver:
    responses: dict[str, tuple[str, ...] | Exception]
    calls: list[str] = field(default_factory=lambda: list[str]())

    def resolve(self, hostname: str) -> tuple[str, ...]:
        self.calls.append(hostname)
        response = self.responses[hostname]
        if isinstance(response, Exception):
            raise response
        return response


def _execute(
    resolver: FakeResolver,
    subdomains: object = ...,
):
    state: dict[str, object] = {}
    if subdomains is not ...:
        if isinstance(subdomains, dict):
            values = cast(dict[str, object], subdomains).get("subdomains", [])
            if not isinstance(values, list):
                values = []
            subdomains = SubdomainDiscoveryResult(
                hostnames=tuple(values)  # type: ignore[arg-type]
            )
        state[PipelineStateKey.SUBDOMAINS] = subdomains
    return HostResolutionCapability(resolver).execute(
        Context(target_id="example.com", state=state)
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (" Example.COM. ", "example.com"),
        ("BÜCHER.example", "xn--bcher-kva.example"),
        ("a-b.example", "a-b.example"),
    ],
)
def test_hostname_normalization(value: str, expected: str) -> None:
    assert normalize_hostname(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "https://example.com",
        "example.com/path",
        "example.com?query",
        "example.com#fragment",
        "example.com:443",
        "a..example",
        "-bad.example",
        "bad-.example",
        f"{'a' * 64}.example",
        ".".join(["a" * 63] * 5),
        "\ud800.example",
    ],
)
def test_hostname_normalization_rejects_invalid_inputs(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_hostname(value)


def test_missing_wrong_and_empty_inputs_are_distinct() -> None:
    resolver = FakeResolver({})

    missing = _execute(resolver)
    wrong = _execute(resolver, ["example.com"])
    empty = _execute(resolver, {"subdomains": []})

    assert missing.status == Status.FAILURE
    assert missing.data == HostResolution()
    assert missing.metadata["missing_prerequisite"] == PipelineStateKey.SUBDOMAINS
    assert wrong.status == Status.ERROR
    assert wrong.data == HostResolution()
    assert empty.status == Status.SUCCESS
    assert empty.data == HostResolution()


def test_success_mixed_families_deduplication_and_evidence() -> None:
    resolver = FakeResolver(
        {
            "example.com": (
                "2001:0db8::1",
                "192.0.2.1",
                "192.0.2.1",
            )
        }
    )

    result = _execute(
        resolver,
        {"subdomains": ["EXAMPLE.COM", "example.com.", " example.com "]},
    )

    assert result.status == Status.SUCCESS
    assert resolver.calls == ["example.com"]
    assert len(result.data.hosts) == 1
    host = result.data.hosts[0]
    assert host.hostname == "example.com"
    assert [(item.version, item.value) for item in host.addresses] == [
        (IPVersion.IPV4, "192.0.2.1"),
        (IPVersion.IPV6, "2001:db8::1"),
    ]
    assert host.evidence == (
        "hostname-input:example.com",
        "resolved-address:192.0.2.1",
        "resolved-address:2001:db8::1",
    )


def test_mixed_success_invalid_unresolved_and_malformed_is_partial() -> None:
    resolver = FakeResolver(
        {
            "good.example": ("malformed", "192.0.2.2"),
            "missing.example": HostResolverError("raw detail"),
        }
    )

    result = _execute(
        resolver,
        {
            "subdomains": [
                "missing.example",
                "https://bad.example",
                "good.example",
                "another.example/path",
            ]
        },
    )

    assert result.status == Status.PARTIAL
    assert [host.hostname for host in result.data.hosts] == ["good.example"]
    assert result.metadata["malformed_address_count"] == 1
    assert result.metadata["unresolved_hostname_count"] == 1
    assert result.errors == [
        "Invalid hostname input at index 1",
        "Invalid hostname input at index 3",
        "Resolver returned malformed address data for hostname 'good.example'",
        "Unable to resolve hostname 'missing.example'",
    ]


def test_all_invalid_or_unresolved_is_failure_and_duplicates_resolve_once() -> None:
    resolver = FakeResolver(
        {"missing.example": HostResolverError("not found")}
    )

    result = _execute(
        resolver,
        {"subdomains": ["MISSING.EXAMPLE", "missing.example.", "bad/path"]},
    )

    assert result.status == Status.FAILURE
    assert result.data == HostResolution()
    assert resolver.calls == ["missing.example"]


def test_unexpected_resolver_error_is_sanitized_error() -> None:
    resolver = FakeResolver(
        {"example.com": RuntimeError("secret-token C:\\private\\resolver")}
    )

    result = _execute(resolver, {"subdomains": ["example.com"]})
    rendered = repr(result)

    assert result.status == Status.ERROR
    assert result.data == HostResolution()
    assert result.errors == [
        "Host resolver failed with an unexpected execution error"
    ]
    assert "secret-token" not in rendered
    assert "private" not in rendered


def test_output_is_deterministic_across_input_and_address_order() -> None:
    first = FakeResolver(
        {
            "a.example": ("2001:db8::1", "192.0.2.1"),
            "z.example": ("192.0.2.2",),
        }
    )
    second = FakeResolver(
        {
            "a.example": ("192.0.2.1", "2001:0db8::1"),
            "z.example": ("192.0.2.2",),
        }
    )

    one = _execute(first, {"subdomains": ["z.example", "a.example"]})
    two = _execute(second, {"subdomains": ["a.example", "z.example"]})

    assert one.data == two.data
    assert first.calls == second.calls == ["a.example", "z.example"]


def test_name() -> None:
    assert HostResolutionCapability(FakeResolver({})).name == "host_resolution"
