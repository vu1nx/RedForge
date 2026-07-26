"""Tests for the tool-agnostic web-crawl capability."""

from dataclasses import dataclass
from ipaddress import IPv4Address

import pytest  # type: ignore[reportMissingImports]

from redforge.capabilities.web_crawl import WebCrawlCapability
from redforge.domain.endpoint import Endpoint
from redforge.domain.host import Host
from redforge.runtime.pipeline import Pipeline
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status
from redforge.sdk.web_crawl import (
    WebCrawlProviderResult,
    WebCrawlProviderStatus,
)


@dataclass
class FakeProvider:
    response: object
    calls: list[tuple[Host, ...]]

    def crawl(self, hosts: tuple[Host, ...]) -> WebCrawlProviderResult:
        self.calls.append(hosts)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response  # type: ignore[return-value]


def _host() -> Host:
    return Host(
        address=IPv4Address("192.0.2.1"),
        hostname="www.example.com",
    )


def _context(hosts: tuple[Host, ...] = (_host(),)) -> Context:
    return Context(
        target_id="example.com",
        state={PipelineStateKey.ALIVE_HOSTS: hosts},
    )


def _published(result: Result[object]) -> tuple[Endpoint, ...]:
    publication = next(
        item
        for item in result.publications
        if item.key is PipelineStateKey.ENDPOINTS
    )
    assert isinstance(publication.value, tuple)
    return publication.value  # type: ignore[return-value]


def test_success_calls_provider_once_and_publishes_immutable_endpoints() -> None:
    first = Endpoint("www.example.com", 443, "https", "/a")
    second = Endpoint("www.example.com", 443, "https", "/b")
    provider = FakeProvider(
        WebCrawlProviderResult(endpoints=(second, first)),
        [],
    )

    result = WebCrawlCapability(provider=provider).execute(_context())

    assert result.status is Status.SUCCESS
    assert result.data is None
    assert provider.calls == [(_host(),)]
    assert _published(result) == (first, second)


def test_empty_input_skips_provider_and_publishes_empty_tuple() -> None:
    provider = FakeProvider(WebCrawlProviderResult(), [])
    result = WebCrawlCapability(provider=provider).execute(_context(()))
    assert result.status is Status.SUCCESS
    assert _published(result) == ()
    assert provider.calls == []


def test_empty_success_is_not_failure() -> None:
    provider = FakeProvider(WebCrawlProviderResult(), [])
    result = WebCrawlCapability(provider=provider).execute(_context())
    assert result.status is Status.SUCCESS
    assert _published(result) == ()
    assert provider.calls == [(_host(),)]


def test_partial_with_endpoints_publishes_and_continues() -> None:
    endpoint = Endpoint("www.example.com", 443, "https", "/partial")
    provider = FakeProvider(
        WebCrawlProviderResult(
            endpoints=(endpoint,),
            status=WebCrawlProviderStatus.PARTIAL,
            message="Katana output contained incomplete or rejected records.",
        ),
        [],
    )
    result = WebCrawlCapability(provider=provider).execute(_context())
    assert result.status is Status.PARTIAL
    assert _published(result) == (endpoint,)


def test_partial_without_endpoints_is_failure() -> None:
    provider = FakeProvider(
        WebCrawlProviderResult(
            status=WebCrawlProviderStatus.PARTIAL,
            message="Web crawling completed partially.",
        ),
        [],
    )
    result = WebCrawlCapability(provider=provider).execute(_context())
    assert result.status is Status.FAILURE
    assert result.publications == ()


@pytest.mark.parametrize(
    ("provider_status", "capability_status"),
    (
        (WebCrawlProviderStatus.FAILURE, Status.FAILURE),
        (WebCrawlProviderStatus.UNAVAILABLE, Status.ERROR),
        (WebCrawlProviderStatus.ERROR, Status.ERROR),
    ),
)
def test_non_publishable_statuses(
    provider_status: WebCrawlProviderStatus,
    capability_status: Status,
) -> None:
    provider = FakeProvider(
        WebCrawlProviderResult(
            status=provider_status,
            message="Web crawling failed.",
        ),
        [],
    )
    result = WebCrawlCapability(provider=provider).execute(_context())
    assert result.status is capability_status
    assert result.publications == ()
    assert provider.calls == [(_host(),)]


@pytest.mark.parametrize("invalid", (None, {}, "invalid"))
def test_invalid_provider_results_are_sanitized(invalid: object) -> None:
    result = WebCrawlCapability(
        provider=FakeProvider(invalid, [])
    ).execute(_context())
    assert result.status is Status.ERROR
    assert result.errors == ["Web crawl provider returned an invalid result"]


def test_unexpected_provider_error_is_sanitized() -> None:
    result = WebCrawlCapability(
        provider=FakeProvider(
            RuntimeError("Authorization secret C:\\private\\katana"),
            [],
        )
    ).execute(_context())
    assert result.status is Status.ERROR
    assert "Authorization" not in repr(result)
    assert "private" not in repr(result)


def test_manual_pipeline_has_one_history_entry_and_publishes_endpoints() -> None:
    endpoint = Endpoint("www.example.com", 443, "https", "/")
    provider = FakeProvider(
        WebCrawlProviderResult(endpoints=(endpoint,)),
        [],
    )
    pipeline = Pipeline()
    pipeline.add(WebCrawlCapability(provider=provider))

    result = pipeline.run(_context())

    assert result.status is Status.SUCCESS
    assert result.context.get(PipelineStateKey.ENDPOINTS) == (endpoint,)
    assert len(result.executions) == 1
    assert result.executions[0].capability_name == "web_crawl"


def test_legacy_crawler_keyword_remains_supported() -> None:
    provider = FakeProvider(WebCrawlProviderResult(), [])
    capability = WebCrawlCapability(crawler=provider)
    assert capability.name == "web_crawl"
    assert capability.execute(_context()).status is Status.SUCCESS


def test_conflicting_endpoint_metadata_is_rejected() -> None:
    first = Endpoint(
        "www.example.com",
        443,
        "https",
        "/",
        description="first",
    )
    conflicting = Endpoint(
        "www.example.com",
        443,
        "https",
        "/",
        description="second",
    )
    result = WebCrawlCapability(
        provider=FakeProvider(
            WebCrawlProviderResult(endpoints=(first, conflicting)),
            [],
        )
    ).execute(_context())
    assert result.status is Status.ERROR
    assert result.publications == ()
    assert result.errors == [
        "Web crawl provider returned invalid endpoint evidence"
    ]
