"""Tests for the typed web crawler boundary."""

from dataclasses import dataclass
from ipaddress import IPv4Address

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.errors import AdapterUnavailableError
from redforge.adapters.katana import WebCrawlAdapterResult
from redforge.capabilities.web_crawl import WebCrawlCapability
from redforge.domain.endpoint import Endpoint
from redforge.domain.host import Host
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.context import Context
from redforge.sdk.result import Status


@dataclass
class FakeCrawler:
    response: object
    calls: list[tuple[str, ...]]

    def crawl(self, hosts: tuple[str, ...]) -> WebCrawlAdapterResult:
        self.calls.append(hosts)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response  # type: ignore[return-value]


def _context() -> Context:
    return Context(
        target_id="example.com",
        state={
            PipelineStateKey.ALIVE_HOSTS: [
                Host(
                    address=IPv4Address("192.0.2.1"),
                    hostname="www.example.com",
                )
            ]
        },
    )


def test_capability_uses_typed_crawler_result() -> None:
    endpoint = Endpoint("www.example.com", 443, "https", "/")
    crawler = FakeCrawler(WebCrawlAdapterResult((endpoint,)), [])

    result = WebCrawlCapability(crawler=crawler).execute(_context())

    assert result.status == Status.SUCCESS
    assert result.data == [endpoint]
    assert crawler.calls == [
        ("http://www.example.com", "https://www.example.com")
    ]


def test_expected_crawler_failure_is_sanitized_failure() -> None:
    result = WebCrawlCapability(
        crawler=FakeCrawler(
            AdapterUnavailableError("C:\\private\\provider"),
            [],
        )
    ).execute(_context())

    assert result.status == Status.FAILURE
    assert "private" not in repr(result)


@pytest.mark.parametrize("invalid", [None, {}, "invalid"])
def test_invalid_crawler_result_is_error(invalid: object) -> None:
    result = WebCrawlCapability(
        crawler=FakeCrawler(invalid, [])
    ).execute(_context())

    assert result.status == Status.ERROR


def test_name() -> None:
    assert WebCrawlCapability(
        crawler=FakeCrawler(WebCrawlAdapterResult(), [])
    ).name == "web_crawl"
