"""Tests for the NVD API adapter boundary."""

import json
from collections.abc import Iterator
from email.message import Message
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.nvd import (
    NvdAdapter,
    NvdAuthenticationError,
    NvdParseError,
    NvdRateLimitError,
    NvdRequestError,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "nvd"


class _Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.closed = False

    def read(self, amount: int = -1) -> bytes:
        return self.payload if amount < 0 else self.payload[:amount]

    def close(self) -> None:
        self.closed = True


class _UrlOpenQueue:
    def __init__(self, *items: _Response | BaseException) -> None:
        self.items: Iterator[_Response | BaseException] = iter(items)
        self.requests: list[Request] = []
        self.timeouts: list[float] = []

    def __call__(self, request: Request, *, timeout: float) -> _Response:
        self.requests.append(request)
        self.timeouts.append(timeout)
        item = next(self.items)
        if isinstance(item, BaseException):
            raise item
        return item


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _json_payload(value: object) -> bytes:
    return json.dumps(value).encode()


def _cpe_product(cpe_name: str, *, deprecated: bool = False) -> dict[str, object]:
    return {
        "cpe": {
            "deprecated": deprecated,
            "cpeName": cpe_name,
            "titles": [{"title": cpe_name, "lang": "en"}],
        }
    }


def _http_error(status_code: int, *, retry_after: str | None = None) -> HTTPError:
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return HTTPError(
        "https://services.nvd.nist.gov",
        status_code,
        "failed",
        headers,
        None,
    )


def test_search_cpe_candidates_parses_exact_deprecated_and_multiple_results() -> None:
    queue = _UrlOpenQueue(_Response(_fixture("cpe_search.json")))

    with patch("redforge.adapters.nvd.urlopen", queue):
        candidates = NvdAdapter(request_interval_seconds=0).search_cpe_candidates(
            "nginx", "1.24.0"
        )

    assert len(candidates) == 3
    assert candidates[0].cpe_name == "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"
    assert candidates[0].vendor == "f5"
    assert candidates[0].product == "nginx"
    assert candidates[0].version == "1.24.0"
    assert candidates[1].deprecated is True
    assert "keywordSearch=nginx+1.24.0" in queue.requests[0].full_url


def test_search_cpe_candidates_handles_empty_response() -> None:
    queue = _UrlOpenQueue(_Response(_fixture("empty_cpe_search.json")))

    with patch("redforge.adapters.nvd.urlopen", queue):
        candidates = NvdAdapter(request_interval_seconds=0).search_cpe_candidates(
            "unknown", "1.0"
        )

    assert candidates == []


def test_pagination_collects_and_orders_all_pages() -> None:
    first = {
        "startIndex": 0,
        "resultsPerPage": 1,
        "totalResults": 2,
        "products": [
            _cpe_product("cpe:2.3:a:z_vendor:z_product:1.0:*:*:*:*:*:*:*")
        ],
    }
    second = {
        "startIndex": 1,
        "resultsPerPage": 1,
        "totalResults": 2,
        "products": [
            _cpe_product("cpe:2.3:a:a_vendor:a_product:1.0:*:*:*:*:*:*:*")
        ],
    }
    queue = _UrlOpenQueue(
        _Response(_json_payload(first)),
        _Response(_json_payload(second)),
    )

    with patch("redforge.adapters.nvd.urlopen", queue):
        candidates = NvdAdapter(request_interval_seconds=0).search_cpe_candidates(
            "product", "1.0"
        )

    assert [candidate.vendor for candidate in candidates] == ["a_vendor", "z_vendor"]
    assert "startIndex=0" in queue.requests[0].full_url
    assert "startIndex=1" in queue.requests[1].full_url


def test_public_request_pacing_uses_nvd_rolling_window_interval() -> None:
    first = {
        "startIndex": 0,
        "resultsPerPage": 1,
        "totalResults": 2,
        "products": [_cpe_product("cpe:2.3:a:a:a:1:*:*:*:*:*:*:*")],
    }
    second = {
        "startIndex": 1,
        "resultsPerPage": 1,
        "totalResults": 2,
        "products": [_cpe_product("cpe:2.3:a:b:b:1:*:*:*:*:*:*:*")],
    }
    queue = _UrlOpenQueue(
        _Response(_json_payload(first)),
        _Response(_json_payload(second)),
    )

    with (
        patch("redforge.adapters.nvd.urlopen", queue),
        patch(
            "redforge.adapters.nvd.time.monotonic",
            side_effect=[0.0, 1.0, 6.0],
        ),
        patch("redforge.adapters.nvd.time.sleep") as sleep,
    ):
        NvdAdapter().search_cpe_candidates("product", "1")

    sleep.assert_called_once_with(5.0)
    assert NvdAdapter(api_key="key").request_interval_seconds == 0.6


def test_malformed_cpe_entries_are_ignored() -> None:
    response = {
        "startIndex": 0,
        "resultsPerPage": 3,
        "totalResults": 3,
        "products": [
            {"cpe": {"cpeName": "not-a-cpe"}},
            {"cpe": {"cpeName": 42}},
            {"unexpected": "shape"},
        ],
    }
    queue = _UrlOpenQueue(_Response(_json_payload(response)))

    with patch("redforge.adapters.nvd.urlopen", queue):
        candidates = NvdAdapter(request_interval_seconds=0).search_cpe_candidates(
            "product", "1.0"
        )

    assert candidates == []


def test_get_vulnerabilities_prefers_cvss4_and_falls_back_to_cvss31() -> None:
    queue = _UrlOpenQueue(_Response(_fixture("cve_search.json")))

    with patch("redforge.adapters.nvd.urlopen", queue):
        records = NvdAdapter(request_interval_seconds=0).get_vulnerabilities(
            "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
        )

    assert [record.identifier for record in records] == [
        "CVE-2024-0003",
        "CVE-2025-0002",
        "CVE-2026-0001",
    ]
    without_cvss, cvss31, cvss4 = records
    assert without_cvss.cvss_score is None
    assert without_cvss.cvss_version is None
    assert cvss31.cvss_score == 8.1
    assert cvss31.cvss_version == "3.1"
    assert cvss31.severity == "HIGH"
    assert cvss4.cvss_score == 9.3
    assert cvss4.cvss_version == "4.0"
    assert cvss4.cwe_ids == ("CWE-787",)
    assert cvss4.references == ("https://example.org/advisories/CVE-2026-0001",)
    assert "cpeName=cpe%3A2.3" in queue.requests[0].full_url
    assert "isVulnerable=" in queue.requests[0].full_url
    assert "noRejected=" in queue.requests[0].full_url


def test_malformed_cvss4_metric_falls_back_to_valid_cvss31() -> None:
    response: dict[str, object] = {
        "startIndex": 0,
        "resultsPerPage": 1,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-1000",
                    "vulnStatus": "Analyzed",
                    "metrics": {
                        "cvssMetricV40": [{"type": "Primary", "cvssData": {}}],
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L",
                                    "baseScore": 7.5,
                                    "baseSeverity": "HIGH",
                                },
                            }
                        ],
                    },
                }
            }
        ],
    }
    queue = _UrlOpenQueue(_Response(_json_payload(response)))

    with patch("redforge.adapters.nvd.urlopen", queue):
        records = NvdAdapter(request_interval_seconds=0).get_vulnerabilities(
            "cpe:2.3:a:a:b:1:*:*:*:*:*:*:*"
        )

    assert records[0].cvss_version == "3.1"
    assert records[0].cvss_score == 7.5


def test_rejected_cve_is_excluded_even_without_cvss() -> None:
    queue = _UrlOpenQueue(_Response(_fixture("cve_search.json")))

    with patch("redforge.adapters.nvd.urlopen", queue):
        records = NvdAdapter(request_interval_seconds=0).get_vulnerabilities(
            "cpe:2.3:a:a:b:1:*:*:*:*:*:*:*"
        )

    assert "CVE-2023-0004" not in {record.identifier for record in records}


def test_malformed_json_raises_parse_error() -> None:
    queue = _UrlOpenQueue(_Response(b"{not-json"))

    with (
        patch("redforge.adapters.nvd.urlopen", queue),
        pytest.raises(NvdParseError, match="Failed to parse NVD JSON"),
    ):
        NvdAdapter(request_interval_seconds=0).search_cpe_candidates("nginx", "1.0")


def test_malformed_collection_schema_raises_parse_error() -> None:
    queue = _UrlOpenQueue(_Response(_json_payload({"totalResults": 1, "products": {}})))

    with (
        patch("redforge.adapters.nvd.urlopen", queue),
        pytest.raises(NvdParseError, match="must be an array"),
    ):
        NvdAdapter(request_interval_seconds=0).search_cpe_candidates("nginx", "1.0")


def test_timeout_is_bounded_and_translated() -> None:
    queue = _UrlOpenQueue(TimeoutError("timed out"))

    with (
        patch("redforge.adapters.nvd.urlopen", queue),
        pytest.raises(NvdRequestError, match="could not be completed"),
    ):
        NvdAdapter(
            max_retries=0,
            timeout_seconds=0.5,
            request_interval_seconds=0,
        ).search_cpe_candidates(
            "nginx", "1.0"
        )

    assert queue.timeouts == [0.5]


def test_retry_after_is_honored_before_retry() -> None:
    error = _http_error(429, retry_after="2")
    queue = _UrlOpenQueue(error, _Response(_fixture("empty_cpe_search.json")))

    with (
        patch("redforge.adapters.nvd.urlopen", queue),
        patch("redforge.adapters.nvd.time.sleep") as sleep,
    ):
        assert (
            NvdAdapter(max_retries=1, request_interval_seconds=0).search_cpe_candidates(
                "nginx", "1.0"
            )
            == []
        )

    sleep.assert_called_once_with(2.0)


@pytest.mark.parametrize(
    ("status_code", "expected_error"),
    [
        (403, NvdAuthenticationError),
        (429, NvdRateLimitError),
    ],
)
def test_http_authentication_and_rate_limit_failures(
    status_code: int,
    expected_error: type[Exception],
) -> None:
    error = _http_error(status_code)
    queue = _UrlOpenQueue(error)

    with (
        patch("redforge.adapters.nvd.urlopen", queue),
        pytest.raises(expected_error),
    ):
        NvdAdapter(max_retries=0, request_interval_seconds=0).search_cpe_candidates(
            "nginx", "1.0"
        )


def test_api_key_uses_header_and_is_not_leaked_in_url_or_diagnostics() -> None:
    secret = "top-secret-api-key"
    queue = _UrlOpenQueue(_Response(_fixture("empty_cpe_search.json")))

    with patch("redforge.adapters.nvd.urlopen", queue):
        NvdAdapter(api_key=secret, request_interval_seconds=0).search_cpe_candidates(
            "nginx", "1.0"
        )

    request = queue.requests[0]
    headers = {name.casefold(): value for name, value in request.header_items()}
    assert headers["apikey"] == secret
    assert secret not in request.full_url

    error_queue = _UrlOpenQueue(_http_error(500))
    with (
        patch("redforge.adapters.nvd.urlopen", error_queue),
        pytest.raises(NvdRequestError) as error_info,
    ):
        NvdAdapter(
            api_key=secret,
            max_retries=0,
            request_interval_seconds=0,
        ).search_cpe_candidates("nginx", "1.0")
    assert secret not in str(error_info.value)


def test_non_object_json_is_rejected() -> None:
    queue = _UrlOpenQueue(_Response(_json_payload(cast(list[Any], []))))

    with (
        patch("redforge.adapters.nvd.urlopen", queue),
        pytest.raises(NvdParseError, match="must be an object"),
    ):
        NvdAdapter(request_interval_seconds=0).search_cpe_candidates("nginx", "1.0")
