"""Adapter for the NIST National Vulnerability Database APIs."""

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlencode
from urllib.request import Request, urlopen

from redforge.adapters.errors import (
    AdapterConfigurationError,
    AdapterError,
    AdapterResponseError,
    AdapterUnavailableError,
)


class NvdAdapterError(AdapterError):
    """Base exception for NVD adapter failures."""

    pass


class NvdRequestError(NvdAdapterError, AdapterUnavailableError):
    """Raised when an NVD request cannot be completed."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        self.status_code = status_code
        super().__init__(message)


class NvdAuthenticationError(NvdRequestError, AdapterConfigurationError):
    """Raised when NVD rejects authentication or authorization."""

    pass


class NvdRateLimitError(NvdRequestError):
    """Raised when the NVD rate limit remains exceeded after bounded retries."""

    def __init__(self, retry_after: float | None = None) -> None:
        self.retry_after = retry_after
        detail = (
            f"; retry after {retry_after:g} seconds"
            if retry_after is not None
            else ""
        )
        super().__init__(f"NVD rate limit exceeded{detail}", status_code=429)


class NvdParseError(NvdAdapterError, AdapterResponseError):
    """Raised when an NVD response cannot be parsed safely."""

    pass


@dataclass(frozen=True, slots=True)
class NvdCpeCandidate:
    """Normalized CPE candidate returned by the NVD CPE API."""

    cpe_name: str
    title: str | None
    deprecated: bool
    vendor: str
    product: str
    version: str


@dataclass(frozen=True, slots=True)
class NvdVulnerabilityRecord:
    """Normalized provider DTO returned by the NVD CVE API."""

    identifier: str
    description: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cwe_ids: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    published_at: str | None = None
    modified_at: str | None = None
    status: str | None = None
    source_identifier: str | None = None


class VulnerabilityProvider(Protocol):
    """Minimal typed vulnerability-provider port."""

    def search_cpe_candidates(
        self, name: str, version: str, vendor: str | None = None
    ) -> tuple[NvdCpeCandidate, ...]:
        """Return normalized candidate product identities."""
        ...

    def get_vulnerabilities(
        self, cpe_name: str
    ) -> tuple[NvdVulnerabilityRecord, ...]:
        """Return normalized vulnerability records for an exact CPE."""
        ...


class NvdAdapter:
    """HTTP adapter for NVD CPE discovery and exact-CPE CVE lookup."""

    _CPE_PATH = "/rest/json/cpes/2.0"
    _CVE_PATH = "/rest/json/cves/2.0"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = "https://services.nvd.nist.gov",
        timeout_seconds: float = 30.0,
        max_retries: int = 1,
        max_pages: int = 10,
        response_size_limit: int = 10 * 1024 * 1024,
        max_retry_after_seconds: float = 30.0,
        request_interval_seconds: float | None = None,
    ) -> None:
        """Initialize the NVD adapter with bounded operational limits."""
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max(0, max_retries)
        self.max_pages = max(1, max_pages)
        self.response_size_limit = max(1, response_size_limit)
        self.max_retry_after_seconds = max(0.0, max_retry_after_seconds)
        default_interval = 0.6 if api_key else 6.0
        self.request_interval_seconds = max(
            0.0,
            default_interval
            if request_interval_seconds is None
            else request_interval_seconds,
        )
        self._last_request_at: float | None = None

    def search_cpe_candidates(
        self, name: str, version: str, vendor: str | None = None
    ) -> tuple[NvdCpeCandidate, ...]:
        """Return normalized CPE candidates discovered by provider keyword search."""
        keywords = " ".join(
            value for value in (vendor, name, version) if value is not None and value
        )
        raw_products = self._get_paginated_items(
            self._CPE_PATH,
            {"keywordSearch": keywords},
            collection_key="products",
        )
        candidates: list[NvdCpeCandidate] = []
        seen: set[str] = set()
        for raw_product in raw_products:
            candidate = self._parse_cpe_candidate(raw_product)
            if candidate is None or candidate.cpe_name in seen:
                continue
            seen.add(candidate.cpe_name)
            candidates.append(candidate)
        candidates.sort(key=lambda item: item.cpe_name)
        return tuple(candidates)

    def get_vulnerabilities(
        self, cpe_name: str
    ) -> tuple[NvdVulnerabilityRecord, ...]:
        """Return normalized non-rejected CVE records for an exact vulnerable CPE."""
        raw_vulnerabilities = self._get_paginated_items(
            self._CVE_PATH,
            {
                "cpeName": cpe_name,
                "isVulnerable": "",
                "noRejected": "",
            },
            collection_key="vulnerabilities",
        )
        records: list[NvdVulnerabilityRecord] = []
        seen: set[str] = set()
        for raw_vulnerability in raw_vulnerabilities:
            record = self._parse_vulnerability_record(raw_vulnerability)
            if record is None or record.identifier in seen:
                continue
            seen.add(record.identifier)
            records.append(record)
        records.sort(key=lambda item: item.identifier)
        return tuple(records)

    def _get_paginated_items(
        self,
        path: str,
        params: dict[str, str],
        *,
        collection_key: str,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        start_index = 0

        for _page_number in range(self.max_pages):
            page_params = {**params, "startIndex": str(start_index)}
            response = self._request_json(path, page_params)
            collection = response.get(collection_key)
            if not isinstance(collection, list):
                raise NvdParseError(
                    f"NVD response field '{collection_key}' must be an array"
                )

            raw_collection = cast(list[Any], collection)
            for item in raw_collection:
                if isinstance(item, dict):
                    items.append(cast(dict[str, Any], item))

            total_results = self._non_negative_int(response.get("totalResults"))
            response_start = self._non_negative_int(response.get("startIndex"))
            results_per_page = self._non_negative_int(response.get("resultsPerPage"))
            if total_results is None:
                raise NvdParseError("NVD response is missing a valid totalResults")

            if response_start is None:
                response_start = start_index
            if results_per_page is None or results_per_page == 0:
                results_per_page = len(raw_collection)

            next_index = response_start + results_per_page
            if next_index >= total_results or not raw_collection:
                return items
            if next_index <= start_index:
                raise NvdParseError("NVD pagination did not advance")
            start_index = next_index

        raise NvdRequestError(
            f"NVD pagination exceeded the configured limit of {self.max_pages} pages"
        )

    def _request_json(self, path: str, params: dict[str, str]) -> dict[str, Any]:
        query = urlencode(params)
        request = Request(
            f"{self.base_url}{path}?{query}",
            headers={
                "Accept": "application/json",
                "User-Agent": "RedForge/0.0.1",
            },
            method="GET",
        )
        if self.api_key:
            request.add_header("apiKey", self.api_key)

        for attempt in range(self.max_retries + 1):
            try:
                self._wait_for_request_slot()
                response = urlopen(request, timeout=self.timeout_seconds)
                try:
                    payload = response.read(self.response_size_limit + 1)
                finally:
                    response.close()
                if len(payload) > self.response_size_limit:
                    raise NvdParseError("NVD response exceeded the configured size limit")
                return self._decode_json(payload)
            except HTTPError as error:
                if error.code == 403:
                    raise NvdAuthenticationError(
                        "NVD request was forbidden", status_code=403
                    ) from error

                retry_after = self._retry_after_seconds(error)
                if error.code == 429:
                    if attempt < self.max_retries:
                        time.sleep(retry_after or 0.0)
                        continue
                    raise NvdRateLimitError(retry_after) from error

                if 500 <= error.code < 600 and attempt < self.max_retries:
                    time.sleep(min(float(attempt + 1), self.max_retry_after_seconds))
                    continue
                raise NvdRequestError(
                    f"NVD request failed with HTTP status {error.code}",
                    status_code=error.code,
                ) from error
            except (TimeoutError, URLError, OSError) as error:
                if attempt < self.max_retries:
                    time.sleep(min(float(attempt + 1), self.max_retry_after_seconds))
                    continue
                raise NvdRequestError("NVD request could not be completed") from error

        raise NvdRequestError("NVD request could not be completed")

    def _wait_for_request_slot(self) -> None:
        if self._last_request_at is not None:
            elapsed = time.monotonic() - self._last_request_at
            remaining = self.request_interval_seconds - elapsed
            if remaining > 0.0:
                time.sleep(remaining)
        self._last_request_at = time.monotonic()

    def _decode_json(self, payload: bytes) -> dict[str, Any]:
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NvdParseError(f"Failed to parse NVD JSON response: {error}") from error
        if not isinstance(parsed, dict):
            raise NvdParseError("NVD JSON response must be an object")
        return cast(dict[str, Any], parsed)

    def _parse_cpe_candidate(self, raw_product: dict[str, Any]) -> NvdCpeCandidate | None:
        raw_cpe = raw_product.get("cpe")
        if not isinstance(raw_cpe, dict):
            return None
        cpe = cast(dict[str, Any], raw_cpe)
        cpe_name = cpe.get("cpeName")
        if not isinstance(cpe_name, str):
            return None

        components = self._split_cpe23(cpe_name)
        if components is None:
            return None
        vendor, product, version = components[3], components[4], components[5]
        deprecated = cpe.get("deprecated") is True
        title = self._english_value(cpe.get("titles"), value_key="title")
        return NvdCpeCandidate(
            cpe_name=cpe_name,
            title=title,
            deprecated=deprecated,
            vendor=self._decode_cpe_component(vendor),
            product=self._decode_cpe_component(product),
            version=self._decode_cpe_component(version),
        )

    def _parse_vulnerability_record(
        self, raw_vulnerability: dict[str, Any]
    ) -> NvdVulnerabilityRecord | None:
        raw_cve = raw_vulnerability.get("cve")
        if not isinstance(raw_cve, dict):
            return None
        cve = cast(dict[str, Any], raw_cve)
        identifier = cve.get("id")
        if not isinstance(identifier, str) or not identifier:
            return None

        status = cve.get("vulnStatus")
        normalized_status = status if isinstance(status, str) else None
        if normalized_status and normalized_status.casefold() == "rejected":
            return None

        description = self._english_value(cve.get("descriptions"), value_key="value")
        if description and description.lstrip().upper().startswith("** REJECT **"):
            return None

        severity, score, vector, version = self._select_cvss(cve.get("metrics"))
        return NvdVulnerabilityRecord(
            identifier=identifier,
            description=description,
            severity=severity,
            cvss_score=score,
            cvss_vector=vector,
            cvss_version=version,
            cwe_ids=self._extract_cwe_ids(cve.get("weaknesses")),
            references=self._extract_references(cve.get("references")),
            published_at=self._optional_string(cve.get("published")),
            modified_at=self._optional_string(cve.get("lastModified")),
            status=normalized_status,
            source_identifier=self._optional_string(cve.get("sourceIdentifier")),
        )

    def _select_cvss(
        self, raw_metrics: Any
    ) -> tuple[str | None, float | None, str | None, str | None]:
        if not isinstance(raw_metrics, dict):
            return (None, None, None, None)
        metrics = cast(dict[str, Any], raw_metrics)
        for key in ("cvssMetricV40", "cvssMetricV31"):
            metric_entries = metrics.get(key)
            if not isinstance(metric_entries, list):
                continue
            entries = [
                cast(dict[str, Any], entry)
                for entry in cast(list[Any], metric_entries)
                if isinstance(entry, dict)
            ]
            entries.sort(key=lambda entry: 0 if entry.get("type") == "Primary" else 1)
            for entry in entries:
                raw_data = entry.get("cvssData")
                if not isinstance(raw_data, dict):
                    continue
                data = cast(dict[str, Any], raw_data)
                severity = self._optional_string(data.get("baseSeverity"))
                score_value = data.get("baseScore")
                score = (
                    float(score_value)
                    if isinstance(score_value, int | float)
                    and not isinstance(score_value, bool)
                    else None
                )
                vector = self._optional_string(data.get("vectorString"))
                version = self._optional_string(data.get("version"))
                if not any((severity, score is not None, vector, version)):
                    continue
                return (severity, score, vector, version)
        return (None, None, None, None)

    def _extract_cwe_ids(self, raw_weaknesses: Any) -> tuple[str, ...]:
        if not isinstance(raw_weaknesses, list):
            return ()
        identifiers: set[str] = set()
        for raw_weakness in cast(list[Any], raw_weaknesses):
            if not isinstance(raw_weakness, dict):
                continue
            weakness = cast(dict[str, Any], raw_weakness)
            descriptions = weakness.get("description")
            if not isinstance(descriptions, list):
                continue
            for raw_description in cast(list[Any], descriptions):
                if not isinstance(raw_description, dict):
                    continue
                value = cast(dict[str, Any], raw_description).get("value")
                if isinstance(value, str) and value.startswith("CWE-"):
                    identifiers.add(value)
        return tuple(sorted(identifiers))

    def _extract_references(self, raw_references: Any) -> tuple[str, ...]:
        if not isinstance(raw_references, list):
            return ()
        references = {
            url
            for item in cast(list[Any], raw_references)
            if isinstance(item, dict)
            and isinstance((url := cast(dict[str, Any], item).get("url")), str)
            and url
        }
        return tuple(sorted(references))

    def _english_value(self, raw_values: Any, *, value_key: str) -> str | None:
        if not isinstance(raw_values, list):
            return None
        values = [
            cast(dict[str, Any], item)
            for item in cast(list[Any], raw_values)
            if isinstance(item, dict)
        ]
        for item in values:
            if item.get("lang") == "en":
                return self._optional_string(item.get(value_key))
        for item in values:
            value = self._optional_string(item.get(value_key))
            if value:
                return value
        return None

    def _split_cpe23(self, cpe_name: str) -> tuple[str, ...] | None:
        components: list[str] = []
        current: list[str] = []
        escaped = False
        for character in cpe_name:
            if character == ":" and not escaped:
                components.append("".join(current))
                current = []
                continue
            current.append(character)
            escaped = character == "\\" and not escaped
        components.append("".join(current))
        if len(components) != 13 or components[:2] != ["cpe", "2.3"]:
            return None
        return tuple(components)

    def _decode_cpe_component(self, component: str) -> str:
        decoded = unquote(component)
        output: list[str] = []
        escaped = False
        for character in decoded:
            if escaped:
                output.append(character)
                escaped = False
            elif character == "\\":
                escaped = True
            else:
                output.append(character)
        if escaped:
            output.append("\\")
        return "".join(output)

    def _retry_after_seconds(self, error: HTTPError) -> float | None:
        raw_value = error.headers.get("Retry-After") if error.headers else None
        if not raw_value:
            return None
        try:
            seconds = max(0.0, float(raw_value))
        except ValueError:
            try:
                retry_at = parsedate_to_datetime(raw_value)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=UTC)
                seconds = max(0.0, (retry_at - datetime.now(UTC)).total_seconds())
            except (TypeError, ValueError, OverflowError):
                return None
        return min(seconds, self.max_retry_after_seconds)

    def _non_negative_int(self, value: Any) -> int | None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return None
        return value

    def _optional_string(self, value: Any) -> str | None:
        return value if isinstance(value, str) and value else None
