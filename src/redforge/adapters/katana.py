"""Katana web-crawl provider implemented through the ToolRunner port."""

import json
import math
from dataclasses import dataclass
from ipaddress import IPv6Address, ip_address
from typing import cast
from urllib.parse import unquote_plus, urlsplit

from redforge.domain.endpoint import Endpoint
from redforge.domain.host import Host
from redforge.domain.hostname import normalize_dns_hostname
from redforge.domain.http_probe import normalize_http_url
from redforge.sdk.tool import (
    ToolDefinition,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolId,
    ToolInvocation,
    ToolRunner,
)
from redforge.sdk.web_crawl import (
    WebCrawlProvider,
    WebCrawlProviderResult,
    WebCrawlProviderStatus,
)

KATANA_TOOL_ID = ToolId("katana")
KATANA_TOOL = ToolDefinition(
    tool_id=KATANA_TOOL_ID,
    display_name="Katana",
    description="Crawls web applications and extracts endpoints.",
    executable="katana",
    version_argument=("-version",),
    default_timeout_seconds=120.0,
    tags=("crawl", "recon", "web"),
)

_MAX_STDIN_BYTES = 1_048_576
_MAX_URL_LENGTH = 4_096
_MAX_PATH_LENGTH = 2_048
_MAX_QUERY_LENGTH = 2_048
_SENSITIVE_QUERY_NAMES = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "cookie",
        "jwt",
        "passwd",
        "password",
        "secret",
        "session",
        "sessionid",
        "token",
    }
)


@dataclass(frozen=True, slots=True)
class KatanaConfig:
    """Conservative immutable Katana execution and crawl policy."""

    timeout_seconds: float | None = None
    depth: int = 2
    crawl_duration_seconds: int = 30
    request_timeout_seconds: int = 10
    concurrency: int = 5
    parallelism: int = 2
    rate_limit_per_second: int = 20
    max_response_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        timeout = cast(object, self.timeout_seconds)
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("Katana execution timeout must be positive and finite")
        for label, value, maximum in (
            ("depth", self.depth, 10),
            ("crawl duration", self.crawl_duration_seconds, 3_600),
            ("request timeout", self.request_timeout_seconds, 300),
            ("concurrency", self.concurrency, 100),
            ("parallelism", self.parallelism, 100),
            ("rate limit", self.rate_limit_per_second, 1_000),
            ("response limit", self.max_response_bytes, 10_485_760),
        ):
            if (
                not isinstance(cast(object, value), int)
                or isinstance(cast(object, value), bool)
                or not 1 <= value <= maximum
            ):
                raise ValueError(
                    f"Katana {label} must be between 1 and {maximum}"
                )


@dataclass(frozen=True, slots=True)
class _PreparedSeeds:
    seeds: tuple[str, ...]
    approved_hosts: frozenset[str]


@dataclass(frozen=True, slots=True)
class _ParseSummary:
    endpoints: tuple[Endpoint, ...]
    malformed_record_count: int
    out_of_scope_count: int
    duplicate_count: int
    record_count: int

    @property
    def has_issues(self) -> bool:
        return bool(
            self.malformed_record_count or self.out_of_scope_count
        )


def _serialized_host(value: str) -> str:
    try:
        address = ip_address(value)
    except ValueError:
        return normalize_dns_hostname(value)
    return f"[{address}]" if isinstance(address, IPv6Address) else str(address)


def _prepare_seeds(hosts: tuple[Host, ...]) -> _PreparedSeeds:
    if not isinstance(cast(object, hosts), tuple):
        raise TypeError("web crawl hosts must be an immutable tuple")
    seeds: set[str] = set()
    approved: set[str] = set()
    for host in hosts:
        if not isinstance(cast(object, host), Host):
            raise TypeError("web crawl input contains an invalid host")
        identities: tuple[str, ...]
        if host.hostname is not None:
            hostname = normalize_dns_hostname(host.hostname)
            identities = (hostname,)
            approved.add(hostname)
            approved.update(str(ip_address(item.value)) for item in host.addresses)
        else:
            identities = tuple(
                str(ip_address(item.value)) for item in host.addresses
            )
            approved.update(identities)
        if not identities:
            raise ValueError("web crawl host has no usable identity")
        for identity in identities:
            serialized = _serialized_host(identity)
            seeds.add(f"http://{serialized}")
            seeds.add(f"https://{serialized}")
    return _PreparedSeeds(tuple(sorted(seeds)), frozenset(approved))


def _safe_query(query: str) -> bool:
    if len(query) > _MAX_QUERY_LENGTH:
        return False
    for component in query.split("&"):
        raw_name = component.partition("=")[0]
        try:
            name = unquote_plus(raw_name).casefold()
        except Exception:
            return False
        if name in _SENSITIVE_QUERY_NAMES:
            return False
    return True


def _record_url(record: dict[object, object]) -> str:
    direct = record.get("url")
    if isinstance(direct, str):
        return direct
    request = record.get("request")
    if not isinstance(request, dict):
        raise ValueError("Katana record has no request")
    typed_request = cast(dict[object, object], request)
    method = typed_request.get("method")
    if method is not None and (
        not isinstance(method, str) or method.upper() not in {"GET", "HEAD"}
    ):
        raise ValueError("Katana record method is unsupported")
    endpoint = typed_request.get("endpoint")
    if not isinstance(endpoint, str):
        raise ValueError("Katana record endpoint is invalid")
    return endpoint


def _url_to_endpoint(url: str, approved_hosts: frozenset[str]) -> Endpoint | None:
    if not isinstance(cast(object, url), str) or len(url) > _MAX_URL_LENGTH:
        raise ValueError("Katana URL is invalid")
    normalized = normalize_http_url(url)
    if normalized.hostname not in approved_hosts:
        return None
    parsed = urlsplit(normalized.value)
    path = parsed.path or "/"
    if len(path) > _MAX_PATH_LENGTH or not _safe_query(parsed.query):
        raise ValueError("Katana URL path or query is invalid")
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return Endpoint(
        host=normalized.hostname,
        port=normalized.port,
        protocol=normalized.scheme,
        path=path,
    )


def _parse_jsonl(
    stdout: str,
    approved_hosts: frozenset[str],
    *,
    discard_unterminated_final_line: bool,
) -> _ParseSummary:
    endpoints: dict[tuple[str, str, int, str], Endpoint] = {}
    malformed = 0
    out_of_scope = 0
    duplicates = 0
    records = 0
    lines = stdout.splitlines()
    if (
        discard_unterminated_final_line
        and stdout
        and not stdout.endswith(("\n", "\r"))
    ):
        malformed += 1
        lines = lines[:-1]
    for line in lines:
        if not line.strip():
            continue
        records += 1
        try:
            parsed = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            malformed += 1
            continue
        if not isinstance(parsed, dict):
            malformed += 1
            continue
        try:
            endpoint = _url_to_endpoint(
                _record_url(cast(dict[object, object], parsed)),
                approved_hosts,
            )
        except (TypeError, ValueError):
            malformed += 1
            continue
        if endpoint is None:
            out_of_scope += 1
            continue
        identity = (
            endpoint.protocol,
            endpoint.host,
            endpoint.port,
            endpoint.path or "/",
        )
        if identity in endpoints:
            duplicates += 1
            continue
        endpoints[identity] = endpoint
    return _ParseSummary(
        endpoints=tuple(endpoints[key] for key in sorted(endpoints)),
        malformed_record_count=malformed,
        out_of_scope_count=out_of_scope,
        duplicate_count=duplicates,
        record_count=records,
    )


class KatanaWebCrawlProvider:
    """Build safe Katana invocations and map JSONL into crawler evidence."""

    def __init__(
        self,
        *,
        runner: ToolRunner,
        definition: ToolDefinition = KATANA_TOOL,
        config: KatanaConfig | None = None,
    ) -> None:
        if not isinstance(cast(object, definition), ToolDefinition):
            raise TypeError("Katana provider requires a ToolDefinition")
        if definition.tool_id != KATANA_TOOL_ID:
            raise ValueError("Katana provider tool identity does not match")
        self._runner = runner
        self._definition = definition
        self._config = config or KatanaConfig()

    @property
    def definition(self) -> ToolDefinition:
        """Return immutable Katana executable metadata."""
        return self._definition

    @property
    def config(self) -> KatanaConfig:
        """Return immutable supported Katana configuration."""
        return self._config

    def build_invocation(self, hosts: tuple[Host, ...]) -> ToolInvocation:
        """Return deterministic safe argv and bounded newline-delimited stdin."""
        prepared = _prepare_seeds(hosts)
        if not prepared.seeds:
            raise ValueError("Katana invocation requires at least one seed")
        stdin = "".join(f"{seed}\n" for seed in prepared.seeds)
        if len(stdin.encode("utf-8")) > _MAX_STDIN_BYTES:
            raise ValueError("Katana target input exceeds the supported limit")
        arguments = (
            "-jsonl",
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-omit-raw",
            "-omit-body",
            "-retry",
            "0",
            "-depth",
            str(self._config.depth),
            "-crawl-duration",
            f"{self._config.crawl_duration_seconds}s",
            "-timeout",
            str(self._config.request_timeout_seconds),
            "-concurrency",
            str(self._config.concurrency),
            "-parallelism",
            str(self._config.parallelism),
            "-rate-limit",
            str(self._config.rate_limit_per_second),
            "-max-response-size",
            str(self._config.max_response_bytes),
            "-field-scope",
            "fqdn",
        )
        return ToolInvocation(
            tool_id=self._definition.tool_id,
            arguments=arguments,
            timeout_seconds=self._config.timeout_seconds,
            stdin=stdin,
        )

    def crawl(self, hosts: tuple[Host, ...]) -> WebCrawlProviderResult:
        """Run Katana once for approved responsive hosts."""
        try:
            prepared = _prepare_seeds(hosts)
            if not prepared.seeds:
                return WebCrawlProviderResult()
            invocation = self.build_invocation(hosts)
        except (TypeError, ValueError):
            return WebCrawlProviderResult(
                status=WebCrawlProviderStatus.ERROR,
                message="Web crawl input is invalid.",
            )
        try:
            result = self._runner.run(self._definition, invocation)
        except Exception:
            return WebCrawlProviderResult(
                status=WebCrawlProviderStatus.ERROR,
                message="Katana execution failed.",
            )
        return self._map_result(
            result,
            approved_hosts=prepared.approved_hosts,
        )

    @staticmethod
    def _map_result(
        result: ToolExecutionResult,
        *,
        approved_hosts: frozenset[str],
    ) -> WebCrawlProviderResult:
        if (
            not isinstance(cast(object, result), ToolExecutionResult)
            or result.tool_id != KATANA_TOOL_ID
        ):
            return WebCrawlProviderResult(
                status=WebCrawlProviderStatus.ERROR,
                message="Katana execution returned an invalid result.",
            )
        if result.status is ToolExecutionStatus.NOT_FOUND:
            return WebCrawlProviderResult(
                status=WebCrawlProviderStatus.UNAVAILABLE,
                message="Katana executable is unavailable.",
            )
        if result.status is ToolExecutionStatus.ERROR:
            return WebCrawlProviderResult(
                status=WebCrawlProviderStatus.ERROR,
                message="Katana execution failed.",
            )
        if result.status is ToolExecutionStatus.FAILURE:
            return WebCrawlProviderResult(
                status=WebCrawlProviderStatus.FAILURE,
                message="Katana returned a non-zero exit status.",
                truncated=result.truncated,
            )
        parsed = _parse_jsonl(
            result.stdout,
            approved_hosts,
            discard_unterminated_final_line=(
                result.status is ToolExecutionStatus.TIMEOUT
                or result.truncated
            ),
        )
        if result.status is ToolExecutionStatus.TIMEOUT:
            if parsed.endpoints:
                status = WebCrawlProviderStatus.PARTIAL
                message = "Web crawling timed out with partial findings."
            else:
                status = WebCrawlProviderStatus.FAILURE
                message = "Web crawling timed out."
        elif parsed.endpoints:
            status = (
                WebCrawlProviderStatus.PARTIAL
                if parsed.has_issues or result.truncated
                else WebCrawlProviderStatus.SUCCESS
            )
            message = (
                "Katana output contained incomplete or rejected records."
                if status is WebCrawlProviderStatus.PARTIAL
                else None
            )
        elif parsed.record_count or parsed.has_issues or result.truncated:
            status = WebCrawlProviderStatus.FAILURE
            message = "Katana output contained no valid approved endpoints."
        else:
            status = WebCrawlProviderStatus.SUCCESS
            message = None
        return WebCrawlProviderResult(
            endpoints=parsed.endpoints,
            status=status,
            message=message,
            malformed_record_count=parsed.malformed_record_count,
            out_of_scope_count=parsed.out_of_scope_count,
            duplicate_count=parsed.duplicate_count,
            truncated=result.truncated,
        )


# Compatibility names retained without a second adapter implementation.
KatanaAdapter = KatanaWebCrawlProvider
WebCrawlAdapterResult = WebCrawlProviderResult
WebCrawler = WebCrawlProvider
