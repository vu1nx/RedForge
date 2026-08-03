"""HTTPX web-service provider implemented through the ToolRunner port."""

import json
import math
import re
from dataclasses import dataclass
from ipaddress import ip_address
from typing import cast
from urllib.parse import urlsplit

from redforge.domain.host import Host
from redforge.domain.hostname import normalize_dns_hostname
from redforge.domain.http_probe import HttpProbeEndpoint, normalize_http_url
from redforge.domain.scan_scope import ExactNetworkTarget
from redforge.sdk.http_probe import (
    HttpProbeProvider,
    HttpProbeProviderResult,
    HttpProbeProviderStatus,
)
from redforge.sdk.tool import (
    ToolDefinition,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolId,
    ToolInvocation,
    ToolRunner,
)

HTTPX_TOOL_ID = ToolId("httpx")
HTTPX_TOOL = ToolDefinition(
    tool_id=HTTPX_TOOL_ID,
    display_name="HTTPX",
    description="Probes HTTP and HTTPS services.",
    executable_candidates=("httpx-toolkit", "httpx"),
    version_argument=("-version",),
    identity_output_pattern=(
        r"(?im)^\s*\[INF\]\s+Current Version:\s+"
        r"(?P<version>v[0-9]+(?:\.[0-9]+){1,3}"
        r"(?:[-+][0-9A-Za-z.-]+)?)\s*$"
    ),
    default_timeout_seconds=300.0,
    tags=("http", "probe", "recon"),
)

_MAX_STDIN_BYTES = 1_048_576
_DURATION_PATTERN = re.compile(
    r"^(?P<value>[0-9]+(?:\.[0-9]+)?)(?P<unit>ns|us|µs|ms|s)$"
)


@dataclass(frozen=True, slots=True)
class HttpxConfig:
    """Narrow immutable HTTPX execution policy."""

    timeout_seconds: float | None = None
    request_timeout_seconds: int | None = None
    threads: int | None = None
    rate_limit_per_second: int | None = None
    follow_redirects: bool = False
    probe_all_ips: bool = False

    def __post_init__(self) -> None:
        timeout = cast(object, self.timeout_seconds)
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("HTTPX execution timeout must be positive and finite")
        for label, value in (
            ("request timeout", self.request_timeout_seconds),
            ("thread count", self.threads),
            ("rate limit", self.rate_limit_per_second),
        ):
            if value is not None and (
                not isinstance(cast(object, value), int)
                or isinstance(cast(object, value), bool)
                or value <= 0
            ):
                raise ValueError(f"HTTPX {label} must be a positive integer")
        for label, value in (
            ("redirect policy", self.follow_redirects),
            ("all-IP policy", self.probe_all_ips),
        ):
            if not isinstance(cast(object, value), bool):
                raise TypeError(f"HTTPX {label} must be boolean")


@dataclass(frozen=True, slots=True)
class _PreparedTargets:
    targets: tuple[str, ...]
    hosts_by_alias: dict[str, Host]


@dataclass(frozen=True, slots=True)
class _ParseSummary:
    endpoints: tuple[HttpProbeEndpoint, ...]
    responsive_hosts: tuple[Host, ...]
    malformed_record_count: int
    out_of_scope_count: int
    duplicate_count: int

    @property
    def has_issues(self) -> bool:
        return bool(self.malformed_record_count or self.out_of_scope_count)


def _host_sort_key(host: Host) -> tuple[object, ...]:
    return (
        host.hostname or "",
        tuple(address.value for address in host.addresses),
        host.evidence,
        host.operating_system or "",
        host.description or "",
    )


def _prepare_targets(
    hosts: tuple[Host, ...],
    exact_target: ExactNetworkTarget | None = None,
) -> _PreparedTargets:
    if not isinstance(cast(object, hosts), tuple):
        raise TypeError("HTTP probe hosts must be an immutable tuple")
    normalized_hosts: list[Host] = []
    for host in hosts:
        if not isinstance(cast(object, host), Host):
            raise TypeError("HTTP probe input contains an invalid host")
        hostname = (
            normalize_dns_hostname(host.hostname)
            if host.hostname is not None
            else None
        )
        if hostname is None and not host.addresses:
            raise ValueError("HTTP probe host has no usable identity")
        normalized_hosts.append(
            Host(
                hostname=hostname,
                addresses=host.addresses,
                evidence=host.evidence,
                operating_system=host.operating_system,
                description=host.description,
            )
        )

    if exact_target is not None:
        if len(normalized_hosts) != 1:
            raise ValueError("HTTP probe input differs from the exact target")
        host = normalized_hosts[0]
        addresses = tuple(str(ip_address(item.value)) for item in host.addresses)
        if (
            host.hostname != exact_target.hostname
            or addresses != (exact_target.expected_ip,)
        ):
            raise ValueError("HTTP probe input differs from the exact target")
        return _PreparedTargets(
            (exact_target.value,),
            {
                exact_target.hostname: host,
                exact_target.expected_ip: host,
            },
        )

    aliases: dict[str, Host] = {}
    targets: set[str] = set()
    for host in sorted(set(normalized_hosts), key=_host_sort_key):
        if host.hostname is not None:
            targets.add(host.hostname)
            aliases.setdefault(host.hostname, host)
        for address in host.addresses:
            canonical = str(ip_address(address.value))
            aliases.setdefault(canonical, host)
            if host.hostname is None:
                targets.add(canonical)
    return _PreparedTargets(tuple(sorted(targets)), aliases)


def _optional_record_text(
    record: dict[object, object],
    key: str,
    *,
    maximum_length: int,
) -> str | None:
    value = record.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("invalid optional HTTPX field")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum_length
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        raise ValueError("invalid optional HTTPX field")
    return normalized


def _redirect_location(value: str | None) -> str | None:
    if value is None:
        return None
    if value.startswith("/"):
        if any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            for character in value
        ):
            raise ValueError("invalid redirect location")
        return value
    parsed = urlsplit(value)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("invalid redirect location")
    return normalize_http_url(value).value


def _response_time(value: object) -> float | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or (
            not isinstance(value, (int, float))
            and not isinstance(value, str)
        )
    ):
        raise ValueError("invalid HTTPX response time")
    if isinstance(value, (int, float)):
        duration = float(value)
    else:
        match = _DURATION_PATTERN.fullmatch(value)
        if match is None:
            raise ValueError("invalid HTTPX response time")
        duration = float(match.group("value"))
        duration *= {
            "s": 1.0,
            "ms": 0.001,
            "us": 0.000001,
            "µs": 0.000001,
            "ns": 0.000000001,
        }[match.group("unit")]
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("invalid HTTPX response time")
    return duration


def _record_endpoint(
    record: dict[object, object],
    hosts_by_alias: dict[str, Host],
    exact_target: ExactNetworkTarget | None = None,
) -> tuple[HttpProbeEndpoint, Host] | None:
    if record.get("failed") is True:
        raise ValueError("failed HTTPX record")
    url = record.get("url")
    status_code = record.get("status_code")
    if not isinstance(url, str):
        raise ValueError("HTTPX record URL is invalid")
    normalized = normalize_http_url(url)
    if exact_target is not None and (
        normalized.scheme != exact_target.scheme
        or normalized.hostname != exact_target.hostname
        or normalized.port != exact_target.port
    ):
        return None
    if normalized.hostname not in hosts_by_alias:
        return None
    if (
        not isinstance(status_code, int)
        or isinstance(status_code, bool)
        or not 100 <= status_code <= 599
    ):
        raise ValueError("HTTPX record status is invalid")
    raw_port = record.get("port")
    if raw_port is not None:
        if isinstance(raw_port, str) and raw_port.isascii() and raw_port.isdigit():
            parsed_port = int(raw_port)
        elif isinstance(raw_port, int) and not isinstance(raw_port, bool):
            parsed_port = raw_port
        else:
            raise ValueError("HTTPX record port is invalid")
        if parsed_port != normalized.port:
            raise ValueError("HTTPX record port does not match URL")
    raw_ip = record.get("host_ip")
    canonical_ip: str | None = None
    if raw_ip is not None:
        if not isinstance(raw_ip, str):
            raise ValueError("HTTPX record IP is invalid")
        canonical_ip = str(ip_address(raw_ip))
    if (
        exact_target is not None
        and canonical_ip != exact_target.expected_ip
    ):
        return None

    location = _redirect_location(
        _optional_record_text(record, "location", maximum_length=2048)
    )
    if (
        exact_target is not None
        and location is not None
        and not location.startswith("/")
    ):
        redirect = normalize_http_url(location)
        if (
            redirect.scheme != exact_target.scheme
            or redirect.hostname != exact_target.hostname
            or redirect.port != exact_target.port
        ):
            return None
    endpoint = HttpProbeEndpoint(
        url=normalized.value,
        scheme=normalized.scheme,
        hostname=normalized.hostname,
        port=normalized.port,
        status_code=status_code,
        ip_address=canonical_ip,
        content_type=_optional_record_text(
            record, "content_type", maximum_length=256
        ),
        title=_optional_record_text(record, "title", maximum_length=512),
        web_server=_optional_record_text(
            record, "webserver", maximum_length=256
        ),
        redirect_location=location,
        response_time_seconds=_response_time(record.get("time")),
    )
    return endpoint, hosts_by_alias[normalized.hostname]


def _parse_jsonl(
    stdout: str,
    hosts_by_alias: dict[str, Host],
    *,
    discard_unterminated_final_line: bool,
    exact_target: ExactNetworkTarget | None = None,
) -> _ParseSummary:
    endpoints: dict[tuple[str, str, int], HttpProbeEndpoint] = {}
    responsive_hosts: set[Host] = set()
    malformed = 0
    out_of_scope = 0
    duplicates = 0
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
        try:
            parsed = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            malformed += 1
            continue
        if not isinstance(parsed, dict):
            malformed += 1
            continue
        try:
            converted = _record_endpoint(
                cast(dict[object, object], parsed),
                hosts_by_alias,
                exact_target,
            )
        except (TypeError, ValueError):
            malformed += 1
            continue
        if converted is None:
            out_of_scope += 1
            continue
        endpoint, responsive_host = converted
        identity = (endpoint.scheme, endpoint.hostname, endpoint.port)
        if identity in endpoints:
            duplicates += 1
            continue
        endpoints[identity] = endpoint
        responsive_hosts.add(responsive_host)
    return _ParseSummary(
        endpoints=tuple(endpoints[key] for key in sorted(endpoints)),
        responsive_hosts=tuple(sorted(responsive_hosts, key=_host_sort_key)),
        malformed_record_count=malformed,
        out_of_scope_count=out_of_scope,
        duplicate_count=duplicates,
    )


class HttpxProbeProvider:
    """Build safe HTTPX invocations and map bounded JSONL into domain evidence."""

    def __init__(
        self,
        *,
        runner: ToolRunner,
        definition: ToolDefinition = HTTPX_TOOL,
        config: HttpxConfig | None = None,
        exact_target: ExactNetworkTarget | None = None,
    ) -> None:
        if not isinstance(cast(object, definition), ToolDefinition):
            raise TypeError("HTTPX provider requires a ToolDefinition")
        if definition.tool_id != HTTPX_TOOL_ID:
            raise ValueError("HTTPX provider tool identity does not match")
        self._runner = runner
        self._definition = definition
        self._config = config or HttpxConfig()
        if exact_target is not None and not isinstance(
            cast(object, exact_target), ExactNetworkTarget
        ):
            raise TypeError("HTTPX exact target is invalid")
        self._exact_target = exact_target

    @property
    def definition(self) -> ToolDefinition:
        """Return immutable HTTPX executable metadata."""
        return self._definition

    @property
    def config(self) -> HttpxConfig:
        """Return immutable supported HTTPX configuration."""
        return self._config

    def build_invocation(self, hosts: tuple[Host, ...]) -> ToolInvocation:
        """Return deterministic literal argv and newline-delimited stdin."""
        prepared = _prepare_targets(hosts, self._exact_target)
        if not prepared.targets:
            raise ValueError("HTTPX invocation requires at least one target")
        stdin = "".join(f"{target}\n" for target in prepared.targets)
        if len(stdin.encode("utf-8")) > _MAX_STDIN_BYTES:
            raise ValueError("HTTPX target input exceeds the supported limit")
        arguments: list[str] = [
            "-json",
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-status-code",
            "-content-type",
            "-title",
            "-web-server",
            "-ip",
            "-location",
            "-response-time",
        ]
        if self._config.request_timeout_seconds is not None:
            arguments.extend(
                ("-timeout", str(self._config.request_timeout_seconds))
            )
        if self._config.threads is not None:
            arguments.extend(("-threads", str(self._config.threads)))
        if self._config.rate_limit_per_second is not None:
            arguments.extend(
                ("-rate-limit", str(self._config.rate_limit_per_second))
            )
        if self._config.follow_redirects:
            arguments.append("-follow-host-redirects")
        if self._config.probe_all_ips:
            arguments.append("-probe-all-ips")
        return ToolInvocation(
            tool_id=self._definition.tool_id,
            arguments=arguments,
            timeout_seconds=self._config.timeout_seconds,
            stdin=stdin,
        )

    def probe(self, hosts: tuple[Host, ...]) -> HttpProbeProviderResult:
        """Run HTTPX once for approved resolved hosts."""
        try:
            prepared = _prepare_targets(hosts, self._exact_target)
            if not prepared.targets:
                return HttpProbeProviderResult()
            invocation = self.build_invocation(hosts)
        except (TypeError, ValueError):
            return HttpProbeProviderResult(
                status=HttpProbeProviderStatus.ERROR,
                message="HTTP probe input is invalid.",
            )
        result = self._runner.run(self._definition, invocation)
        return self._map_result(
            result,
            hosts_by_alias=prepared.hosts_by_alias,
            exact_target=self._exact_target,
        )

    @staticmethod
    def _map_result(
        result: ToolExecutionResult,
        *,
        hosts_by_alias: dict[str, Host],
        exact_target: ExactNetworkTarget | None = None,
    ) -> HttpProbeProviderResult:
        if result.status is ToolExecutionStatus.NOT_FOUND:
            return HttpProbeProviderResult(
                status=HttpProbeProviderStatus.UNAVAILABLE,
                message="HTTPX executable is unavailable.",
            )
        if result.status is ToolExecutionStatus.ERROR:
            return HttpProbeProviderResult(
                status=HttpProbeProviderStatus.ERROR,
                message="HTTPX execution failed.",
            )
        if result.status is ToolExecutionStatus.FAILURE:
            return HttpProbeProviderResult(
                status=HttpProbeProviderStatus.FAILURE,
                message="HTTPX returned a non-zero exit status.",
                truncated=result.truncated,
            )
        parsed = _parse_jsonl(
            result.stdout,
            hosts_by_alias,
            discard_unterminated_final_line=(
                result.status is ToolExecutionStatus.TIMEOUT
                or result.truncated
            ),
            exact_target=exact_target,
        )
        if result.status is ToolExecutionStatus.TIMEOUT:
            if parsed.endpoints:
                status = HttpProbeProviderStatus.PARTIAL
                message = "HTTP probing timed out with partial findings."
            else:
                status = HttpProbeProviderStatus.FAILURE
                message = "HTTP probing timed out."
        elif parsed.endpoints:
            status = (
                HttpProbeProviderStatus.PARTIAL
                if parsed.has_issues or result.truncated
                else HttpProbeProviderStatus.SUCCESS
            )
            message = (
                "HTTPX output contained incomplete or rejected records."
                if status is HttpProbeProviderStatus.PARTIAL
                else None
            )
        elif parsed.has_issues or result.truncated:
            status = HttpProbeProviderStatus.FAILURE
            message = "HTTPX output contained no valid approved endpoints."
        else:
            status = HttpProbeProviderStatus.SUCCESS
            message = None
        return HttpProbeProviderResult(
            endpoints=parsed.endpoints,
            responsive_hosts=parsed.responsive_hosts,
            status=status,
            message=message,
            malformed_record_count=parsed.malformed_record_count,
            out_of_scope_count=parsed.out_of_scope_count,
            duplicate_count=parsed.duplicate_count,
            truncated=result.truncated,
        )


# Compatibility aliases for the previous application-facing names.
HttpProbeAdapterResult = HttpProbeProviderResult
HttpProbeTransport = HttpProbeProvider

__all__ = [
    "HTTPX_TOOL",
    "HTTPX_TOOL_ID",
    "HttpProbeAdapterResult",
    "HttpProbeProvider",
    "HttpProbeProviderResult",
    "HttpProbeProviderStatus",
    "HttpProbeTransport",
    "HttpxConfig",
    "HttpxProbeProvider",
]
