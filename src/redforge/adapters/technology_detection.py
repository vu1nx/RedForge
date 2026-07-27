"""WhatWeb technology detection implemented through the ToolRunner port."""

import json
import math
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from ipaddress import IPv6Address, ip_address
from pathlib import Path
from typing import cast

from redforge.domain.endpoint import Endpoint
from redforge.domain.http_probe import normalize_http_url
from redforge.domain.scan_scope import ExactNetworkTarget
from redforge.domain.technology import Technology
from redforge.sdk.technology_detection import (
    TechnologyDetectionProvider,
    TechnologyDetectionProviderResult,
    TechnologyDetectionProviderStatus,
)
from redforge.sdk.tool import (
    ToolDefinition,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolId,
    ToolInvocation,
    ToolRunner,
)

WHATWEB_TOOL_ID = ToolId("whatweb")
WHATWEB_TOOL = ToolDefinition(
    tool_id=WHATWEB_TOOL_ID,
    display_name="WhatWeb",
    description="Detects technologies used by discovered web endpoints.",
    executable="whatweb",
    version_argument=("--version",),
    default_timeout_seconds=120.0,
    tags=("fingerprint", "technology", "web"),
)

_MAX_URL_LENGTH = 4_096
_MAX_NAME_LENGTH = 256
_MAX_VERSION_LENGTH = 128
_MAX_EVIDENCE_LENGTH = 256
_EVIDENCE_FIELDS = ("string", "os", "model", "firmware", "module")


@dataclass(frozen=True, slots=True)
class WhatWebConfig:
    """Conservative immutable WhatWeb execution and scan policy."""

    timeout_seconds: float | None = None
    open_timeout_seconds: int = 10
    read_timeout_seconds: int = 15
    max_threads: int = 10
    max_targets: int = 256
    max_input_bytes: int = 65_536
    max_output_bytes: int = 1_048_576
    max_records: int = 10_000

    def __post_init__(self) -> None:
        timeout = cast(object, self.timeout_seconds)
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0 < timeout <= 3_600
        ):
            raise ValueError(
                "WhatWeb execution timeout must be between 0 and 3600 seconds"
            )
        for label, value, maximum in (
            ("open timeout", self.open_timeout_seconds, 300),
            ("read timeout", self.read_timeout_seconds, 600),
            ("thread count", self.max_threads, 100),
            ("target count", self.max_targets, 10_000),
            ("input limit", self.max_input_bytes, 1_048_576),
            ("output limit", self.max_output_bytes, 10_485_760),
            ("record limit", self.max_records, 100_000),
        ):
            if (
                not isinstance(cast(object, value), int)
                or isinstance(cast(object, value), bool)
                or not 1 <= value <= maximum
            ):
                raise ValueError(
                    f"WhatWeb {label} must be between 1 and {maximum}"
                )


@dataclass(frozen=True, slots=True)
class _PreparedTargets:
    targets: tuple[str, ...]
    approved_targets: frozenset[str]


@dataclass(frozen=True, slots=True)
class _ParseSummary:
    technologies: tuple[Technology, ...]
    malformed_record_count: int
    out_of_scope_count: int
    duplicate_count: int
    record_count: int

    @property
    def has_issues(self) -> bool:
        return bool(
            self.malformed_record_count or self.out_of_scope_count
        )


def _valid_text(value: object, *, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in normalized
        )
    ):
        return None
    return normalized


def _endpoint_url(endpoint: Endpoint) -> str:
    if not isinstance(cast(object, endpoint), Endpoint):
        raise TypeError("technology detection input contains an invalid endpoint")
    scheme = endpoint.protocol.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("technology detection supports only HTTP endpoints")
    try:
        address = ip_address(endpoint.host)
    except ValueError:
        serialized_host = endpoint.host
    else:
        serialized_host = (
            f"[{address}]" if isinstance(address, IPv6Address) else str(address)
        )
    if (
        not isinstance(cast(object, endpoint.port), int)
        or isinstance(cast(object, endpoint.port), bool)
        or not 1 <= endpoint.port <= 65_535
    ):
        raise ValueError("technology detection endpoint port is invalid")
    path = endpoint.path or "/"
    if not isinstance(cast(object, path), str) or not path.startswith("/"):
        raise ValueError("technology detection endpoint path is invalid")
    default_port = 443 if scheme == "https" else 80
    authority = (
        serialized_host
        if endpoint.port == default_port
        else f"{serialized_host}:{endpoint.port}"
    )
    normalized = normalize_http_url(f"{scheme}://{authority}{path}").value
    if len(normalized) > _MAX_URL_LENGTH:
        raise ValueError("technology detection endpoint URL is too long")
    return normalized


def _prepare_targets(
    endpoints: tuple[Endpoint, ...],
    config: WhatWebConfig,
    exact_target: ExactNetworkTarget | None = None,
) -> _PreparedTargets:
    if not isinstance(cast(object, endpoints), tuple):
        raise TypeError("technology detection endpoints must be an immutable tuple")
    endpoint_targets = tuple(
        sorted({_endpoint_url(endpoint) for endpoint in endpoints})
    )
    if exact_target is not None:
        for target in endpoint_targets:
            normalized = normalize_http_url(target)
            if (
                normalized.scheme != exact_target.scheme
                or normalized.hostname != exact_target.hostname
                or normalized.port != exact_target.port
            ):
                raise ValueError(
                    "technology detection input differs from the exact target"
                )
        targets = (exact_target.value,) if endpoint_targets else ()
    else:
        targets = endpoint_targets
    if len(targets) > config.max_targets:
        raise ValueError("technology detection target count exceeds the limit")
    serialized_size = sum(len(target.encode("utf-8")) + 1 for target in targets)
    if serialized_size > config.max_input_bytes:
        raise ValueError("technology detection target input exceeds the limit")
    return _PreparedTargets(targets, frozenset(targets))


def _technology_sort_key(technology: Technology) -> tuple[object, ...]:
    return (
        technology.source or "",
        technology.name.casefold(),
        technology.name,
        technology.category,
        technology.version or "",
        technology.vendor or "",
        technology.description or "",
        technology.evidence,
        technology.confidence if technology.confidence is not None else -1,
    )


def _infer_category(plugin_name: str) -> str:
    name = plugin_name.casefold()
    categories = (
        ("framework", ("django", "flask", "rails", "express", "spring", "laravel")),
        ("web-server", ("nginx", "apache", "iis", "lighttpd", "caddy", "traefik")),
        ("database", ("mysql", "postgresql", "mongodb", "redis", "sqlite", "oracle")),
        ("javascript-library", ("jquery", "react", "angular", "vue", "backbone", "ember")),
        ("cms", ("wordpress", "drupal", "joomla", "ghost")),
        ("analytics", ("google analytics", "analytics", "tracking")),
        ("cdn", ("cloudflare", "akamai", "fastly")),
    )
    for category, markers in categories:
        if any(marker in name for marker in markers):
            return category
    return "other"


def _string_values(
    value: object,
    *,
    maximum: int,
) -> tuple[tuple[str, ...], int]:
    if value is None:
        return (), 0
    raw_values: tuple[object, ...]
    if isinstance(value, str):
        raw_values = (value,)
    elif isinstance(value, list):
        raw_values = tuple(cast(list[object], value))
    else:
        return (), 1
    normalized: list[str] = []
    invalid = 0
    for item in raw_values:
        text = _valid_text(item, maximum=maximum)
        if text is None:
            invalid += 1
        else:
            normalized.append(text)
    return tuple(dict.fromkeys(normalized)), invalid


def _plugin_technologies(
    plugin_name: object,
    plugin_data: object,
    *,
    source: str,
) -> tuple[tuple[Technology, ...], int]:
    name = _valid_text(plugin_name, maximum=_MAX_NAME_LENGTH)
    if name is None or not isinstance(plugin_data, dict):
        return (), 1
    data = cast(dict[object, object], plugin_data)
    certainty = data.get("certainty")
    if certainty is None:
        confidence = 100
    elif (
        isinstance(certainty, int)
        and not isinstance(certainty, bool)
        and 0 <= certainty <= 100
    ):
        confidence = certainty
    else:
        return (), 1

    raw_versions = data.get("version")
    if raw_versions in (None, "", []):
        versions = ()
        invalid = 0
    else:
        versions, invalid = _string_values(
            raw_versions,
            maximum=_MAX_VERSION_LENGTH,
        )
        if not versions:
            return (), invalid or 1
    if not versions:
        versions_or_none: tuple[str | None, ...] = (None,)
    else:
        versions_or_none = cast(tuple[str | None, ...], versions)

    evidence: list[str] = []
    for field in _EVIDENCE_FIELDS:
        values, field_invalid = _string_values(
            data.get(field),
            maximum=_MAX_EVIDENCE_LENGTH,
        )
        invalid += field_invalid
        evidence.extend(f"{field}: {value}" for value in values)
    normalized_evidence = tuple(dict.fromkeys(evidence))
    return (
        tuple(
            Technology(
                name=name,
                category=_infer_category(name),
                version=version,
                source=source,
                evidence=normalized_evidence,
                confidence=confidence,
            )
            for version in versions_or_none
        ),
        invalid,
    )


def _parse_json(
    output: str,
    *,
    approved_targets: frozenset[str],
    max_records: int,
) -> _ParseSummary:
    if not output.strip():
        return _ParseSummary((), 0, 0, 0, 0)
    try:
        parsed = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return _ParseSummary((), 1, 0, 0, 1)
    if not isinstance(parsed, list):
        return _ParseSummary((), 1, 0, 0, 1)
    records = cast(list[object], parsed)
    if len(records) > max_records:
        return _ParseSummary((), 1, 0, 0, len(records))

    technologies: dict[Technology, Technology] = {}
    malformed = 0
    out_of_scope = 0
    duplicates = 0
    for item in records:
        if not isinstance(item, dict):
            malformed += 1
            continue
        record = cast(dict[object, object], item)
        target = record.get("target")
        if not isinstance(target, str):
            malformed += 1
            continue
        try:
            source = normalize_http_url(target).value
        except (TypeError, ValueError):
            malformed += 1
            continue
        if source not in approved_targets:
            out_of_scope += 1
            continue
        plugins = record.get("plugins", {})
        if not isinstance(plugins, dict):
            malformed += 1
            continue
        for plugin_name, plugin_data in cast(
            dict[object, object], plugins
        ).items():
            observations, invalid = _plugin_technologies(
                plugin_name,
                plugin_data,
                source=source,
            )
            malformed += invalid
            for technology in observations:
                if technology in technologies:
                    duplicates += 1
                else:
                    technologies[technology] = technology
    ordered = tuple(sorted(technologies.values(), key=_technology_sort_key))
    return _ParseSummary(
        ordered,
        malformed,
        out_of_scope,
        duplicates,
        len(records),
    )


class WhatWebTechnologyDetectionProvider:
    """Build safe WhatWeb invocations and normalize its JSON evidence."""

    def __init__(
        self,
        *,
        runner: ToolRunner,
        definition: ToolDefinition = WHATWEB_TOOL,
        config: WhatWebConfig | None = None,
        exact_target: ExactNetworkTarget | None = None,
    ) -> None:
        if not isinstance(cast(object, definition), ToolDefinition):
            raise TypeError("WhatWeb provider requires a ToolDefinition")
        if definition.tool_id != WHATWEB_TOOL_ID:
            raise ValueError("WhatWeb provider tool identity does not match")
        self._runner = runner
        self._definition = definition
        self._config = config or WhatWebConfig()
        if exact_target is not None and not isinstance(
            cast(object, exact_target), ExactNetworkTarget
        ):
            raise TypeError("WhatWeb exact target is invalid")
        self._exact_target = exact_target

    @property
    def definition(self) -> ToolDefinition:
        """Return immutable WhatWeb executable metadata."""
        return self._definition

    @property
    def config(self) -> WhatWebConfig:
        """Return immutable supported WhatWeb configuration."""
        return self._config

    def _build_invocation(
        self,
        endpoints: tuple[Endpoint, ...],
        *,
        output_path: Path,
    ) -> ToolInvocation:
        """Return one deterministic bounded batch invocation."""
        prepared = _prepare_targets(
            endpoints,
            self._config,
            self._exact_target,
        )
        if not prepared.targets:
            raise ValueError("WhatWeb invocation requires at least one target")
        arguments = (
            f"--log-json={output_path}",
            "--quiet",
            "--colour=never",
            "--no-errors",
            "--no-cookies",
            "--aggression=1",
            "--follow-redirect=never",
            "--max-redirects=0",
            f"--max-threads={self._config.max_threads}",
            f"--open-timeout={self._config.open_timeout_seconds}",
            f"--read-timeout={self._config.read_timeout_seconds}",
            *prepared.targets,
        )
        return ToolInvocation(
            tool_id=self._definition.tool_id,
            arguments=arguments,
            timeout_seconds=self._config.timeout_seconds,
        )

    def detect(
        self,
        endpoints: tuple[Endpoint, ...],
    ) -> TechnologyDetectionProviderResult:
        """Run WhatWeb once for the approved endpoint batch."""
        try:
            prepared = _prepare_targets(
                endpoints,
                self._config,
                self._exact_target,
            )
        except (TypeError, ValueError):
            return TechnologyDetectionProviderResult(
                status=TechnologyDetectionProviderStatus.ERROR,
                message="Technology detection input is invalid.",
            )
        if not prepared.targets:
            return TechnologyDetectionProviderResult()

        output_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix="redforge-whatweb-",
                suffix=".json",
                delete=False,
            ) as output_file:
                output_path = Path(output_file.name)
            invocation = self._build_invocation(
                endpoints,
                output_path=output_path,
            )
            result = self._runner.run(self._definition, invocation)
            output, output_truncated = self._output(
                output_path,
                result,
            )
        except Exception:
            return TechnologyDetectionProviderResult(
                status=TechnologyDetectionProviderStatus.ERROR,
                message="WhatWeb execution failed.",
            )
        finally:
            if output_path is not None:
                with suppress(OSError):
                    output_path.unlink(missing_ok=True)
        return self._map_result(
            result,
            output=output,
            output_truncated=output_truncated,
            approved_targets=prepared.approved_targets,
        )

    def _output(
        self,
        output_path: Path,
        result: ToolExecutionResult,
    ) -> tuple[str, bool]:
        if output_path.is_file():
            output_size = output_path.stat().st_size
            if output_size > self._config.max_output_bytes:
                return "", True
            if output_size:
                return (
                    output_path.read_text(
                        encoding="utf-8",
                        errors="replace",
                    ),
                    False,
                )
        encoded = result.stdout.encode("utf-8")
        if len(encoded) > self._config.max_output_bytes:
            return (
                encoded[: self._config.max_output_bytes].decode(
                    "utf-8", errors="replace"
                ),
                True,
            )
        return result.stdout, result.truncated

    def _map_result(
        self,
        result: ToolExecutionResult,
        *,
        output: str,
        output_truncated: bool,
        approved_targets: frozenset[str],
    ) -> TechnologyDetectionProviderResult:
        if (
            not isinstance(cast(object, result), ToolExecutionResult)
            or result.tool_id != WHATWEB_TOOL_ID
        ):
            return TechnologyDetectionProviderResult(
                status=TechnologyDetectionProviderStatus.ERROR,
                message="WhatWeb execution returned an invalid result.",
            )
        if result.status is ToolExecutionStatus.NOT_FOUND:
            return TechnologyDetectionProviderResult(
                status=TechnologyDetectionProviderStatus.UNAVAILABLE,
                message="WhatWeb executable is unavailable.",
            )
        if result.status is ToolExecutionStatus.ERROR:
            return TechnologyDetectionProviderResult(
                status=TechnologyDetectionProviderStatus.ERROR,
                message="WhatWeb execution failed.",
            )
        if result.status is ToolExecutionStatus.FAILURE:
            return TechnologyDetectionProviderResult(
                status=TechnologyDetectionProviderStatus.FAILURE,
                message="WhatWeb returned a non-zero exit status.",
                truncated=output_truncated,
            )

        parsed = _parse_json(
            output,
            approved_targets=approved_targets,
            max_records=self._config.max_records,
        )
        if result.status is ToolExecutionStatus.TIMEOUT:
            if parsed.technologies:
                status = TechnologyDetectionProviderStatus.PARTIAL
                message = "Technology detection timed out with partial findings."
            else:
                status = TechnologyDetectionProviderStatus.FAILURE
                message = "Technology detection timed out."
        elif parsed.technologies:
            status = (
                TechnologyDetectionProviderStatus.PARTIAL
                if parsed.has_issues or output_truncated
                else TechnologyDetectionProviderStatus.SUCCESS
            )
            message = (
                "WhatWeb output contained incomplete or rejected records."
                if status is TechnologyDetectionProviderStatus.PARTIAL
                else None
            )
        elif parsed.record_count or parsed.has_issues or output_truncated:
            status = TechnologyDetectionProviderStatus.FAILURE
            message = "WhatWeb output contained no valid approved evidence."
        else:
            status = TechnologyDetectionProviderStatus.SUCCESS
            message = None
        return TechnologyDetectionProviderResult(
            technologies=parsed.technologies,
            status=status,
            message=message,
            malformed_record_count=parsed.malformed_record_count,
            out_of_scope_count=parsed.out_of_scope_count,
            duplicate_count=parsed.duplicate_count,
            truncated=output_truncated,
        )


# Compatibility names retained without a second adapter implementation.
TechnologyDetectionAdapter = WhatWebTechnologyDetectionProvider
TechnologyDetectionResult = TechnologyDetectionProviderResult
TechnologyDetector = TechnologyDetectionProvider

__all__ = [
    "WHATWEB_TOOL",
    "WHATWEB_TOOL_ID",
    "TechnologyDetectionAdapter",
    "TechnologyDetectionResult",
    "TechnologyDetector",
    "WhatWebConfig",
    "WhatWebTechnologyDetectionProvider",
]
