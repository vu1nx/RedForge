"""Nuclei v3 adapter implemented exclusively through the ToolRunner port."""

import hashlib
import json
import math
from dataclasses import dataclass
from typing import cast

from redforge.domain.http_probe import HttpProbeEndpoint, normalize_http_url
from redforge.sdk.tool import (
    ToolDefinition,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolId,
    ToolInvocation,
    ToolRunner,
)
from redforge.sdk.vulnerability import (
    EvidenceReference,
    ExtractorName,
    Finding,
    FindingCollection,
    FindingId,
    FindingSeverity,
    FindingStatus,
    MatcherName,
    TemplateId,
    TemplateReference,
    VulnerabilityDetectionResult,
    VulnerabilityDetectionStatus,
)

NUCLEI_TOOL_ID = ToolId("nuclei")
NUCLEI_TOOL = ToolDefinition(
    tool_id=NUCLEI_TOOL_ID,
    display_name="Nuclei",
    description="Runs template-based vulnerability detection.",
    executable="nuclei",
    version_argument=("-version",),
    default_timeout_seconds=600.0,
    tags=("detection", "security", "vulnerability"),
)

_MAX_STDIN_BYTES = 1_048_576
_MAX_TITLE_LENGTH = 512
_MAX_NAME_LENGTH = 256


@dataclass(frozen=True, slots=True)
class NucleiConfig:
    """Narrow immutable execution and parser limits for Nuclei."""

    timeout_seconds: float | None = None
    request_timeout_seconds: int = 10
    rate_limit_per_second: int = 50
    concurrency: int = 10
    max_targets: int = 2_000
    max_input_bytes: int = _MAX_STDIN_BYTES
    max_output_bytes: int = 4_194_304
    max_records: int = 20_000

    def __post_init__(self) -> None:
        timeout = cast(object, self.timeout_seconds)
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
            or timeout > 86_400
        ):
            raise ValueError("Nuclei execution timeout is invalid")
        for label, value, maximum in (
            ("request timeout", self.request_timeout_seconds, 300),
            ("rate limit", self.rate_limit_per_second, 10_000),
            ("concurrency", self.concurrency, 1_000),
            ("target count", self.max_targets, 100_000),
            ("input size", self.max_input_bytes, 16_777_216),
            ("output size", self.max_output_bytes, 67_108_864),
            ("record count", self.max_records, 1_000_000),
        ):
            if (
                not isinstance(cast(object, value), int)
                or isinstance(cast(object, value), bool)
                or not 1 <= value <= maximum
            ):
                raise ValueError(f"Nuclei {label} is invalid")


@dataclass(frozen=True, slots=True)
class _PreparedTargets:
    targets: tuple[str, ...]
    evidence_by_target: dict[str, EvidenceReference]


@dataclass(frozen=True, slots=True)
class _ParseResult:
    collection: FindingCollection
    malformed: int
    duplicates: int
    unassociated: int
    records: int


def _clean_text(value: object, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("Nuclei record text is invalid")
    return value


def _prepare_targets(
    endpoints: tuple[HttpProbeEndpoint, ...],
    config: NucleiConfig,
) -> _PreparedTargets:
    if not isinstance(cast(object, endpoints), tuple):
        raise TypeError("Nuclei endpoints must be an immutable tuple")
    targets: set[str] = set()
    for endpoint in endpoints:
        if not isinstance(cast(object, endpoint), HttpProbeEndpoint):
            raise TypeError("Nuclei input contains an invalid endpoint")
        targets.add(normalize_http_url(endpoint.url).value)
    ordered = tuple(sorted(targets))
    if len(ordered) > config.max_targets:
        raise ValueError("Nuclei target count exceeds the limit")
    stdin_size = sum(len(item.encode("utf-8")) + 1 for item in ordered)
    if stdin_size > config.max_input_bytes:
        raise ValueError("Nuclei input exceeds the size limit")
    return _PreparedTargets(
        ordered,
        {
            target: EvidenceReference(f"http_endpoint_{index:06d}")
            for index, target in enumerate(ordered, start=1)
        },
    )


def _optional_name(
    record: dict[object, object],
    field_name: str,
    model: type[MatcherName] | type[ExtractorName],
) -> MatcherName | ExtractorName | None:
    value = record.get(field_name)
    if value is None:
        return None
    return model(_clean_text(value, maximum=_MAX_NAME_LENGTH))


def _finding_from_record(
    record: dict[object, object],
    evidence_by_target: dict[str, EvidenceReference],
) -> Finding | None:
    template_id = TemplateId(
        _clean_text(record.get("template-id"), maximum=_MAX_NAME_LENGTH)
    )
    info = record.get("info")
    if not isinstance(info, dict):
        raise ValueError("Nuclei record info is invalid")
    typed_info = cast(dict[object, object], info)
    title = _clean_text(typed_info.get("name"), maximum=_MAX_TITLE_LENGTH)
    severity_value = _clean_text(
        typed_info.get("severity"),
        maximum=16,
    ).lower()
    try:
        severity = FindingSeverity(severity_value)
    except ValueError:
        severity = FindingSeverity.UNKNOWN
    protocol = _clean_text(record.get("type"), maximum=32).lower()
    if protocol != "http":
        raise ValueError("Nuclei record protocol is unsupported")
    host = _clean_text(record.get("host"), maximum=4096)
    try:
        target = normalize_http_url(host).value
    except ValueError:
        raise ValueError("Nuclei record host is invalid") from None
    evidence = evidence_by_target.get(target)
    if evidence is None:
        return None
    matcher = _optional_name(record, "matcher-name", MatcherName)
    extractor = _optional_name(record, "extractor-name", ExtractorName)
    identity_material = "\x1f".join(
        (
            template_id.value,
            evidence.value,
            matcher.value if matcher is not None else "",
            extractor.value if extractor is not None else "",
        )
    ).encode("utf-8")
    identity = FindingId(
        f"nuclei_{hashlib.sha256(identity_material).hexdigest()}"
    )
    return Finding(
        finding_id=identity,
        template=TemplateReference(template_id),
        title=title,
        severity=severity,
        status=FindingStatus.DETECTED,
        evidence=evidence,
        matcher=cast(MatcherName | None, matcher),
        extractor=cast(ExtractorName | None, extractor),
    )


def _finding_value_key(finding: Finding) -> tuple[object, ...]:
    return (
        finding.template.template_id.value,
        finding.evidence.value,
        finding.title.casefold(),
        finding.title,
        finding.severity.value,
        finding.status.value,
        finding.matcher.value if finding.matcher is not None else "",
        finding.extractor.value if finding.extractor is not None else "",
        finding.finding_id.value,
    )


def _parse_jsonl(
    output: str,
    *,
    evidence_by_target: dict[str, EvidenceReference],
    max_records: int,
    discard_unterminated_final_line: bool,
) -> _ParseResult:
    if not output:
        return _ParseResult(FindingCollection(), 0, 0, 0, 0)
    lines = output.splitlines()
    malformed = 0
    if discard_unterminated_final_line and not output.endswith(("\n", "\r")):
        lines = lines[:-1]
        malformed += 1
    nonempty = tuple(line for line in lines if line.strip())
    if len(nonempty) > max_records:
        return _ParseResult(
            FindingCollection(),
            malformed + 1,
            0,
            0,
            len(nonempty),
        )
    findings: dict[FindingId, Finding] = {}
    duplicates = 0
    unassociated = 0
    for line in nonempty:
        try:
            raw = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            malformed += 1
            continue
        if not isinstance(raw, dict):
            malformed += 1
            continue
        try:
            finding = _finding_from_record(
                cast(dict[object, object], raw),
                evidence_by_target,
            )
        except (TypeError, ValueError):
            malformed += 1
            continue
        if finding is None:
            unassociated += 1
            continue
        existing = findings.get(finding.finding_id)
        if existing is not None:
            duplicates += 1
            if existing != finding:
                malformed += 1
                findings[finding.finding_id] = min(
                    (existing, finding),
                    key=_finding_value_key,
                )
            continue
        findings[finding.finding_id] = finding
    return _ParseResult(
        FindingCollection(tuple(findings.values())),
        malformed,
        duplicates,
        unassociated,
        len(nonempty),
    )


class NucleiVulnerabilityDetectionProvider:
    """Build one bounded Nuclei invocation and normalize JSONL findings."""

    def __init__(
        self,
        *,
        runner: ToolRunner,
        definition: ToolDefinition = NUCLEI_TOOL,
        config: NucleiConfig | None = None,
    ) -> None:
        if not isinstance(cast(object, definition), ToolDefinition):
            raise TypeError("Nuclei provider requires a ToolDefinition")
        if definition.tool_id != NUCLEI_TOOL_ID:
            raise ValueError("Nuclei provider tool identity does not match")
        self._runner = runner
        self._definition = definition
        self._config = config or NucleiConfig()

    @property
    def definition(self) -> ToolDefinition:
        return self._definition

    def build_invocation(
        self,
        endpoints: tuple[HttpProbeEndpoint, ...],
    ) -> ToolInvocation:
        """Build a deterministic stdin-fed Nuclei v3 invocation."""
        prepared = _prepare_targets(endpoints, self._config)
        if not prepared.targets:
            raise ValueError("Nuclei invocation requires at least one target")
        return ToolInvocation(
            tool_id=self._definition.tool_id,
            arguments=(
                "-jsonl",
                "-silent",
                "-no-color",
                "-omit-raw",
                "-omit-template",
                "-disable-update-check",
                "-no-interactsh",
                "-no-httpx",
                "-retries",
                "0",
                "-timeout",
                str(self._config.request_timeout_seconds),
                "-rate-limit",
                str(self._config.rate_limit_per_second),
                "-concurrency",
                str(self._config.concurrency),
            ),
            timeout_seconds=self._config.timeout_seconds,
            stdin="".join(f"{target}\n" for target in prepared.targets),
        )

    def detect(
        self,
        endpoints: tuple[HttpProbeEndpoint, ...],
    ) -> VulnerabilityDetectionResult:
        """Execute through ToolRunner and return only normalized SDK findings."""
        try:
            prepared = _prepare_targets(endpoints, self._config)
        except (TypeError, ValueError):
            return VulnerabilityDetectionResult(
                status=VulnerabilityDetectionStatus.ERROR,
                message="Vulnerability detection input is invalid.",
            )
        if not prepared.targets:
            return VulnerabilityDetectionResult()
        try:
            invocation = self.build_invocation(endpoints)
            result = self._runner.run(self._definition, invocation)
        except Exception:
            return VulnerabilityDetectionResult(
                status=VulnerabilityDetectionStatus.ERROR,
                message="Nuclei execution failed.",
            )
        return self._map_result(result, prepared)

    def _map_result(
        self,
        result: ToolExecutionResult,
        prepared: _PreparedTargets,
    ) -> VulnerabilityDetectionResult:
        if (
            not isinstance(cast(object, result), ToolExecutionResult)
            or result.tool_id != NUCLEI_TOOL_ID
        ):
            return VulnerabilityDetectionResult(
                status=VulnerabilityDetectionStatus.ERROR,
                message="Nuclei execution returned an invalid result.",
            )
        if result.status is ToolExecutionStatus.NOT_FOUND:
            return VulnerabilityDetectionResult(
                status=VulnerabilityDetectionStatus.UNAVAILABLE,
                message="Nuclei executable is unavailable.",
            )
        if result.status is ToolExecutionStatus.ERROR:
            return VulnerabilityDetectionResult(
                status=VulnerabilityDetectionStatus.ERROR,
                message="Nuclei execution failed.",
            )
        if result.status is ToolExecutionStatus.FAILURE:
            return VulnerabilityDetectionResult(
                status=VulnerabilityDetectionStatus.FAILURE,
                message="Nuclei returned a non-zero exit status.",
                truncated=result.truncated,
            )
        if result.status is ToolExecutionStatus.TIMEOUT:
            return VulnerabilityDetectionResult(
                status=VulnerabilityDetectionStatus.FAILURE,
                message="Nuclei execution timed out.",
                truncated=result.truncated,
            )

        encoded = result.stdout.encode("utf-8")
        output_truncated = result.truncated or len(encoded) > self._config.max_output_bytes
        output = (
            encoded[: self._config.max_output_bytes].decode(
                "utf-8",
                errors="replace",
            )
            if len(encoded) > self._config.max_output_bytes
            else result.stdout
        )
        parsed = _parse_jsonl(
            output,
            evidence_by_target=prepared.evidence_by_target,
            max_records=self._config.max_records,
            discard_unterminated_final_line=output_truncated,
        )
        has_findings = bool(len(parsed.collection))
        has_issues = bool(
            parsed.malformed or parsed.unassociated or output_truncated
        )
        if has_findings:
            status = (
                VulnerabilityDetectionStatus.PARTIAL
                if has_issues
                else VulnerabilityDetectionStatus.SUCCESS
            )
        elif parsed.records or has_issues:
            status = VulnerabilityDetectionStatus.FAILURE
        else:
            status = VulnerabilityDetectionStatus.SUCCESS
        message = (
            "Nuclei output contained incomplete or rejected records."
            if status is VulnerabilityDetectionStatus.PARTIAL
            else (
                "Nuclei output contained no valid approved findings."
                if status is VulnerabilityDetectionStatus.FAILURE
                else None
            )
        )
        return VulnerabilityDetectionResult(
            findings=parsed.collection,
            status=status,
            message=message,
            malformed_record_count=parsed.malformed,
            duplicate_count=parsed.duplicates,
            unassociated_record_count=parsed.unassociated,
            truncated=output_truncated,
        )
