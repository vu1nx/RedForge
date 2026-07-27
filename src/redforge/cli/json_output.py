"""Pure, bounded JSON contracts for the application-facing CLI."""

import json
from dataclasses import dataclass
from enum import StrEnum

from redforge.application import (
    PreflightResult,
    ReadinessCheckResult,
    ReadinessReason,
    ReadinessStatus,
    ScanResult,
)
from redforge.runtime import DeadlineViolation, StateLimitViolation

JSON_SCHEMA_VERSION = 1


class JsonOutcomeType(StrEnum):
    """Stable application phase represented by one JSON document."""

    COMPLETED = "completed"
    NOT_READY = "not_ready"
    INVALID_INPUT = "invalid_input"
    INTERRUPTED = "interrupted"
    INTERNAL_ERROR = "internal_error"


class JsonReasonCode(StrEnum):
    """Stable CLI-level reason codes not sourced from exception messages."""

    INVALID_TARGET = "invalid_target"
    CONFIGURATION_FILE_UNAVAILABLE = "configuration_file_unavailable"
    CONFIGURATION_PARSE_FAILED = "configuration_parse_failed"
    CONFIGURATION_VERSION_MISSING = "configuration_version_missing"
    CONFIGURATION_VERSION_UNSUPPORTED = "configuration_version_unsupported"
    CONFIGURATION_FIELD_UNKNOWN = "configuration_field_unknown"
    CONFIGURATION_VALUE_INVALID = "configuration_value_invalid"
    CONFIGURATION_PROFILE_INCOMPATIBLE = "configuration_profile_incompatible"
    COMPOSITION_FAILED = "composition_failed"
    STATE_LIMIT_EXCEEDED = "state_limit_exceeded"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    INTERRUPTED = "interrupted"
    INTERNAL_ERROR = "internal_error"


class JsonPolicyViolationType(StrEnum):
    """Stable policy categories exposed by the CLI."""

    STATE_LIMIT = "state_limit"
    DEADLINE = "deadline"


@dataclass(frozen=True, slots=True)
class JsonPreflightFailure:
    """One sanitized, typed non-ready check."""

    subject_type: str
    subject_id: str
    status: str
    reason_code: str
    message: str


@dataclass(frozen=True, slots=True)
class JsonPreflightSummary:
    """Bounded readiness aggregate with failures only."""

    ready: bool
    checks_total: int
    checks_failed: int
    failures: tuple[JsonPreflightFailure, ...] = ()


@dataclass(frozen=True, slots=True)
class JsonPolicyViolation:
    """Fixed policy payload with nulls for inapplicable details."""

    type: JsonPolicyViolationType
    reason_code: JsonReasonCode
    state_key: str | None = None
    observed: int | None = None
    allowed: int | None = None


@dataclass(frozen=True, slots=True)
class JsonError:
    """Sanitized CLI failure independent from Python exceptions."""

    reason_code: JsonReasonCode
    message: str


@dataclass(frozen=True, slots=True)
class JsonScanOutcome:
    """Complete versioned machine-output document."""

    schema_version: int
    outcome: JsonOutcomeType
    exit_code: int
    target: str | None
    preset: str | None
    runtime_status: str | None
    accepted: bool | None
    capabilities_executed: int
    preflight: JsonPreflightSummary | None
    policy_violation: JsonPolicyViolation | None
    error: JsonError | None


type JsonPrimitive = str | int | bool | None
type JsonValue = JsonPrimitive | list[JsonValue] | dict[str, JsonValue]


def build_completed_json_outcome(
    result: ScanResult,
    *,
    preset: str,
    exit_code: int,
) -> JsonScanOutcome:
    """Extract only stable public summary fields from an executed scan."""
    return JsonScanOutcome(
        schema_version=JSON_SCHEMA_VERSION,
        outcome=JsonOutcomeType.COMPLETED,
        exit_code=exit_code,
        target=result.config.scope.root.value,
        preset=preset,
        runtime_status=result.runtime_status.value,
        accepted=result.accepted,
        capabilities_executed=len(
            result.pipeline_result.executed_capabilities
        ),
        preflight=build_json_preflight_summary(result.preflight),
        policy_violation=_build_json_policy_violation(
            result.policy_violation
        ),
        error=None,
    )


def build_json_preflight_summary(
    result: PreflightResult,
) -> JsonPreflightSummary:
    """Build a deterministic readiness aggregate without implementation data."""
    failures = tuple(
        _build_json_preflight_failure(check)
        for check in result.checks
        if check.status is not ReadinessStatus.READY
    )
    return JsonPreflightSummary(
        ready=result.ready,
        checks_total=len(result.checks),
        checks_failed=len(failures),
        failures=failures,
    )


def build_error_json_outcome(
    *,
    outcome: JsonOutcomeType,
    exit_code: int,
    reason_code: JsonReasonCode,
    message: str,
    target: str | None = None,
    preset: str | None = None,
    preflight: PreflightResult | None = None,
) -> JsonScanOutcome:
    """Build one handled non-runtime outcome from fixed sanitized inputs."""
    return JsonScanOutcome(
        schema_version=JSON_SCHEMA_VERSION,
        outcome=outcome,
        exit_code=exit_code,
        target=target,
        preset=preset,
        runtime_status=None,
        accepted=None,
        capabilities_executed=0,
        preflight=(
            build_json_preflight_summary(preflight)
            if preflight is not None
            else None
        ),
        policy_violation=None,
        error=JsonError(reason_code=reason_code, message=message),
    )


def build_preflight_json_outcome(
    result: PreflightResult,
    *,
    exit_code: int,
    target: str,
    preset: str,
) -> JsonScanOutcome:
    """Build a non-runtime readiness outcome with typed failure details."""
    return JsonScanOutcome(
        schema_version=JSON_SCHEMA_VERSION,
        outcome=JsonOutcomeType.NOT_READY,
        exit_code=exit_code,
        target=target,
        preset=preset,
        runtime_status=None,
        accepted=None,
        capabilities_executed=0,
        preflight=build_json_preflight_summary(result),
        policy_violation=None,
        error=None,
    )


def render_json_outcome(outcome: JsonScanOutcome) -> str:
    """Serialize one explicit DTO with stable field and list ordering."""
    payload: dict[str, JsonValue] = {
        "schema_version": outcome.schema_version,
        "outcome": outcome.outcome.value,
        "exit_code": outcome.exit_code,
        "target": outcome.target,
        "preset": outcome.preset,
        "runtime_status": outcome.runtime_status,
        "accepted": outcome.accepted,
        "capabilities_executed": outcome.capabilities_executed,
        "preflight": _preflight_payload(outcome.preflight),
        "policy_violation": _policy_payload(outcome.policy_violation),
        "error": _error_payload(outcome.error),
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def _build_json_preflight_failure(
    check: ReadinessCheckResult,
) -> JsonPreflightFailure:
    reason = check.reason
    if reason is None:
        raise ValueError("non-ready check has no reason")
    subject = check.subject
    identity = (
        subject.tool_id.value
        if subject.tool_id is not None
        else (
            subject.capability_id.value
            if subject.capability_id is not None
            else subject.provider_role.value
            if subject.provider_role is not None
            else None
        )
    )
    if identity is None:
        raise ValueError("readiness subject has no identity")
    return JsonPreflightFailure(
        subject_type=subject.kind.value,
        subject_id=identity,
        status=check.status.value,
        reason_code=reason.value,
        message=_readiness_message(reason),
    )


def _build_json_policy_violation(
    violation: StateLimitViolation | DeadlineViolation | None,
) -> JsonPolicyViolation | None:
    if isinstance(violation, StateLimitViolation):
        return JsonPolicyViolation(
            type=JsonPolicyViolationType.STATE_LIMIT,
            reason_code=JsonReasonCode.STATE_LIMIT_EXCEEDED,
            state_key=violation.state_key.name,
            observed=violation.observed,
            allowed=violation.allowed,
        )
    if isinstance(violation, DeadlineViolation):
        return JsonPolicyViolation(
            type=JsonPolicyViolationType.DEADLINE,
            reason_code=JsonReasonCode.DEADLINE_EXCEEDED,
        )
    return None


def _preflight_payload(
    summary: JsonPreflightSummary | None,
) -> dict[str, JsonValue] | None:
    if summary is None:
        return None
    failures: list[JsonValue] = [
        {
            "subject_type": failure.subject_type,
            "subject_id": failure.subject_id,
            "status": failure.status,
            "reason_code": failure.reason_code,
            "message": failure.message,
        }
        for failure in summary.failures
    ]
    return {
        "ready": summary.ready,
        "checks_total": summary.checks_total,
        "checks_failed": summary.checks_failed,
        "failures": failures,
    }


def _policy_payload(
    violation: JsonPolicyViolation | None,
) -> dict[str, JsonValue] | None:
    if violation is None:
        return None
    return {
        "type": violation.type.value,
        "reason_code": violation.reason_code.value,
        "state_key": violation.state_key,
        "observed": violation.observed,
        "allowed": violation.allowed,
    }


def _error_payload(error: JsonError | None) -> dict[str, JsonValue] | None:
    if error is None:
        return None
    return {
        "reason_code": error.reason_code.value,
        "message": error.message,
    }


def _readiness_message(reason: ReadinessReason) -> str:
    messages = {
        ReadinessReason.FACTORY_MISSING: (
            "required capability factory is unavailable"
        ),
        ReadinessReason.FACTORY_BINDING_MISMATCH: (
            "required capability binding is incompatible"
        ),
        ReadinessReason.TOOL_DEFINITION_MISSING: (
            "required tool definition is unavailable"
        ),
        ReadinessReason.TOOL_PROBE_MISSING: (
            "tool readiness probe is unavailable"
        ),
        ReadinessReason.EXECUTABLE_UNAVAILABLE: (
            "required executable is unavailable"
        ),
        ReadinessReason.PROVIDER_ABSENT: (
            "required provider is not configured"
        ),
        ReadinessReason.PROVIDER_MISCONFIGURED: (
            "required provider is misconfigured"
        ),
        ReadinessReason.BINDING_INCOMPATIBLE: (
            "required binding is incompatible"
        ),
        ReadinessReason.PROBE_FAILED: "readiness probe failed",
    }
    return messages[reason]
