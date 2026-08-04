"""Immutable provider-neutral diagnostic event contracts."""

from dataclasses import dataclass, fields
from enum import StrEnum
from types import MappingProxyType
from typing import cast

DIAGNOSTIC_EVENT_SCHEMA_VERSION = 1


class DiagnosticSeverity(StrEnum):
    """Fixed diagnostic severity independent from logging frameworks."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class DiagnosticEventType(StrEnum):
    """Stable lifecycle event identities emitted by current integrations."""

    SCAN_PREPARATION_STARTED = "scan_preparation_started"
    SCAN_PREPARATION_COMPLETED = "scan_preparation_completed"
    SCAN_PREFLIGHT_STARTED = "scan_preflight_started"
    SCAN_PREFLIGHT_COMPLETED = "scan_preflight_completed"
    SCAN_PREFLIGHT_FAILED = "scan_preflight_failed"
    SCAN_BUILD_STARTED = "scan_build_started"
    SCAN_BUILD_COMPLETED = "scan_build_completed"
    SCAN_EXECUTION_STARTED = "scan_execution_started"
    SCAN_EXECUTION_COMPLETED = "scan_execution_completed"
    CAPABILITY_STARTED = "capability_started"
    CAPABILITY_COMPLETED = "capability_completed"
    CAPABILITY_PARTIAL = "capability_partial"
    CAPABILITY_FAILED = "capability_failed"
    CAPABILITY_ERROR = "capability_error"
    POLICY_LIMIT_EXCEEDED = "policy_limit_exceeded"
    POLICY_DEADLINE_EXCEEDED = "policy_deadline_exceeded"
    SCAN_RESULT_CREATED = "scan_result_created"


_EVENT_MESSAGES = MappingProxyType(
    {
        DiagnosticEventType.SCAN_PREPARATION_STARTED: (
            "Scan preparation started"
        ),
        DiagnosticEventType.SCAN_PREPARATION_COMPLETED: (
            "Scan preparation completed"
        ),
        DiagnosticEventType.SCAN_PREFLIGHT_STARTED: "Scan preflight started",
        DiagnosticEventType.SCAN_PREFLIGHT_COMPLETED: (
            "Scan preflight completed"
        ),
        DiagnosticEventType.SCAN_PREFLIGHT_FAILED: "Scan preflight failed",
        DiagnosticEventType.SCAN_BUILD_STARTED: "Scan build started",
        DiagnosticEventType.SCAN_BUILD_COMPLETED: "Scan build completed",
        DiagnosticEventType.SCAN_EXECUTION_STARTED: "Scan execution started",
        DiagnosticEventType.SCAN_EXECUTION_COMPLETED: (
            "Scan execution completed"
        ),
        DiagnosticEventType.CAPABILITY_STARTED: "Capability started",
        DiagnosticEventType.CAPABILITY_COMPLETED: "Capability completed",
        DiagnosticEventType.CAPABILITY_PARTIAL: (
            "Capability completed partially"
        ),
        DiagnosticEventType.CAPABILITY_FAILED: "Capability failed",
        DiagnosticEventType.CAPABILITY_ERROR: "Capability error",
        DiagnosticEventType.POLICY_LIMIT_EXCEEDED: "State limit exceeded",
        DiagnosticEventType.POLICY_DEADLINE_EXCEEDED: (
            "Execution deadline exceeded"
        ),
        DiagnosticEventType.SCAN_RESULT_CREATED: "Scan result created",
    }
)


@dataclass(frozen=True, slots=True)
class DiagnosticFields:
    """Closed set of bounded fields safe for structured diagnostics."""

    preset: str | None = None
    composition_profile: str | None = None
    capability_id: str | None = None
    runtime_status: str | None = None
    partial_reasons: tuple[StrEnum, ...] | None = None
    accepted: bool | None = None
    history_count: int | None = None
    planned_steps: int | None = None
    preflight_checks_total: int | None = None
    preflight_checks_failed: int | None = None
    ready: bool | None = None
    policy_type: str | None = None
    state_key: str | None = None
    observed: int | None = None
    allowed: int | None = None

    def __post_init__(self) -> None:
        for item in fields(self):
            value = cast(object, getattr(self, item.name))
            if value is None:
                continue
            if item.name == "partial_reasons":
                object.__setattr__(
                    self,
                    item.name,
                    _normalize_partial_reasons(value),
                )
                continue
            if isinstance(value, str):
                _validate_text(value, field_name=item.name, maximum=512)
                continue
            if isinstance(value, bool):
                continue
            if isinstance(value, int) and value >= 0:
                continue
            raise TypeError(f"diagnostic field '{item.name}' is invalid")


@dataclass(frozen=True, slots=True)
class DiagnosticEvent:
    """One deterministic schema-versioned diagnostic event."""

    event_type: DiagnosticEventType
    severity: DiagnosticSeverity
    message: str
    fields: DiagnosticFields = DiagnosticFields()
    schema_version: int = DIAGNOSTIC_EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(cast(object, self.schema_version), int)
            or isinstance(cast(object, self.schema_version), bool)
            or self.schema_version != DIAGNOSTIC_EVENT_SCHEMA_VERSION
        ):
            raise ValueError("diagnostic event schema version is invalid")
        if not isinstance(cast(object, self.event_type), DiagnosticEventType):
            raise TypeError("diagnostic event type is invalid")
        if not isinstance(cast(object, self.severity), DiagnosticSeverity):
            raise TypeError("diagnostic severity is invalid")
        if not isinstance(cast(object, self.message), str):
            raise TypeError("diagnostic message is invalid")
        _validate_text(self.message, field_name="message", maximum=128)
        if self.message != _EVENT_MESSAGES[self.event_type]:
            raise ValueError("diagnostic message does not match event type")
        if not isinstance(cast(object, self.fields), DiagnosticFields):
            raise TypeError("diagnostic fields are invalid")


def _validate_text(value: str, *, field_name: str, maximum: int) -> None:
    if (
        not value
        or len(value) > maximum
        or any(character in value for character in ("\r", "\n", "\x00"))
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"diagnostic {field_name} is invalid")


def _normalize_partial_reasons(value: object) -> tuple[StrEnum, ...]:
    if not isinstance(value, tuple) or not all(
        isinstance(reason, StrEnum)
        for reason in cast(tuple[object, ...], value)
    ):
        raise TypeError("diagnostic partial reasons must be typed")
    reasons = cast(tuple[StrEnum, ...], value)
    if not reasons or len(reasons) > 8:
        raise ValueError("diagnostic partial reason count is invalid")
    by_value: dict[str, StrEnum] = {}
    for reason in reasons:
        code = reason.value
        _validate_text(code, field_name="partial reason", maximum=64)
        if (
            code.startswith("_")
            or code.endswith("_")
            or "__" in code
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789_"
                for character in code
            )
        ):
            raise ValueError("diagnostic partial reason is invalid")
        by_value.setdefault(code, reason)
    return tuple(by_value[code] for code in sorted(by_value))
