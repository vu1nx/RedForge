"""Typed diagnostic contracts and standard-library logging adapter."""

import json
import logging
from dataclasses import FrozenInstanceError
from io import StringIO
from typing import cast

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.observability import PythonLoggingDiagnosticSink
from redforge.observability import (
    DIAGNOSTIC_EVENT_SCHEMA_VERSION,
    DiagnosticEvent,
    DiagnosticEventType,
    DiagnosticFields,
    DiagnosticSeverity,
    NullDiagnosticEventSink,
    emit_safely,
)


def _event(
    severity: DiagnosticSeverity = DiagnosticSeverity.INFO,
) -> DiagnosticEvent:
    return DiagnosticEvent(
        event_type=DiagnosticEventType.CAPABILITY_COMPLETED,
        severity=severity,
        message="Capability completed",
        fields=DiagnosticFields(
            capability_id="http_probe",
            runtime_status="SUCCESS",
            accepted=False,
            history_count=1,
        ),
    )


def test_event_contract_is_immutable_slotted_and_schema_versioned() -> None:
    event = _event()

    assert event.schema_version == DIAGNOSTIC_EVENT_SCHEMA_VERSION == 1
    assert not hasattr(event, "__dict__")
    assert not hasattr(event.fields, "__dict__")
    with pytest.raises(FrozenInstanceError):
        event.message = "changed"  # type: ignore[misc]


def test_severity_and_event_type_values_are_fixed() -> None:
    assert tuple(item.value for item in DiagnosticSeverity) == (
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
    )
    assert tuple(item.value for item in DiagnosticEventType) == (
        "scan_preparation_started",
        "scan_preparation_completed",
        "scan_preflight_started",
        "scan_preflight_completed",
        "scan_preflight_failed",
        "scan_build_started",
        "scan_build_completed",
        "scan_execution_started",
        "scan_execution_completed",
        "capability_started",
        "capability_completed",
        "capability_partial",
        "capability_failed",
        "capability_error",
        "policy_limit_exceeded",
        "policy_deadline_exceeded",
        "scan_result_created",
    )


@pytest.mark.parametrize(
    "value",
    (
        "line\nsecret",
        "line\rsecret",
        "nul\x00secret",
        "",
    ),
)
def test_diagnostic_text_rejects_multiline_and_control_values(
    value: str,
) -> None:
    with pytest.raises(ValueError):
        DiagnosticFields(capability_id=value)
    with pytest.raises(ValueError):
        DiagnosticEvent(
            event_type=DiagnosticEventType.SCAN_EXECUTION_STARTED,
            severity=DiagnosticSeverity.INFO,
            message=value,
        )


def test_event_message_is_fixed_by_typed_event_identity() -> None:
    with pytest.raises(ValueError):
        DiagnosticEvent(
            event_type=DiagnosticEventType.CAPABILITY_ERROR,
            severity=DiagnosticSeverity.ERROR,
            message="private provider exception",
        )


def test_null_sink_and_ordinary_sink_failure_are_semantically_silent() -> None:
    event = _event()
    NullDiagnosticEventSink().emit(event)

    class RaisingSink:
        def emit(self, event: DiagnosticEvent) -> None:
            _ = event
            raise RuntimeError("private provider exception")

    emit_safely(RaisingSink(), event)


@pytest.mark.parametrize("raised", (KeyboardInterrupt(), SystemExit()))
def test_safe_emitter_does_not_swallow_process_control(
    raised: BaseException,
) -> None:
    class InterruptingSink:
        def emit(self, event: DiagnosticEvent) -> None:
            _ = event
            raise raised

    with pytest.raises(type(raised)):
        emit_safely(InterruptingSink(), _event())


def test_python_logging_sink_serializes_deterministic_compact_json() -> None:
    stream = StringIO()
    logger = logging.Logger("test.redforge.diagnostics", level=logging.DEBUG)
    logger.propagate = False
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    sink = PythonLoggingDiagnosticSink(logger)

    sink.emit(_event())
    first = stream.getvalue()
    stream.seek(0)
    stream.truncate()
    sink.emit(_event())
    second = stream.getvalue()
    payload = cast(dict[str, object], json.loads(first))

    assert first == second
    assert first.count("\n") == 1
    assert payload == {
        "schema_version": 1,
        "event_type": "capability_completed",
        "severity": "INFO",
        "message": "Capability completed",
        "fields": {
            "capability_id": "http_probe",
            "runtime_status": "SUCCESS",
            "accepted": False,
            "history_count": 1,
        },
    }
    for forbidden in (
        "timestamp",
        "exception",
        "stdout",
        "stderr",
        "environment",
        "executable",
        "0x",
    ):
        assert forbidden not in first.lower()


def test_logging_sink_maps_severity_and_respects_dedicated_logger_level() -> None:
    stream = StringIO()
    logger = logging.Logger("test.redforge.threshold", level=logging.WARNING)
    logger.propagate = False
    handler = logging.StreamHandler(stream)
    logger.addHandler(handler)
    sink = PythonLoggingDiagnosticSink(logger)

    sink.emit(_event(DiagnosticSeverity.INFO))
    assert stream.getvalue() == ""
    sink.emit(_event(DiagnosticSeverity.ERROR))
    assert json.loads(stream.getvalue())["severity"] == "ERROR"
