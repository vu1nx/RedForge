"""Public structured observability contracts."""

from redforge.observability.models import (
    DIAGNOSTIC_EVENT_SCHEMA_VERSION,
    DiagnosticEvent,
    DiagnosticEventType,
    DiagnosticFields,
    DiagnosticSeverity,
)
from redforge.observability.sinks import (
    DiagnosticEventSink,
    NullDiagnosticEventSink,
    emit_safely,
)

__all__ = [
    "DIAGNOSTIC_EVENT_SCHEMA_VERSION",
    "DiagnosticEvent",
    "DiagnosticEventSink",
    "DiagnosticEventType",
    "DiagnosticFields",
    "DiagnosticSeverity",
    "NullDiagnosticEventSink",
    "emit_safely",
]
