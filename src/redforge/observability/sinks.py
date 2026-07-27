"""Synchronous diagnostic sink port and failure isolation."""

from typing import Protocol, runtime_checkable

from redforge.observability.models import DiagnosticEvent


@runtime_checkable
class DiagnosticEventSink(Protocol):
    """Execution-scoped destination for immutable diagnostic events."""

    def emit(self, event: DiagnosticEvent) -> None:
        """Consume one event synchronously."""
        ...


class NullDiagnosticEventSink:
    """Silent default sink."""

    __slots__ = ()

    def emit(self, event: DiagnosticEvent) -> None:
        """Discard one already-constructed event."""
        _ = event


def emit_safely(
    sink: DiagnosticEventSink,
    event: DiagnosticEvent,
) -> None:
    """Suppress ordinary sink failures without affecting scan semantics."""
    try:
        sink.emit(event)
    except Exception:
        return
