"""Standard-library logging adapter for typed diagnostic events."""

import json
import logging
from dataclasses import fields
from types import MappingProxyType
from typing import cast

from redforge.observability import (
    DiagnosticEvent,
    DiagnosticFields,
    DiagnosticSeverity,
)

_LOG_LEVELS = MappingProxyType(
    {
        DiagnosticSeverity.DEBUG: logging.DEBUG,
        DiagnosticSeverity.INFO: logging.INFO,
        DiagnosticSeverity.WARNING: logging.WARNING,
        DiagnosticSeverity.ERROR: logging.ERROR,
    }
)


class PythonLoggingDiagnosticSink:
    """Emit one compact deterministic JSON object per logging record."""

    __slots__ = ("_logger",)

    def __init__(self, logger: logging.Logger) -> None:
        if not isinstance(cast(object, logger), logging.Logger):
            raise TypeError("diagnostic logging sink requires a Logger")
        self._logger = logger

    def emit(self, event: DiagnosticEvent) -> None:
        """Serialize only the closed diagnostic contract."""
        if not isinstance(cast(object, event), DiagnosticEvent):
            raise TypeError("diagnostic logging sink requires an event")
        payload: dict[str, object] = {
            "schema_version": event.schema_version,
            "event_type": event.event_type.value,
            "severity": event.severity.value,
            "message": event.message,
            "fields": _structured_fields(event.fields),
        }
        rendered = json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )
        self._logger.log(
            _LOG_LEVELS[event.severity],
            rendered,
            exc_info=False,
            stack_info=False,
        )


def _structured_fields(value: DiagnosticFields) -> dict[str, object]:
    structured: dict[str, object] = {}
    for item in fields(value):
        field_value = getattr(value, item.name)
        if field_value is not None:
            structured[item.name] = (
                [reason.value for reason in field_value]
                if item.name == "partial_reasons"
                else field_value
            )
    return structured
