"""Public reusable RedForge CLI API."""

from redforge.cli.json_output import (
    JSON_SCHEMA_VERSION,
    JsonScanOutcome,
    render_json_outcome,
)
from redforge.cli.main import (
    ExitCode,
    OutputFormat,
    ScanPreset,
    build_parser,
    main,
    render_preflight_result,
    render_scan_result,
)

__all__ = [
    "ExitCode",
    "JSON_SCHEMA_VERSION",
    "JsonScanOutcome",
    "OutputFormat",
    "ScanPreset",
    "build_parser",
    "main",
    "render_preflight_result",
    "render_json_outcome",
    "render_scan_result",
]
