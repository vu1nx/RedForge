"""Public reusable RedForge CLI API."""

from redforge.cli.doctor_output import (
    DOCTOR_JSON_SCHEMA_VERSION,
    DoctorJsonOutcome,
    render_doctor_human,
    render_doctor_json,
)
from redforge.cli.json_output import (
    JSON_SCHEMA_VERSION,
    JsonDryRunOutcome,
    JsonScanOutcome,
    render_dry_run_json_outcome,
    render_json_outcome,
)
from redforge.cli.main import (
    ExitCode,
    build_parser,
    main,
    render_preflight_result,
    render_scan_inspection,
    render_scan_result,
)
from redforge.configuration import OutputFormat, ScanPreset

__all__ = [
    "ExitCode",
    "DOCTOR_JSON_SCHEMA_VERSION",
    "DoctorJsonOutcome",
    "JSON_SCHEMA_VERSION",
    "JsonDryRunOutcome",
    "JsonScanOutcome",
    "OutputFormat",
    "ScanPreset",
    "build_parser",
    "main",
    "render_preflight_result",
    "render_doctor_human",
    "render_doctor_json",
    "render_dry_run_json_outcome",
    "render_json_outcome",
    "render_scan_inspection",
    "render_scan_result",
]
