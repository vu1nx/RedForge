"""Deterministic human and JSON rendering for environment diagnostics."""

import json
from dataclasses import dataclass

from redforge.doctor import DoctorResult

DOCTOR_JSON_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class DoctorJsonTool:
    tool_id: str
    status: str
    version: str | None
    compatibility: str


@dataclass(frozen=True, slots=True)
class DoctorJsonCheck:
    kind: str
    subject: str
    status: str
    required: bool


@dataclass(frozen=True, slots=True)
class DoctorJsonPlatform:
    family: str
    architecture: str
    distribution: str | None
    support: str


@dataclass(frozen=True, slots=True)
class DoctorJsonPython:
    implementation: str
    version: str
    supported: bool


@dataclass(frozen=True, slots=True)
class DoctorJsonOutcome:
    schema_version: int
    outcome: str
    exit_code: int
    ready: bool | None
    platform: DoctorJsonPlatform | None
    python: DoctorJsonPython | None
    profile: str | None
    configuration: str | None
    composition: str | None
    tools: tuple[DoctorJsonTool, ...]
    checks: tuple[DoctorJsonCheck, ...]
    error: str | None


def build_doctor_json_outcome(
    result: DoctorResult,
    *,
    exit_code: int,
) -> DoctorJsonOutcome:
    """Translate one typed result into the versioned CLI DTO."""
    statuses = {check.kind.value: check.status.value for check in result.checks}
    return DoctorJsonOutcome(
        schema_version=DOCTOR_JSON_SCHEMA_VERSION,
        outcome="ready" if result.ready else "not_ready",
        exit_code=exit_code,
        ready=result.ready,
        platform=DoctorJsonPlatform(
            family=result.platform.family,
            architecture=result.platform.architecture,
            distribution=result.platform.distribution,
            support=result.platform.support.value,
        ),
        python=DoctorJsonPython(
            implementation=result.python.implementation,
            version=result.python.version,
            supported=result.python.supported,
        ),
        profile=result.profile.value,
        configuration=statuses.get("configuration"),
        composition=statuses.get("composition"),
        tools=tuple(
            DoctorJsonTool(
                tool_id=tool.tool_id.value,
                status=tool.status.value,
                version=tool.version,
                compatibility=tool.compatibility.value,
            )
            for tool in result.tools
        ),
        checks=tuple(
            DoctorJsonCheck(
                kind=check.kind.value,
                subject=check.subject,
                status=check.status.value,
                required=check.required,
            )
            for check in result.checks
        ),
        error=None,
    )


def build_doctor_error_outcome(
    *,
    outcome: str,
    exit_code: int,
    message: str,
) -> DoctorJsonOutcome:
    """Return a fixed sanitized handled-error DTO."""
    return DoctorJsonOutcome(
        schema_version=DOCTOR_JSON_SCHEMA_VERSION,
        outcome=outcome,
        exit_code=exit_code,
        ready=None,
        platform=None,
        python=None,
        profile=None,
        configuration=None,
        composition=None,
        tools=(),
        checks=(),
        error=message,
    )


def render_doctor_json(outcome: DoctorJsonOutcome) -> str:
    """Serialize one deterministic JSON document without generic conversion."""
    payload = {
        "schema_version": outcome.schema_version,
        "outcome": outcome.outcome,
        "exit_code": outcome.exit_code,
        "ready": outcome.ready,
        "platform": (
            {
                "family": outcome.platform.family,
                "architecture": outcome.platform.architecture,
                "distribution": outcome.platform.distribution,
                "support": outcome.platform.support,
            }
            if outcome.platform is not None
            else None
        ),
        "python": (
            {
                "implementation": outcome.python.implementation,
                "version": outcome.python.version,
                "supported": outcome.python.supported,
            }
            if outcome.python is not None
            else None
        ),
        "profile": outcome.profile,
        "configuration": outcome.configuration,
        "composition": outcome.composition,
        "tools": [
            {
                "tool_id": tool.tool_id,
                "status": tool.status,
                "version": tool.version,
                "compatibility": tool.compatibility,
            }
            for tool in outcome.tools
        ],
        "checks": [
            {
                "kind": check.kind,
                "subject": check.subject,
                "status": check.status,
                "required": check.required,
            }
            for check in outcome.checks
        ],
        "error": outcome.error,
    }
    return json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    )


def render_doctor_human(result: DoctorResult) -> str:
    """Render bounded diagnostics without paths, commands, or raw output."""
    platform_name = (
        "Kali Linux"
        if result.platform.distribution == "kali"
        else result.platform.family
    )
    platform_status = next(
        check.status.value.upper()
        for check in result.checks
        if check.kind.value == "platform"
    )
    python_status = next(
        check.status.value.upper()
        for check in result.checks
        if check.kind.value == "python"
    )
    configuration = next(
        check.status.value.upper()
        for check in result.checks
        if check.kind.value == "configuration"
    )
    lines = [
        "RedForge Doctor",
        f"Platform: {platform_name} - {platform_status}",
        (
            f"Python: {result.python.implementation} "
            f"{result.python.version} - {python_status}"
        ),
        f"Profile: {result.profile.value}",
        f"Configuration: {configuration}",
        "",
        "Tools:",
    ]
    for tool in result.tools:
        suffix = f", version {tool.version}" if tool.version is not None else ""
        lines.append(
            f"- {tool.tool_id.value}: {tool.status.value.upper()}{suffix}, "
            f"compatibility {tool.compatibility.value}"
        )
    lines.extend(
        (
            "",
            f"Overall: {'READY' if result.ready else 'NOT READY'}",
        )
    )
    return "\n".join(lines)
