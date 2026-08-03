"""Offline CLI tests for RedForge Doctor."""

import io
import json

from redforge.cli import main
from redforge.cli.main import ExitCode, parse_cli_args
from redforge.composition import CompositionProfile
from redforge.doctor import (
    DoctorCheck,
    DoctorCheckKind,
    DoctorResult,
    DoctorStatus,
    PlatformInformation,
    PlatformSupport,
    PythonRuntimeInformation,
    ToolCompatibility,
    ToolDiagnostic,
)
from redforge.sdk import ToolId


def _result(*, ready: bool = True) -> DoctorResult:
    terminal = DoctorStatus.READY if ready else DoctorStatus.UNAVAILABLE
    return DoctorResult(
        profile=CompositionProfile.RECONNAISSANCE,
        platform=PlatformInformation(
            "linux",
            "x86_64",
            "kali",
            PlatformSupport.PRIMARY,
        ),
        python=PythonRuntimeInformation("cpython", 3, 12, True),
        tools=(
            ToolDiagnostic(
                ToolId("httpx"),
                terminal,
                "1.0",
                ToolCompatibility.UNVERIFIED,
            ),
        ),
        checks=(
            DoctorCheck(
                DoctorCheckKind.PLATFORM,
                "linux",
                DoctorStatus.READY,
            ),
            DoctorCheck(
                DoctorCheckKind.PYTHON,
                "cpython",
                DoctorStatus.READY,
            ),
            DoctorCheck(
                DoctorCheckKind.CONFIGURATION,
                "default",
                DoctorStatus.READY,
            ),
            DoctorCheck(
                DoctorCheckKind.COMPOSITION,
                "reconnaissance",
                DoctorStatus.READY,
            ),
            DoctorCheck(
                DoctorCheckKind.TOOL_EXECUTABLE,
                "httpx",
                terminal,
            ),
        ),
        ready=ready,
    )


class _Doctor:
    def __init__(self, result: DoctorResult) -> None:
        self._result = result

    def inspect(self) -> DoctorResult:
        return self._result


class _FailingDoctor:
    def inspect(self) -> DoctorResult:
        raise RuntimeError("secret path and exception detail")


class _InterruptedDoctor:
    def inspect(self) -> DoctorResult:
        raise KeyboardInterrupt


def test_doctor_parser_requires_no_target_and_selects_profile() -> None:
    options = parse_cli_args(
        ["doctor", "--profile", "full_assessment", "--output", "json"]
    )

    assert options.target is None
    assert options.doctor_profile is CompositionProfile.FULL_ASSESSMENT
    assert options.output_format.value == "json"  # type: ignore[union-attr]


def test_human_doctor_output_and_exit_codes() -> None:
    output = io.StringIO()
    errors = io.StringIO()

    code = main(
        ["doctor"],
        doctor_factory=lambda _profile: _Doctor(_result()),
        stdout=output,
        stderr=errors,
    )

    assert code == ExitCode.ACCEPTED
    assert output.getvalue().startswith("RedForge Doctor\n")
    assert "Overall: READY" in output.getvalue()
    assert errors.getvalue() == ""
    assert "target" not in output.getvalue().lower()


def test_json_is_deterministic_one_document_and_exit_consistent() -> None:
    outputs: list[str] = []
    for _ in range(2):
        output = io.StringIO()
        code = main(
            ["doctor", "--output", "json"],
            doctor_factory=lambda _profile: _Doctor(_result(ready=False)),
            stdout=output,
            stderr=io.StringIO(),
        )
        assert code == ExitCode.NOT_READY
        outputs.append(output.getvalue())

    assert outputs[0] == outputs[1]
    payload = json.loads(outputs[0])
    assert payload["schema_version"] == 1
    assert payload["outcome"] == "not_ready"
    assert payload["exit_code"] == ExitCode.NOT_READY
    assert payload["ready"] is False
    assert "target" not in payload


def test_doctor_internal_error_and_interruption_are_sanitized() -> None:
    for doctor, expected in (
        (_FailingDoctor(), ExitCode.INTERNAL_ERROR),
        (_InterruptedDoctor(), ExitCode.INTERRUPTED),
    ):
        output = io.StringIO()
        code = main(
            ["doctor", "--output", "json"],
            doctor_factory=lambda _profile, service=doctor: service,
            stdout=output,
            stderr=io.StringIO(),
        )
        payload = json.loads(output.getvalue())
        assert code == expected
        assert payload["exit_code"] == expected
        assert "secret" not in output.getvalue()
