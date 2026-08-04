"""Offline tests for the thin application-facing command adapter."""

import json
from io import StringIO
from pathlib import Path
from typing import Any, cast

import pytest  # type: ignore[reportMissingImports]

from redforge.application import (
    PreflightResult,
    ReadinessCheckResult,
    ReadinessReason,
    ReadinessStatus,
    ReadinessSubject,
    ReadinessSubjectKind,
    ScanConfig,
    ScanPreflightError,
    ScanResult,
    prepare_scan,
)
from redforge.cli import (
    JSON_SCHEMA_VERSION,
    ExitCode,
    OutputFormat,
    ScanPreset,
    build_parser,
    main,
    render_preflight_result,
    render_scan_result,
)
from redforge.cli.main import parse_cli_args
from redforge.configuration import ObservabilityLevel, RedForgeConfiguration
from redforge.observability import (
    DiagnosticEvent,
    DiagnosticEventSink,
    DiagnosticEventType,
    DiagnosticFields,
    DiagnosticSeverity,
    emit_safely,
)
from redforge.planning import (
    MissingCapabilityFactoryError,
    create_default_registry,
)
from redforge.runtime import (
    DeadlinePhase,
    DeadlineViolation,
    StateLimitViolation,
)
from redforge.runtime.pipeline import (
    CapabilityExecution,
    PipelineResult,
)
from redforge.sdk import (
    Context,
    PipelineStateKey,
    Result,
    Status,
    TechnologyDetectionPartialReason,
    ToolId,
)


def _scan_result(
    config: ScanConfig,
    *,
    status: Status,
    accepted: bool,
    violation: StateLimitViolation | DeadlineViolation | None = None,
) -> ScanResult:
    prepared = prepare_scan(
        config=config,
        registry=create_default_registry(),
    )
    capability_result: Result[Any] = Result(status=status, data=None)
    execution = CapabilityExecution(
        capability_name="test_capability",
        result=capability_result,
        policy_violation=violation,
    )
    pipeline_result = PipelineResult(
        status=status,
        executed_capabilities=("test_capability",),
        context=Context(target_id=config.scope.root.value),
        last_result=capability_result,
        execution_order=("test_capability",),
        executions=(execution,),
    )
    return ScanResult(
        config=config,
        plan=prepared.plan,
        preflight=PreflightResult(ready=True, checks=()),
        pipeline_result=pipeline_result,
        accepted=accepted,
    )


class FakeOrchestrator:
    def __init__(
        self,
        *,
        status: Status = Status.SUCCESS,
        accepted: bool | None = None,
        violation: StateLimitViolation | DeadlineViolation | None = None,
        raised: BaseException | None = None,
    ) -> None:
        self.status = status
        self.accepted = accepted
        self.violation = violation
        self.raised = raised
        self.configs: list[ScanConfig] = []

    def run(self, config: ScanConfig) -> ScanResult:
        self.configs.append(config)
        if self.raised is not None:
            raise self.raised
        accepted = (
            self.accepted
            if self.accepted is not None
            else (
                self.status is Status.SUCCESS
                or (
                    self.status is Status.PARTIAL
                    and config.allow_partial_results
                )
            )
        )
        return _scan_result(
            config,
            status=self.status,
            accepted=accepted,
            violation=self.violation,
        )


class DiagnosticFakeOrchestrator(FakeOrchestrator):
    def __init__(
        self,
        sink: DiagnosticEventSink,
        severities: tuple[DiagnosticSeverity, ...],
    ) -> None:
        super().__init__()
        self._sink = sink
        self._severities = severities

    def run(self, config: ScanConfig) -> ScanResult:
        for severity in self._severities:
            emit_safely(
                self._sink,
                DiagnosticEvent(
                    event_type=DiagnosticEventType.SCAN_EXECUTION_STARTED,
                    severity=severity,
                    message="Scan execution started",
                ),
            )
        return super().run(config)


class PartialDiagnosticFakeOrchestrator(FakeOrchestrator):
    def __init__(self, sink: DiagnosticEventSink) -> None:
        super().__init__(status=Status.PARTIAL, accepted=False)
        self._sink = sink

    def run(self, config: ScanConfig) -> ScanResult:
        emit_safely(
            self._sink,
            DiagnosticEvent(
                event_type=DiagnosticEventType.CAPABILITY_PARTIAL,
                severity=DiagnosticSeverity.WARNING,
                message="Capability completed partially",
                fields=DiagnosticFields(
                    capability_id="technology_detection",
                    runtime_status="PARTIAL",
                    partial_reasons=(
                        TechnologyDetectionPartialReason.MALFORMED_RECORDS_SKIPPED,
                    ),
                ),
            ),
        )
        return super().run(config)


def _run(
    argv: list[str],
    orchestrator: FakeOrchestrator,
) -> tuple[int, str, str, int]:
    stdout = StringIO()
    stderr = StringIO()
    factory_calls = 0

    def factory() -> FakeOrchestrator:
        nonlocal factory_calls
        factory_calls += 1
        return orchestrator

    code = main(
        argv,
        orchestrator_factory=factory,
        stdout=stdout,
        stderr=stderr,
    )
    return code, stdout.getvalue(), stderr.getvalue(), factory_calls


def _run_with_composition(
    argv: list[str],
    severities: tuple[DiagnosticSeverity, ...],
) -> tuple[int, str, str, int]:
    stdout = StringIO()
    stderr = StringIO()
    composition_calls = 0

    def factory(
        profile: object,
        sink: DiagnosticEventSink,
    ) -> DiagnosticFakeOrchestrator:
        nonlocal composition_calls
        _ = profile
        composition_calls += 1
        return DiagnosticFakeOrchestrator(sink, severities)

    code = main(
        argv,
        composition_factory=factory,
        stdout=stdout,
        stderr=stderr,
    )
    return (
        code,
        stdout.getvalue(),
        stderr.getvalue(),
        composition_calls,
    )


def test_parser_is_fresh_and_preserves_omitted_overrides() -> None:
    first = build_parser()
    second = build_parser()
    options = parse_cli_args(["scan", "authorized.example"])

    assert first is not second
    assert options.target == "authorized.example"
    assert options.preset is None
    assert options.output_format is None
    assert options.allow_partial_results is None
    assert options.log_level is None


def test_log_level_option_is_typed() -> None:
    options = parse_cli_args(
        ["scan", "authorized.example", "--log-level", "warning"]
    )

    assert options.log_level is ObservabilityLevel.WARNING


def test_root_and_scan_help_are_non_exiting_and_authorization_safe() -> None:
    for argv in (["--help"], ["scan", "--help"]):
        code, stdout, stderr, factory_calls = _run(
            argv,
            FakeOrchestrator(),
        )

        assert code == ExitCode.ACCEPTED
        assert "Only scan systems you are explicitly authorized" in stdout
        assert stderr == ""
        assert factory_calls == 0


def test_success_uses_canonical_target_and_one_orchestrator_call() -> None:
    orchestrator = FakeOrchestrator()

    code, stdout, stderr, factory_calls = _run(
        ["scan", "AUTHORIZED.example."],
        orchestrator,
    )

    assert code == ExitCode.ACCEPTED
    assert stderr == ""
    assert factory_calls == 1
    assert len(orchestrator.configs) == 1
    assert orchestrator.configs[0].scope.root.value == "authorized.example"
    assert orchestrator.configs[0].requested_outputs == (
        PipelineStateKey.TECHNOLOGIES,
    )
    assert stdout == (
        "Scan completed\n"
        "Target: authorized.example\n"
        "Preset: reconnaissance\n"
        "Status: SUCCESS\n"
        "Accepted: yes\n"
        "Capabilities executed: 1\n"
    )


def test_full_preset_uses_full_assessment_constructor() -> None:
    orchestrator = FakeOrchestrator()

    code, stdout, stderr, _ = _run(
        ["scan", "authorized.example", "--preset", "full"],
        orchestrator,
    )

    assert code == ExitCode.ACCEPTED
    assert stderr == ""
    assert orchestrator.configs[0].requested_outputs == (
        PipelineStateKey.RISK_INTELLIGENCE,
    )
    assert "Preset: full" in stdout


@pytest.mark.parametrize(
    "target",
    (
        "https://authorized.example",
        "192.0.2.10",
        "*.authorized.example",
        "user@authorized.example",
    ),
)
def test_invalid_target_is_usage_error_before_composition(target: str) -> None:
    code, stdout, stderr, factory_calls = _run(
        ["scan", target],
        FakeOrchestrator(),
    )

    assert code == ExitCode.INVALID_INPUT
    assert stdout == ""
    assert factory_calls == 0
    assert stderr == "Invalid input: scan target or options are invalid\n"
    assert "Traceback" not in stderr


@pytest.mark.parametrize(
    ("flag", "expected_code", "expected_accepted"),
    (
        ("--allow-partial-results", ExitCode.ACCEPTED, "yes"),
        (None, ExitCode.NOT_ACCEPTED, "no"),
    ),
)
def test_partial_result_uses_application_acceptance_without_remapping(
    flag: str | None,
    expected_code: ExitCode,
    expected_accepted: str,
) -> None:
    argv = ["scan", "authorized.example"]
    if flag is not None:
        argv.append(flag)
    code, stdout, stderr, _ = _run(
        argv,
        FakeOrchestrator(status=Status.PARTIAL),
    )

    assert code == expected_code
    assert stderr == ""
    assert "Status: PARTIAL" in stdout
    assert f"Accepted: {expected_accepted}" in stdout


@pytest.mark.parametrize("status", (Status.FAILURE, Status.ERROR))
def test_nonaccepted_runtime_results_use_stdout_and_exit_four(
    status: Status,
) -> None:
    code, stdout, stderr, _ = _run(
        ["scan", "authorized.example"],
        FakeOrchestrator(status=status, accepted=False),
    )

    assert code == ExitCode.NOT_ACCEPTED
    assert stderr == ""
    assert f"Status: {status.name}" in stdout
    assert "Accepted: no" in stdout


@pytest.mark.parametrize(
    ("violation", "expected"),
    (
        (
            StateLimitViolation(
                PipelineStateKey.TECHNOLOGIES,
                observed=2,
                allowed=1,
            ),
            "Policy violation: TECHNOLOGIES observed=2 allowed=1",
        ),
        (
            DeadlineViolation(DeadlinePhase.AFTER_CAPABILITY),
            "Policy violation: execution deadline exceeded",
        ),
    ),
)
def test_policy_failures_render_only_sanitized_public_data(
    violation: StateLimitViolation | DeadlineViolation,
    expected: str,
) -> None:
    code, stdout, stderr, _ = _run(
        ["scan", "authorized.example"],
        FakeOrchestrator(
            status=Status.FAILURE,
            accepted=False,
            violation=violation,
        ),
    )

    assert code == ExitCode.NOT_ACCEPTED
    assert expected in stdout
    assert stderr == ""


def _preflight_error() -> ScanPreflightError:
    result = PreflightResult(
        ready=False,
        checks=(
            ReadinessCheckResult(
                subject=ReadinessSubject(
                    kind=ReadinessSubjectKind.TOOL_EXECUTABLE,
                    tool_id=ToolId("offline_tool"),
                ),
                status=ReadinessStatus.UNAVAILABLE,
                reason=ReadinessReason.EXECUTABLE_UNAVAILABLE,
            ),
        ),
    )
    return ScanPreflightError(result)


def test_preflight_failure_uses_stderr_and_exit_three() -> None:
    error = _preflight_error()
    code, stdout, stderr, _ = _run(
        ["scan", "authorized.example"],
        FakeOrchestrator(raised=error),
    )

    assert code == ExitCode.NOT_READY
    assert stdout == ""
    assert stderr == (
        "Scan could not start\n"
        "Readiness checks failed:\n"
        "- tool executable unavailable: offline_tool "
        "(executable_unavailable)\n"
    )
    assert "Traceback" not in stderr


def test_renderers_are_pure_and_deterministic() -> None:
    error = _preflight_error()
    first = render_preflight_result(error.result)
    second = render_preflight_result(error.result)
    config = ScanConfig.for_reconnaissance("authorized.example")
    result = _scan_result(
        config,
        status=Status.SUCCESS,
        accepted=True,
    )

    assert first == second
    assert render_scan_result(
        result,
        preset=ScanPreset.RECONNAISSANCE,
    ) == render_scan_result(
        result,
        preset=ScanPreset.RECONNAISSANCE,
    )


def test_composition_failure_is_sanitized_exit_three() -> None:
    code, stdout, stderr, _ = _run(
        ["scan", "authorized.example"],
        FakeOrchestrator(
            raised=MissingCapabilityFactoryError("secret_factory")
        ),
    )

    assert code == ExitCode.NOT_READY
    assert stdout == ""
    assert stderr == "Scan could not start\nComposition is invalid\n"
    assert "secret_factory" not in stderr


def test_unexpected_error_is_sanitized_exit_five() -> None:
    code, stdout, stderr, _ = _run(
        ["scan", "authorized.example"],
        FakeOrchestrator(
            raised=ValueError("secret-token C:\\private\\path")
        ),
    )

    assert code == ExitCode.INTERNAL_ERROR
    assert stdout == ""
    assert stderr == "RedForge encountered an unexpected internal failure\n"
    assert "secret" not in stderr
    assert "Traceback" not in stderr


def test_keyboard_interrupt_is_exit_130_without_traceback() -> None:
    code, stdout, stderr, _ = _run(
        ["scan", "authorized.example"],
        FakeOrchestrator(raised=KeyboardInterrupt()),
    )

    assert code == ExitCode.INTERRUPTED
    assert stdout == ""
    assert stderr == "Scan interrupted\n"


def test_usage_error_does_not_construct_orchestrator() -> None:
    code, stdout, stderr, factory_calls = _run([], FakeOrchestrator())

    assert code == ExitCode.INVALID_INPUT
    assert stdout == ""
    assert factory_calls == 0
    assert stderr == "Invalid command: the scan command is required\n"


def _json_document(stdout: str) -> dict[str, Any]:
    assert stdout.endswith("\n")
    assert stdout.count("\n") == 1
    payload = cast(dict[str, Any], json.loads(stdout))
    assert isinstance(payload, dict)
    return payload


def test_json_output_option_is_typed_and_invalid_value_does_not_compose() -> None:
    options = parse_cli_args(
        ["scan", "authorized.example", "--output", "json"]
    )
    assert options.output_format is OutputFormat.JSON

    code, stdout, stderr, factory_calls = _run(
        ["scan", "authorized.example", "--output", "xml"],
        FakeOrchestrator(),
    )

    assert code == ExitCode.INVALID_INPUT
    assert stdout == ""
    assert "invalid choice" in stderr
    assert factory_calls == 0


def test_explicit_human_output_preserves_default_document() -> None:
    default = _run(["scan", "authorized.example"], FakeOrchestrator())
    explicit = _run(
        ["scan", "authorized.example", "--output", "human"],
        FakeOrchestrator(),
    )

    assert default == explicit


def test_json_success_has_versioned_complete_deterministic_schema() -> None:
    argv = ["scan", "AUTHORIZED.example.", "--output", "json"]
    first = _run(argv, FakeOrchestrator())
    second = _run(argv, FakeOrchestrator())

    assert first == second
    code, stdout, stderr, factory_calls = first
    payload = _json_document(stdout)
    assert code == ExitCode.ACCEPTED
    assert stderr == ""
    assert factory_calls == 1
    assert list(payload) == [
        "schema_version",
        "outcome",
        "exit_code",
        "target",
        "preset",
        "runtime_status",
        "accepted",
        "capabilities_executed",
        "preflight",
        "policy_violation",
        "error",
    ]
    assert payload == {
        "schema_version": JSON_SCHEMA_VERSION,
        "outcome": "completed",
        "exit_code": 0,
        "target": "authorized.example",
        "preset": "reconnaissance",
        "runtime_status": "success",
        "accepted": True,
        "capabilities_executed": 1,
        "preflight": {
            "ready": True,
            "checks_total": 0,
            "checks_failed": 0,
            "failures": [],
        },
        "policy_violation": None,
        "error": None,
    }


@pytest.mark.parametrize(
    ("status", "allow_partial", "accepted", "exit_code"),
    (
        (Status.PARTIAL, True, True, ExitCode.ACCEPTED),
        (Status.PARTIAL, False, False, ExitCode.NOT_ACCEPTED),
        (Status.FAILURE, False, False, ExitCode.NOT_ACCEPTED),
        (Status.ERROR, False, False, ExitCode.NOT_ACCEPTED),
    ),
)
def test_json_completed_status_and_exit_code_are_not_rewritten(
    status: Status,
    allow_partial: bool,
    accepted: bool,
    exit_code: ExitCode,
) -> None:
    argv = ["scan", "authorized.example", "--output", "json"]
    if allow_partial:
        argv.append("--allow-partial-results")

    code, stdout, stderr, _ = _run(
        argv,
        FakeOrchestrator(status=status, accepted=accepted),
    )
    payload = _json_document(stdout)

    assert code == exit_code == payload["exit_code"]
    assert stderr == ""
    assert payload["outcome"] == "completed"
    assert payload["runtime_status"] == status.value
    assert payload["accepted"] is accepted
    assert payload["error"] is None


@pytest.mark.parametrize(
    ("violation", "expected"),
    (
        (
            StateLimitViolation(
                PipelineStateKey.TECHNOLOGIES,
                observed=11,
                allowed=10,
            ),
            {
                "type": "state_limit",
                "reason_code": "state_limit_exceeded",
                "state_key": "TECHNOLOGIES",
                "observed": 11,
                "allowed": 10,
            },
        ),
        (
            DeadlineViolation(DeadlinePhase.BEFORE_CAPABILITY),
            {
                "type": "deadline",
                "reason_code": "deadline_exceeded",
                "state_key": None,
                "observed": None,
                "allowed": None,
            },
        ),
    ),
)
def test_json_policy_violation_is_typed_and_bounded(
    violation: StateLimitViolation | DeadlineViolation,
    expected: dict[str, Any],
) -> None:
    code, stdout, stderr, _ = _run(
        ["scan", "authorized.example", "--output", "json"],
        FakeOrchestrator(
            status=Status.FAILURE,
            accepted=False,
            violation=violation,
        ),
    )
    payload = _json_document(stdout)

    assert code == payload["exit_code"] == ExitCode.NOT_ACCEPTED
    assert stderr == ""
    assert payload["policy_violation"] == expected
    assert "context" not in stdout.lower()


def test_json_preflight_failure_contains_only_stable_failed_checks() -> None:
    code, stdout, stderr, _ = _run(
        ["scan", "authorized.example", "--output", "json"],
        FakeOrchestrator(raised=_preflight_error()),
    )
    payload = _json_document(stdout)

    assert code == payload["exit_code"] == ExitCode.NOT_READY
    assert stderr == ""
    assert payload["outcome"] == "not_ready"
    assert payload["runtime_status"] is None
    assert payload["accepted"] is None
    assert payload["capabilities_executed"] == 0
    assert payload["error"] is None
    assert payload["preflight"] == {
        "ready": False,
        "checks_total": 1,
        "checks_failed": 1,
        "failures": [
            {
                "subject_type": "tool_executable",
                "subject_id": "offline_tool",
                "status": "unavailable",
                "reason_code": "executable_unavailable",
                "message": "required executable is unavailable",
            }
        ],
    }


@pytest.mark.parametrize(
    "target",
    (
        "https://authorized.example/private?token=secret",
        "192.0.2.10",
        "*.authorized.example",
        "user:password@authorized.example",
    ),
)
def test_json_invalid_target_is_sanitized_and_never_composes(
    target: str,
) -> None:
    code, stdout, stderr, factory_calls = _run(
        ["scan", target, "--output", "json"],
        FakeOrchestrator(),
    )
    payload = _json_document(stdout)

    assert code == payload["exit_code"] == ExitCode.INVALID_INPUT
    assert stderr == ""
    assert factory_calls == 0
    assert payload["outcome"] == "invalid_input"
    assert payload["target"] is None
    assert payload["error"] == {
        "reason_code": "invalid_target",
        "message": "invalid scan target",
    }
    assert target not in stdout
    assert "secret" not in stdout
    assert "password" not in stdout


def test_json_missing_target_is_handled_after_output_mode_resolution() -> None:
    code, stdout, stderr, factory_calls = _run(
        ["scan", "--output", "json"],
        FakeOrchestrator(),
    )
    payload = _json_document(stdout)

    assert code == payload["exit_code"] == ExitCode.INVALID_INPUT
    assert stderr == ""
    assert factory_calls == 0
    assert payload["outcome"] == "invalid_input"
    assert payload["target"] is None
    assert payload["preset"] is None


def test_json_composition_failure_is_sanitized() -> None:
    code, stdout, stderr, _ = _run(
        ["scan", "authorized.example", "--output", "json"],
        FakeOrchestrator(
            raised=MissingCapabilityFactoryError("secret_factory")
        ),
    )
    payload = _json_document(stdout)

    assert code == payload["exit_code"] == ExitCode.NOT_READY
    assert stderr == ""
    assert payload["outcome"] == "not_ready"
    assert payload["preflight"] is None
    assert payload["error"] == {
        "reason_code": "composition_failed",
        "message": "scan composition is unavailable",
    }
    assert "secret_factory" not in stdout


@pytest.mark.parametrize(
    ("raised", "outcome", "exit_code", "reason_code", "message"),
    (
        (
            ValueError("secret-token C:\\private\\path"),
            "internal_error",
            ExitCode.INTERNAL_ERROR,
            "internal_error",
            "an unexpected internal error occurred",
        ),
        (
            KeyboardInterrupt(),
            "interrupted",
            ExitCode.INTERRUPTED,
            "interrupted",
            "scan was interrupted",
        ),
    ),
)
def test_json_internal_error_and_interrupt_are_single_sanitized_documents(
    raised: BaseException,
    outcome: str,
    exit_code: ExitCode,
    reason_code: str,
    message: str,
) -> None:
    code, stdout, stderr, _ = _run(
        ["scan", "authorized.example", "--output", "json"],
        FakeOrchestrator(raised=raised),
    )
    payload = _json_document(stdout)

    assert code == payload["exit_code"] == exit_code
    assert stderr == ""
    assert payload["outcome"] == outcome
    assert payload["target"] is None
    assert payload["preset"] is None
    assert payload["runtime_status"] is None
    assert payload["error"] == {
        "reason_code": reason_code,
        "message": message,
    }
    assert "secret-token" not in stdout
    assert "private" not in stdout


def _configuration_file(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "redforge.toml"
    path.write_text(f"schema_version = 1\n{body}", encoding="utf-8")
    return path


def test_config_values_apply_when_cli_overrides_are_omitted(
    tmp_path: Path,
) -> None:
    path = _configuration_file(
        tmp_path,
        """
[scan]
preset = "full"
allow_partial_results = true
[composition]
profile = "full_assessment"
[output]
format = "json"
""",
    )
    orchestrator = FakeOrchestrator(status=Status.PARTIAL)

    code, stdout, stderr, _ = _run(
        ["scan", "authorized.example", "--config", str(path)],
        orchestrator,
    )
    payload = _json_document(stdout)

    assert code == ExitCode.ACCEPTED
    assert stderr == ""
    assert payload["preset"] == "full"
    assert payload["runtime_status"] == "partial"
    assert orchestrator.configs[0].requested_outputs == (
        PipelineStateKey.RISK_INTELLIGENCE,
    )
    assert orchestrator.configs[0].allow_partial_results


def test_explicit_cli_values_override_configuration(
    tmp_path: Path,
) -> None:
    path = _configuration_file(
        tmp_path,
        """
[scan]
preset = "reconnaissance"
allow_partial_results = false
[composition]
profile = "reconnaissance"
[output]
format = "human"
""",
    )
    orchestrator = FakeOrchestrator(status=Status.PARTIAL)

    code, stdout, stderr, _ = _run(
        [
            "scan",
            "authorized.example",
            "--config",
            str(path),
            "--preset",
            "full",
            "--allow-partial-results",
            "--output",
            "json",
        ],
        orchestrator,
    )
    payload = _json_document(stdout)

    assert code == ExitCode.ACCEPTED
    assert stderr == ""
    assert payload["preset"] == "full"
    assert orchestrator.configs[0].requested_outputs == (
        PipelineStateKey.RISK_INTELLIGENCE,
    )
    assert orchestrator.configs[0].allow_partial_results


def test_configuration_limits_are_translated_into_scan_config(
    tmp_path: Path,
) -> None:
    path = _configuration_file(
        tmp_path,
        "[scan.limits]\nmax_hosts = 7\noverall_timeout_seconds = 9\n",
    )
    orchestrator = FakeOrchestrator()

    code, _, stderr, _ = _run(
        ["scan", "authorized.example", "--config", str(path)],
        orchestrator,
    )

    assert code == ExitCode.ACCEPTED
    assert stderr == ""
    assert orchestrator.configs[0].limits.max_hosts == 7
    assert orchestrator.configs[0].limits.overall_timeout_seconds == 9


@pytest.mark.parametrize(
    ("body", "expected"),
    (
        ("not valid =", "configuration file could not be parsed"),
        ("schema_version = 2\n", "schema version is unsupported"),
        (
            "schema_version = 1\n[scan]\npresett = true\n",
            "unknown configuration field: scan.presett",
        ),
        (
            'schema_version = 1\n[scan]\npreset = "full"\n'
            '[composition]\nprofile = "reconnaissance"\n',
            "scan preset is incompatible",
        ),
        (
            "schema_version = 1\n[scan.limits]\nmax_hosts = false\n",
            "invalid configuration value",
        ),
        (
            'schema_version = 1\n[observability]\nlevel = "verbose"\n',
            "invalid configuration value",
        ),
    ),
)
def test_human_configuration_errors_are_typed_and_sanitized(
    tmp_path: Path,
    body: str,
    expected: str,
) -> None:
    path = tmp_path / "redforge.toml"
    path.write_text(body, encoding="utf-8")

    code, stdout, stderr, factory_calls = _run(
        ["scan", "authorized.example", "--config", str(path)],
        FakeOrchestrator(),
    )

    assert code == ExitCode.INVALID_INPUT
    assert stdout == ""
    assert factory_calls == 0
    assert stderr.startswith("Configuration error\n")
    assert expected in stderr
    assert str(path) not in stderr
    assert "Traceback" not in stderr


def test_explicit_json_configuration_failure_is_one_document(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "private" / "missing.toml"

    code, stdout, stderr, factory_calls = _run(
        [
            "scan",
            "authorized.example",
            "--config",
            str(missing),
            "--output",
            "json",
        ],
        FakeOrchestrator(),
    )
    payload = _json_document(stdout)

    assert code == payload["exit_code"] == ExitCode.INVALID_INPUT
    assert stderr == ""
    assert factory_calls == 0
    assert payload["outcome"] == "invalid_input"
    assert payload["target"] is None
    assert payload["preset"] is None
    assert payload["error"] == {
        "reason_code": "configuration_file_unavailable",
        "message": "configuration file is unavailable",
    }
    assert str(missing) not in stdout


def test_missing_configuration_file_is_a_sanitized_human_error(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "private" / "missing.toml"

    code, stdout, stderr, factory_calls = _run(
        ["scan", "authorized.example", "--config", str(missing)],
        FakeOrchestrator(),
    )

    assert code == ExitCode.INVALID_INPUT
    assert stdout == ""
    assert factory_calls == 0
    assert stderr == (
        "Configuration error\nconfiguration file is unavailable\n"
    )
    assert str(missing) not in stderr


@pytest.mark.parametrize(
    ("body", "reason_code"),
    (
        ("not valid =", "configuration_parse_failed"),
        ("schema_version = 2\n", "configuration_version_unsupported"),
        (
            "schema_version = 1\n[scan]\npresett = true\n",
            "configuration_field_unknown",
        ),
        (
            'schema_version = 1\n[scan]\npreset = "full"\n'
            '[composition]\nprofile = "reconnaissance"\n',
            "configuration_profile_incompatible",
        ),
        (
            "schema_version = 1\n[scan.limits]\nmax_hosts = false\n",
            "configuration_value_invalid",
        ),
        (
            'schema_version = 1\n[observability]\nlevel = "verbose"\n',
            "configuration_value_invalid",
        ),
    ),
)
def test_json_configuration_failures_use_stable_reason_codes(
    tmp_path: Path,
    body: str,
    reason_code: str,
) -> None:
    path = tmp_path / "redforge.toml"
    path.write_text(body, encoding="utf-8")

    code, stdout, stderr, factory_calls = _run(
        [
            "scan",
            "authorized.example",
            "--config",
            str(path),
            "--output",
            "json",
        ],
        FakeOrchestrator(),
    )
    payload = _json_document(stdout)

    assert code == payload["exit_code"] == ExitCode.INVALID_INPUT
    assert stderr == ""
    assert factory_calls == 0
    assert payload["error"]["reason_code"] == reason_code
    assert str(path) not in stdout


def test_invalid_credential_target_with_config_never_composes(
    tmp_path: Path,
) -> None:
    path = _configuration_file(tmp_path, "")

    code, stdout, stderr, factory_calls = _run(
        [
            "scan",
            "user:password@authorized.example",
            "--config",
            str(path),
            "--output",
            "json",
        ],
        FakeOrchestrator(),
    )

    assert code == ExitCode.INVALID_INPUT
    assert stderr == ""
    assert factory_calls == 0
    assert "password" not in stdout


def test_configured_json_output_applies_to_invalid_target(
    tmp_path: Path,
) -> None:
    path = _configuration_file(
        tmp_path,
        '[output]\nformat = "json"\n',
    )

    code, stdout, stderr, factory_calls = _run(
        [
            "scan",
            "user:password@authorized.example",
            "--config",
            str(path),
        ],
        FakeOrchestrator(),
    )
    payload = _json_document(stdout)

    assert code == ExitCode.INVALID_INPUT
    assert stderr == ""
    assert factory_calls == 0
    assert payload["error"]["reason_code"] == "invalid_target"
    assert "password" not in stdout


def test_interrupt_after_configuration_load_uses_configured_output(
    tmp_path: Path,
) -> None:
    path = _configuration_file(
        tmp_path,
        '[output]\nformat = "json"\n',
    )

    code, stdout, stderr, _ = _run(
        ["scan", "authorized.example", "--config", str(path)],
        FakeOrchestrator(raised=KeyboardInterrupt()),
    )
    payload = _json_document(stdout)

    assert code == ExitCode.INTERRUPTED
    assert stderr == ""
    assert payload["outcome"] == "interrupted"


def test_duplicate_config_options_are_parser_errors(tmp_path: Path) -> None:
    path = _configuration_file(tmp_path, "")

    code, stdout, stderr, factory_calls = _run(
        [
            "scan",
            "authorized.example",
            "--config",
            str(path),
            "--config",
            str(path),
        ],
        FakeOrchestrator(),
    )

    assert code == ExitCode.INVALID_INPUT
    assert stdout == ""
    assert factory_calls == 0
    assert "only once" in stderr


def test_unexpected_loader_error_uses_outer_json_boundary() -> None:
    stdout = StringIO()
    stderr = StringIO()

    def broken_loader(path: Path) -> RedForgeConfiguration:
        raise RuntimeError(f"secret loader path: {path}")

    code = main(
        [
            "scan",
            "authorized.example",
            "--config",
            "private.toml",
            "--output",
            "json",
        ],
        configuration_loader=broken_loader,
        orchestrator_factory=lambda: FakeOrchestrator(),
        stdout=stdout,
        stderr=stderr,
    )
    payload = _json_document(stdout.getvalue())

    assert code == ExitCode.INTERNAL_ERROR
    assert stderr.getvalue() == ""
    assert payload["outcome"] == "internal_error"
    assert "private.toml" not in stdout.getvalue()


def test_default_and_explicit_off_observability_remain_silent() -> None:
    default = _run_with_composition(
        ["scan", "authorized.example"],
        (DiagnosticSeverity.ERROR,),
    )
    explicit = _run_with_composition(
        ["scan", "authorized.example", "--log-level", "off"],
        (DiagnosticSeverity.ERROR,),
    )

    assert default == explicit
    assert default[0] == ExitCode.ACCEPTED
    assert default[2] == ""


def test_human_output_and_structured_diagnostics_are_isolated() -> None:
    code, stdout, stderr, calls = _run_with_composition(
        ["scan", "authorized.example", "--log-level", "info"],
        (DiagnosticSeverity.INFO,),
    )
    diagnostic = cast(dict[str, Any], json.loads(stderr))

    assert code == ExitCode.ACCEPTED
    assert calls == 1
    assert stdout.startswith("Scan completed\n")
    assert stdout.count("Scan completed") == 1
    assert diagnostic["event_type"] == "scan_execution_started"
    assert diagnostic["severity"] == "INFO"
    assert "Scan completed" not in stderr


def test_json_outcome_stays_one_stdout_document_with_stderr_diagnostics() -> None:
    code, stdout, stderr, calls = _run_with_composition(
        [
            "scan",
            "authorized.example",
            "--output",
            "json",
            "--log-level",
            "info",
        ],
        (DiagnosticSeverity.INFO,),
    )
    outcome = _json_document(stdout)
    diagnostic = cast(dict[str, Any], json.loads(stderr))

    assert code == outcome["exit_code"] == ExitCode.ACCEPTED
    assert calls == 1
    assert diagnostic["schema_version"] == 1
    assert diagnostic["event_type"] == "scan_execution_started"
    assert "scan_execution_started" not in stdout
    assert '"outcome"' not in stderr


def test_partial_reasons_remain_in_stderr_diagnostics_only() -> None:
    stdout = StringIO()
    stderr = StringIO()

    def composition(
        profile: object,
        sink: DiagnosticEventSink,
    ) -> PartialDiagnosticFakeOrchestrator:
        _ = profile
        return PartialDiagnosticFakeOrchestrator(sink)

    code = main(
        [
            "scan",
            "authorized.example",
            "--output",
            "json",
            "--log-level",
            "debug",
        ],
        composition_factory=composition,
        stdout=stdout,
        stderr=stderr,
    )

    outcome = _json_document(stdout.getvalue())
    diagnostic = cast(dict[str, Any], json.loads(stderr.getvalue()))
    fields = cast(dict[str, Any], diagnostic["fields"])

    assert code == outcome["exit_code"] == ExitCode.NOT_ACCEPTED
    assert outcome["runtime_status"] == "partial"
    assert "partial_reasons" not in outcome
    assert diagnostic["event_type"] == "capability_partial"
    assert fields == {
        "capability_id": "technology_detection",
        "runtime_status": "PARTIAL",
        "partial_reasons": ["malformed_records_skipped"],
    }
    assert "capability_partial" not in stdout.getvalue()
    assert '"outcome"' not in stderr.getvalue()


def test_configured_log_level_and_explicit_cli_precedence(
    tmp_path: Path,
) -> None:
    path = _configuration_file(
        tmp_path,
        '[observability]\nlevel = "warning"\n',
    )

    configured = _run_with_composition(
        ["scan", "authorized.example", "--config", str(path)],
        (DiagnosticSeverity.INFO, DiagnosticSeverity.WARNING),
    )
    overridden = _run_with_composition(
        [
            "scan",
            "authorized.example",
            "--config",
            str(path),
            "--log-level",
            "error",
        ],
        (DiagnosticSeverity.WARNING,),
    )

    assert json.loads(configured[2])["severity"] == "WARNING"
    assert overridden[0] == ExitCode.ACCEPTED
    assert overridden[2] == ""


def test_repeated_cli_calls_do_not_accumulate_logging_handlers() -> None:
    first = _run_with_composition(
        ["scan", "authorized.example", "--log-level", "info"],
        (DiagnosticSeverity.INFO,),
    )
    second = _run_with_composition(
        ["scan", "authorized.example", "--log-level", "info"],
        (DiagnosticSeverity.INFO,),
    )

    assert first[2] == second[2]
    assert first[2].count("\n") == second[2].count("\n") == 1


def test_sink_failure_does_not_change_cli_exit_code_or_escape() -> None:
    class RaisingSink:
        def __init__(self) -> None:
            self.calls = 0

        def emit(self, event: DiagnosticEvent) -> None:
            _ = event
            self.calls += 1
            raise RuntimeError("private sink failure")

    sink = RaisingSink()
    stdout = StringIO()
    stderr = StringIO()

    def composition(
        profile: object,
        injected: DiagnosticEventSink,
    ) -> DiagnosticFakeOrchestrator:
        _ = profile
        return DiagnosticFakeOrchestrator(
            injected,
            (DiagnosticSeverity.INFO,),
        )

    code = main(
        ["scan", "authorized.example", "--log-level", "info"],
        composition_factory=composition,
        diagnostic_sink=sink,
        stdout=stdout,
        stderr=stderr,
    )

    assert code == ExitCode.ACCEPTED
    assert stdout.getvalue().startswith("Scan completed\n")
    assert stderr.getvalue() == ""
    assert sink.calls == 1
