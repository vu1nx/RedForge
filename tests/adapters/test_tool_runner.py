"""Portable integration tests for LocalSubprocessToolRunner."""

import json
import os
import sys
from pathlib import Path

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters import LocalSubprocessToolRunner
from redforge.sdk import (
    ToolDefinition,
    ToolExecutionStatus,
    ToolId,
    ToolInvocation,
    ToolRunnerConfig,
)


def _python_definition(*, timeout: float = 2.0) -> ToolDefinition:
    return ToolDefinition(
        tool_id=ToolId("python_child"),
        display_name="Python Child",
        description="Portable child process used by framework tests.",
        executable=sys.executable,
        default_timeout_seconds=timeout,
    )


def test_success_captures_stdout_and_stderr_separately() -> None:
    runner = LocalSubprocessToolRunner()
    definition = _python_definition()

    result = runner.run(
        definition,
        ToolInvocation(
            definition.tool_id,
            arguments=(
                "-c",
                "import sys; print('hello'); print('notice', file=sys.stderr)",
            ),
        ),
    )

    assert result.status is ToolExecutionStatus.SUCCESS
    assert result.exit_code == 0
    assert result.stdout == "hello\n"
    assert result.stderr == "notice\n"
    assert result.duration_seconds >= 0
    assert not result.timed_out


def test_non_zero_exit_is_failure_with_both_streams() -> None:
    runner = LocalSubprocessToolRunner()
    definition = _python_definition()

    result = runner.run(
        definition,
        ToolInvocation(
            definition.tool_id,
            arguments=(
                "-c",
                "import sys; print('out'); print('err', file=sys.stderr); sys.exit(7)",
            ),
        ),
    )

    assert result.status is ToolExecutionStatus.FAILURE
    assert result.exit_code == 7
    assert result.stdout == "out\n"
    assert result.stderr == "err\n"


def test_timeout_returns_typed_result_without_exception() -> None:
    runner = LocalSubprocessToolRunner()
    definition = _python_definition(timeout=1.0)

    result = runner.run(
        definition,
        ToolInvocation(
            definition.tool_id,
            arguments=("-c", "import time; time.sleep(1)"),
            timeout_seconds=0.02,
        ),
    )

    assert result.status is ToolExecutionStatus.TIMEOUT
    assert result.exit_code is None
    assert result.timed_out
    assert result.duration_seconds < 2


def test_missing_executable_is_sanitized_not_found() -> None:
    definition = ToolDefinition(
        "guaranteed_missing",
        "Missing",
        "Guaranteed absent test executable.",
        "redforge_guaranteed_missing_executable_17f38a",
    )

    result = LocalSubprocessToolRunner().run(
        definition,
        ToolInvocation(definition.tool_id),
    )

    assert result.status is ToolExecutionStatus.NOT_FOUND
    assert result.exit_code is None
    assert result.stdout == ""
    assert "PATH" not in result.stderr
    assert "Users" not in result.stderr


def test_shell_metacharacters_arrive_as_literal_argv(tmp_path: Path) -> None:
    definition = _python_definition()
    values = (
        ";",
        "&&",
        "|",
        "$(echo injected)",
        "`echo injected`",
        "two words",
        '"quoted"',
        "*",
        ">",
        "<",
    )
    marker = tmp_path / "must_not_exist"
    code = "import json,sys; print(json.dumps(sys.argv[1:]))"

    result = LocalSubprocessToolRunner().run(
        definition,
        ToolInvocation(
            definition.tool_id,
            arguments=("-c", code, *values, str(marker)),
        ),
    )

    assert result.status is ToolExecutionStatus.SUCCESS
    assert tuple(json.loads(result.stdout)) == (*values, str(marker))
    assert not marker.exists()


def test_safe_environment_is_allowlisted_and_overrides_win(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REDFORGE_ALLOWED_TEST", "parent")
    monkeypatch.setenv("REDFORGE_BLOCKED_SECRET", "blocked-secret")
    inherited = (
        *ToolRunnerConfig().inherited_environment_keys,
        "REDFORGE_ALLOWED_TEST",
    )
    runner = LocalSubprocessToolRunner(
        ToolRunnerConfig(inherited_environment_keys=inherited)
    )
    definition = _python_definition()
    code = (
        "import json,os; print(json.dumps({"
        "'allowed':os.getenv('REDFORGE_ALLOWED_TEST'),"
        "'blocked':os.getenv('REDFORGE_BLOCKED_SECRET'),"
        "'explicit':os.getenv('REDFORGE_EXPLICIT')}))"
    )
    invocation = ToolInvocation(
        definition.tool_id,
        arguments=("-c", code),
        environment={
            "REDFORGE_ALLOWED_TEST": "override",
            "REDFORGE_EXPLICIT": "explicit-secret",
        },
    )

    result = runner.run(definition, invocation)
    observed = json.loads(result.stdout)

    assert observed == {
        "allowed": "override",
        "blocked": None,
        "explicit": "explicit-secret",
    }
    assert "explicit-secret" not in repr(invocation)
    assert "blocked-secret" not in repr(result)


def test_working_directory_is_per_process_and_validated(tmp_path: Path) -> None:
    runner = LocalSubprocessToolRunner()
    definition = _python_definition()
    parent_cwd = Path.cwd()
    valid = runner.run(
        definition,
        ToolInvocation(
            definition.tool_id,
            arguments=("-c", "import os; print(os.getcwd())"),
            cwd=tmp_path,
        ),
    )
    file_path = tmp_path / "file.txt"
    file_path.write_text("x", encoding="utf-8")
    invalid_file = runner.run(
        definition,
        ToolInvocation(definition.tool_id, cwd=file_path),
    )
    missing = runner.run(
        definition,
        ToolInvocation(definition.tool_id, cwd=tmp_path / "missing"),
    )

    assert Path(valid.stdout.strip()) == tmp_path
    assert invalid_file.status is ToolExecutionStatus.ERROR
    assert missing.status is ToolExecutionStatus.ERROR
    assert "file.txt" not in invalid_file.stderr
    assert Path.cwd() == parent_cwd


def test_stdout_and_stderr_are_independently_truncated() -> None:
    runner = LocalSubprocessToolRunner(
        ToolRunnerConfig(
            max_stdout_bytes=7,
            max_stderr_bytes=5,
            max_stdin_bytes=100,
        )
    )
    definition = _python_definition()
    code = (
        "import sys;"
        "sys.stdout.buffer.write(('é'*20).encode());"
        "sys.stderr.buffer.write(b'abcdefghij')"
    )

    result = runner.run(
        definition,
        ToolInvocation(definition.tool_id, arguments=("-c", code)),
    )

    assert result.status is ToolExecutionStatus.SUCCESS
    assert result.stdout == "ééé"
    assert result.stderr == "abcde"
    assert result.truncated
    assert "abcde" not in repr(result)


def test_stdin_text_empty_and_limit_behavior() -> None:
    definition = _python_definition()
    code = "import sys; print(sys.stdin.read()[::-1])"
    runner = LocalSubprocessToolRunner(
        ToolRunnerConfig(max_stdin_bytes=8)
    )

    text = runner.run(
        definition,
        ToolInvocation(
            definition.tool_id,
            arguments=("-c", code),
            stdin="abc",
        ),
    )
    empty = runner.run(
        definition,
        ToolInvocation(
            definition.tool_id,
            arguments=("-c", "import sys; print(len(sys.stdin.read()))"),
        ),
    )
    too_large = runner.run(
        definition,
        ToolInvocation(
            definition.tool_id,
            arguments=("-c", code),
            stdin="sensitive-over-limit",
        ),
    )

    assert text.stdout == "cba\n"
    assert empty.stdout == "0\n"
    assert too_large.status is ToolExecutionStatus.ERROR
    assert "sensitive-over-limit" not in too_large.stderr


def test_availability_does_not_execute_process() -> None:
    runner = LocalSubprocessToolRunner()

    assert runner.is_available(_python_definition())
    assert not runner.is_available(
        ToolDefinition(
            "missing",
            "Missing",
            "Missing test executable.",
            "redforge_missing_executable_82b",
        )
    )


def test_invocation_identity_mismatch_fails_before_execution() -> None:
    with pytest.raises(ValueError, match="identity"):
        LocalSubprocessToolRunner().run(
            _python_definition(),
            ToolInvocation("different"),
        )


def test_runner_rejects_invalid_configuration_object() -> None:
    with pytest.raises(TypeError, match="ToolRunnerConfig"):
        LocalSubprocessToolRunner(object())  # type: ignore[arg-type]


def test_parent_environment_is_not_mutated() -> None:
    before = dict(os.environ)
    definition = _python_definition()
    LocalSubprocessToolRunner().run(
        definition,
        ToolInvocation(
            definition.tool_id,
            arguments=("-c", "pass"),
            environment={"REDFORGE_CHILD_ONLY": "yes"},
        ),
    )

    assert dict(os.environ) == before
