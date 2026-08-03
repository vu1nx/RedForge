"""Portable integration tests for LocalSubprocessToolRunner."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters import LocalSubprocessToolRunner
from redforge.sdk import (
    ToolDefinition,
    ToolExecutableResolutionStatus,
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


def _identity_definition() -> ToolDefinition:
    return ToolDefinition(
        "httpx",
        "HTTPX",
        "ProjectDiscovery HTTP probe.",
        executable_candidates=("httpx-toolkit", "httpx"),
        version_argument=("-version",),
        identity_output_pattern=(
            r"(?m)^\[INF\] Current Version: "
            r"(?P<version>v[0-9]+(?:\.[0-9]+)+)$"
        ),
    )


def _fake_executable(candidate: str) -> str:
    return str(Path("C:/private-tools") / candidate)


def _locate_fake(
    candidate: str,
    *,
    path: str | None = None,  # noqa: ARG001
) -> str:
    return _fake_executable(candidate)


def _locate_nothing(
    candidate: str,  # noqa: ARG001
    *,
    path: str | None = None,  # noqa: ARG001
) -> None:
    return None


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


def test_resolution_selects_first_compatible_candidate_without_path_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        "redforge.adapters.tool_runner.shutil.which",
        _locate_fake,
    )

    def completed(argv: list[str], **kwargs: object) -> object:
        calls.append(tuple(argv))
        assert kwargs["shell"] is False
        assert kwargs["stdin"] is subprocess.DEVNULL
        return subprocess.CompletedProcess(
            argv,
            0,
            b"[INF] Current Version: v1.9.0\n",
            b"",
        )

    monkeypatch.setattr(
        "redforge.adapters.tool_runner.subprocess.run",
        completed,
    )

    result = LocalSubprocessToolRunner().resolve(_identity_definition())

    assert result.status is ToolExecutableResolutionStatus.RESOLVED
    assert result.tool_id == ToolId("httpx")
    assert result.executable_candidate == "httpx-toolkit"
    assert result.version == "v1.9.0"
    assert calls == [
        (_fake_executable("httpx-toolkit"), "-version"),
    ]
    assert "private-tools" not in repr(result)
    assert _fake_executable("httpx-toolkit") not in repr(result)


def test_resolution_uses_second_candidate_when_first_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def locate_second(
        candidate: str,
        *,
        path: str | None = None,  # noqa: ARG001
    ) -> str | None:
        return (
            None
            if candidate == "httpx-toolkit"
            else _fake_executable(candidate)
        )

    monkeypatch.setattr(
        "redforge.adapters.tool_runner.shutil.which",
        locate_second,
    )

    def completed(
        argv: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            argv,
            0,
            b"[INF] Current Version: v1.8.1\n",
            b"",
        )

    monkeypatch.setattr(
        "redforge.adapters.tool_runner.subprocess.run",
        completed,
    )

    result = LocalSubprocessToolRunner().resolve(_identity_definition())

    assert result.status is ToolExecutableResolutionStatus.RESOLVED
    assert result.executable_candidate == "httpx"
    assert result.version == "v1.8.1"


def test_resolution_skips_wrong_identity_and_selects_second_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        "redforge.adapters.tool_runner.shutil.which",
        _locate_fake,
    )

    def completed(argv: list[str], **_kwargs: object) -> object:
        candidate = Path(argv[0]).name
        calls.append(candidate)
        output = (
            b"Python HTTPX command line client\n"
            if candidate == "httpx-toolkit"
            else b"[INF] Current Version: v1.9.0\n"
        )
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(
        "redforge.adapters.tool_runner.subprocess.run",
        completed,
    )

    result = LocalSubprocessToolRunner().resolve(_identity_definition())

    assert result.status is ToolExecutableResolutionStatus.RESOLVED
    assert result.executable_candidate == "httpx"
    assert calls == ["httpx-toolkit", "httpx"]


def test_resolution_distinguishes_absent_incompatible_and_probe_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = LocalSubprocessToolRunner()
    monkeypatch.setattr(
        "redforge.adapters.tool_runner.shutil.which",
        _locate_nothing,
    )
    absent = runner.resolve(_identity_definition())

    monkeypatch.setattr(
        "redforge.adapters.tool_runner.shutil.which",
        _locate_fake,
    )

    def incompatible_process(
        argv: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            argv,
            2,
            b"",
            b"secret Python CLI error C:\\private\\httpx",
        )

    monkeypatch.setattr(
        "redforge.adapters.tool_runner.subprocess.run",
        incompatible_process,
    )
    incompatible = runner.resolve(_identity_definition())

    def raise_probe_error(
        _argv: list[str],
        **_kwargs: object,
    ) -> object:
        raise OSError("secret path C:\\private\\httpx")

    monkeypatch.setattr(
        "redforge.adapters.tool_runner.subprocess.run",
        raise_probe_error,
    )
    error = runner.resolve(_identity_definition())

    assert absent.status is ToolExecutableResolutionStatus.UNAVAILABLE
    assert incompatible.status is ToolExecutableResolutionStatus.INCOMPATIBLE
    assert error.status is ToolExecutableResolutionStatus.ERROR
    for result in (absent, incompatible, error):
        assert result.executable_candidate is None
        assert result.version is None
        assert "private" not in repr(result)
        assert "secret" not in repr(result)


def test_python_httpx_only_candidate_is_incompatible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def locate_python_only(
        candidate: str,
        *,
        path: str | None = None,  # noqa: ARG001
    ) -> str | None:
        return (
            _fake_executable(candidate)
            if candidate == "httpx"
            else None
        )

    def python_httpx_version(
        argv: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            argv,
            2,
            b"",
            b"Error: No such option: -v",
        )

    monkeypatch.setattr(
        "redforge.adapters.tool_runner.shutil.which",
        locate_python_only,
    )
    monkeypatch.setattr(
        "redforge.adapters.tool_runner.subprocess.run",
        python_httpx_version,
    )

    result = LocalSubprocessToolRunner().resolve(_identity_definition())

    assert result.status is ToolExecutableResolutionStatus.INCOMPATIBLE
    assert result.executable_candidate is None
    assert result.version is None


def test_resolution_is_not_cached_across_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    available = {"candidate": "httpx-toolkit"}

    def locate_current(
        candidate: str,
        *,
        path: str | None = None,  # noqa: ARG001
    ) -> str | None:
        return (
            _fake_executable(candidate)
            if candidate == available["candidate"]
            else None
        )

    def valid_version(
        argv: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            argv,
            0,
            b"[INF] Current Version: v1.9.0\n",
            b"",
        )

    monkeypatch.setattr(
        "redforge.adapters.tool_runner.shutil.which",
        locate_current,
    )
    monkeypatch.setattr(
        "redforge.adapters.tool_runner.subprocess.run",
        valid_version,
    )
    runner = LocalSubprocessToolRunner()

    first = runner.resolve(_identity_definition())
    available["candidate"] = "httpx"
    second = runner.resolve(_identity_definition())

    assert first.executable_candidate == "httpx-toolkit"
    assert second.executable_candidate == "httpx"


def test_runtime_uses_resolved_candidate_after_target_free_identity_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[str, ...], object]] = []
    monkeypatch.setattr(
        "redforge.adapters.tool_runner.shutil.which",
        _locate_fake,
    )

    def completed(argv: list[str], **kwargs: object) -> object:
        calls.append((tuple(argv), kwargs.get("input")))
        if tuple(argv[1:]) == ("-version",):
            return subprocess.CompletedProcess(
                argv,
                0,
                b"[INF] Current Version: v1.9.0\n",
                b"",
            )
        return subprocess.CompletedProcess(argv, 0, b"runtime", b"")

    monkeypatch.setattr(
        "redforge.adapters.tool_runner.subprocess.run",
        completed,
    )
    definition = _identity_definition()

    result = LocalSubprocessToolRunner().run(
        definition,
        ToolInvocation(
            definition.tool_id,
            arguments=("-json",),
            stdin="http://authorized.test:8080\n",
        ),
    )

    assert result.status is ToolExecutionStatus.SUCCESS
    assert calls[0] == (
        (_fake_executable("httpx-toolkit"), "-version"),
        None,
    )
    assert calls[1][0] == (
        _fake_executable("httpx-toolkit"),
        "-json",
    )
    assert calls[1][1] == b"http://authorized.test:8080\n"


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
