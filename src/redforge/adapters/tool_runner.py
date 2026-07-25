"""Safe local subprocess implementation of the external tool execution port."""

import os
import shutil
import subprocess
from time import perf_counter
from typing import cast

from redforge.sdk.tool import (
    ToolDefinition,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolInvocation,
    ToolRunnerConfig,
)


def _bounded_decode(
    value: bytes | str | None,
    *,
    limit: int,
    encoding: str,
) -> tuple[str, bool]:
    if value is None:
        return "", False
    raw = value.encode(encoding, errors="replace") if isinstance(value, str) else value
    truncated = len(raw) > limit
    decoded = raw[:limit].decode(encoding, errors="ignore")
    return decoded.replace("\r\n", "\n").replace("\r", "\n"), truncated


class LocalSubprocessToolRunner:
    """Execute literal argv without a shell under explicit generic limits."""

    def __init__(self, config: ToolRunnerConfig | None = None) -> None:
        if config is not None and not isinstance(
            cast(object, config), ToolRunnerConfig
        ):
            raise TypeError("local tool runner requires ToolRunnerConfig")
        self._config = config or ToolRunnerConfig()

    @property
    def config(self) -> ToolRunnerConfig:
        """Return immutable runner configuration."""
        return self._config

    def is_available(self, definition: ToolDefinition) -> bool:
        """Resolve an executable without running it or changing state."""
        self._validate_definition(definition)
        environment = self._environment(())
        return self._resolve(definition, environment) is not None

    def run(
        self,
        definition: ToolDefinition,
        invocation: ToolInvocation,
    ) -> ToolExecutionResult:
        """Execute one invocation and return bounded, sanitized process evidence."""
        self._validate_definition(definition)
        if not isinstance(cast(object, invocation), ToolInvocation):
            raise TypeError("local tool runner requires a ToolInvocation")
        if invocation.tool_id != definition.tool_id:
            raise ValueError("tool invocation identity does not match definition")

        started = perf_counter()
        try:
            cwd_is_valid = invocation.cwd is None or (
                invocation.cwd.exists() and invocation.cwd.is_dir()
            )
        except OSError:
            cwd_is_valid = False
        if not cwd_is_valid:
            return self._operational_result(
                definition,
                ToolExecutionStatus.ERROR,
                started,
                "tool working directory is invalid",
            )

        environment = self._environment(invocation.environment)
        try:
            executable = self._resolve(definition, environment)
        except OSError:
            return self._operational_result(
                definition,
                ToolExecutionStatus.ERROR,
                started,
                "tool executable resolution failed",
            )
        if executable is None:
            return self._operational_result(
                definition,
                ToolExecutionStatus.NOT_FOUND,
                started,
                "tool executable was not found",
            )

        stdin = invocation.stdin
        try:
            stdin_bytes = (
                None
                if stdin is None
                else (
                    stdin.encode(self._config.encoding)
                    if isinstance(stdin, str)
                    else stdin
                )
            )
        except UnicodeError:
            return self._operational_result(
                definition,
                ToolExecutionStatus.ERROR,
                started,
                "tool standard input encoding failed",
            )
        if stdin_bytes is not None and len(stdin_bytes) > self._config.max_stdin_bytes:
            return self._operational_result(
                definition,
                ToolExecutionStatus.ERROR,
                started,
                "tool standard input exceeds configured limit",
            )

        timeout = (
            invocation.timeout_seconds
            if invocation.timeout_seconds is not None
            else definition.default_timeout_seconds
        )
        argv = [executable, *invocation.arguments]
        try:
            if stdin_bytes is None:
                completed = subprocess.run(
                    argv,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    cwd=invocation.cwd,
                    env=environment,
                    timeout=timeout,
                    check=False,
                    shell=False,
                )
            else:
                completed = subprocess.run(
                    argv,
                    input=stdin_bytes,
                    capture_output=True,
                    cwd=invocation.cwd,
                    env=environment,
                    timeout=timeout,
                    check=False,
                    shell=False,
                )
        except subprocess.TimeoutExpired as error:
            stdout, stdout_truncated = _bounded_decode(
                error.stdout,
                limit=self._config.max_stdout_bytes,
                encoding=self._config.encoding,
            )
            stderr, stderr_truncated = _bounded_decode(
                error.stderr,
                limit=self._config.max_stderr_bytes,
                encoding=self._config.encoding,
            )
            return ToolExecutionResult(
                tool_id=definition.tool_id,
                status=ToolExecutionStatus.TIMEOUT,
                exit_code=None,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=perf_counter() - started,
                timed_out=True,
                truncated=stdout_truncated or stderr_truncated,
            )
        except FileNotFoundError:
            return self._operational_result(
                definition,
                ToolExecutionStatus.NOT_FOUND,
                started,
                "tool executable was not found",
            )
        except PermissionError:
            return self._operational_result(
                definition,
                ToolExecutionStatus.ERROR,
                started,
                "tool execution permission was denied",
            )
        except OSError:
            return self._operational_result(
                definition,
                ToolExecutionStatus.ERROR,
                started,
                "tool execution failed",
            )

        stdout, stdout_truncated = _bounded_decode(
            completed.stdout,
            limit=self._config.max_stdout_bytes,
            encoding=self._config.encoding,
        )
        stderr, stderr_truncated = _bounded_decode(
            completed.stderr,
            limit=self._config.max_stderr_bytes,
            encoding=self._config.encoding,
        )
        return ToolExecutionResult(
            tool_id=definition.tool_id,
            status=(
                ToolExecutionStatus.SUCCESS
                if completed.returncode == 0
                else ToolExecutionStatus.FAILURE
            ),
            exit_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=perf_counter() - started,
            truncated=stdout_truncated or stderr_truncated,
        )

    @staticmethod
    def _validate_definition(definition: ToolDefinition) -> None:
        if not isinstance(cast(object, definition), ToolDefinition):
            raise TypeError("local tool runner requires a ToolDefinition")

    def _environment(
        self,
        overrides: tuple[tuple[str, str], ...],
    ) -> dict[str, str]:
        if self._config.inherit_environment:
            environment = dict(os.environ)
        else:
            environment = {
                key: os.environ[key]
                for key in self._config.inherited_environment_keys
                if key in os.environ
            }
        for name, value in overrides:
            if os.name == "nt":
                for existing in tuple(environment):
                    if existing.casefold() == name.casefold():
                        del environment[existing]
            environment[name] = value
        return dict(sorted(environment.items()))

    @staticmethod
    def _resolve(
        definition: ToolDefinition,
        environment: dict[str, str],
    ) -> str | None:
        return shutil.which(
            definition.executable,
            path=environment.get("PATH", ""),
        )

    @staticmethod
    def _operational_result(
        definition: ToolDefinition,
        status: ToolExecutionStatus,
        started: float,
        diagnostic: str,
    ) -> ToolExecutionResult:
        return ToolExecutionResult(
            tool_id=definition.tool_id,
            status=status,
            exit_code=None,
            stdout="",
            stderr=diagnostic,
            duration_seconds=perf_counter() - started,
            timed_out=status is ToolExecutionStatus.TIMEOUT,
        )
