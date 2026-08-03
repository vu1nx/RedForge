"""Safe local subprocess implementation of the external tool execution port."""

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import cast

from redforge.sdk.tool import (
    ToolDefinition,
    ToolExecutableResolution,
    ToolExecutableResolutionStatus,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolInvocation,
    ToolRunnerConfig,
)

_IDENTITY_OUTPUT_LIMIT = 16_384
_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


@dataclass(frozen=True, slots=True)
class _ExecutableSelection:
    status: ToolExecutableResolutionStatus
    candidate: str | None = None
    resolved_path: str | None = None
    version: str | None = None


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
        """Return whether any candidate exists without executing it."""
        self._validate_definition(definition)
        environment = self._environment(())
        try:
            return any(
                self._locate(candidate, environment) is not None
                for candidate in definition.executable_candidates
            )
        except OSError:
            return False

    def resolve(
        self,
        definition: ToolDefinition,
    ) -> ToolExecutableResolution:
        """Resolve candidates and perform declared target-free identity checks."""
        self._validate_definition(definition)
        selection = self._select(definition, self._environment(()))
        safe_candidate = (
            None
            if selection.candidate is None
            else Path(selection.candidate).name
        )
        return ToolExecutableResolution(
            tool_id=definition.tool_id,
            status=selection.status,
            executable_candidate=safe_candidate,
            version=selection.version,
        )

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
            selection = self._select(definition, environment)
        except OSError:
            return self._operational_result(
                definition,
                ToolExecutionStatus.ERROR,
                started,
                "tool executable resolution failed",
            )
        if selection.status is ToolExecutableResolutionStatus.UNAVAILABLE:
            return self._operational_result(
                definition,
                ToolExecutionStatus.NOT_FOUND,
                started,
                "tool executable was not found",
            )
        if selection.status is ToolExecutableResolutionStatus.INCOMPATIBLE:
            return self._operational_result(
                definition,
                ToolExecutionStatus.ERROR,
                started,
                "tool executable identity is incompatible",
            )
        if selection.status is ToolExecutableResolutionStatus.ERROR:
            return self._operational_result(
                definition,
                ToolExecutionStatus.ERROR,
                started,
                "tool executable identity probe failed",
            )
        executable = selection.resolved_path
        if executable is None:
            return self._operational_result(
                definition,
                ToolExecutionStatus.ERROR,
                started,
                "tool executable resolution failed",
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

    def _select(
        self,
        definition: ToolDefinition,
        environment: dict[str, str],
    ) -> _ExecutableSelection:
        incompatible = False
        probe_error = False
        for candidate in definition.executable_candidates:
            try:
                resolved_path = self._locate(candidate, environment)
            except OSError:
                probe_error = True
                continue
            if resolved_path is None:
                continue
            if definition.identity_output_pattern is None:
                return _ExecutableSelection(
                    ToolExecutableResolutionStatus.RESOLVED,
                    candidate,
                    resolved_path,
                )
            status, version = self._probe_identity(
                definition,
                resolved_path,
                environment,
            )
            if status is ToolExecutableResolutionStatus.RESOLVED:
                return _ExecutableSelection(
                    status,
                    candidate,
                    resolved_path,
                    version,
                )
            if status is ToolExecutableResolutionStatus.ERROR:
                probe_error = True
            else:
                incompatible = True
        if probe_error:
            return _ExecutableSelection(ToolExecutableResolutionStatus.ERROR)
        if incompatible:
            return _ExecutableSelection(
                ToolExecutableResolutionStatus.INCOMPATIBLE
            )
        return _ExecutableSelection(ToolExecutableResolutionStatus.UNAVAILABLE)

    def _probe_identity(
        self,
        definition: ToolDefinition,
        resolved_path: str,
        environment: dict[str, str],
    ) -> tuple[ToolExecutableResolutionStatus, str | None]:
        try:
            completed = subprocess.run(
                [resolved_path, *definition.version_argument],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env=environment,
                timeout=definition.identity_timeout_seconds,
                check=False,
                shell=False,
            )
        except (subprocess.TimeoutExpired, PermissionError, OSError):
            return ToolExecutableResolutionStatus.ERROR, None
        stdout, _ = _bounded_decode(
            completed.stdout,
            limit=min(self._config.max_stdout_bytes, _IDENTITY_OUTPUT_LIMIT),
            encoding=self._config.encoding,
        )
        stderr, _ = _bounded_decode(
            completed.stderr,
            limit=min(self._config.max_stderr_bytes, _IDENTITY_OUTPUT_LIMIT),
            encoding=self._config.encoding,
        )
        if completed.returncode != 0:
            return ToolExecutableResolutionStatus.INCOMPATIBLE, None
        pattern = definition.identity_output_pattern
        if pattern is None:
            return ToolExecutableResolutionStatus.RESOLVED, None
        evidence = _ANSI_ESCAPE_PATTERN.sub("", f"{stdout}\n{stderr}")
        match = re.search(pattern, evidence)
        if match is None:
            return ToolExecutableResolutionStatus.INCOMPATIBLE, None
        version = match.group("version")
        if (
            not version
            or len(version) > 128
            or any(character in version for character in "\r\n")
        ):
            return ToolExecutableResolutionStatus.INCOMPATIBLE, None
        return ToolExecutableResolutionStatus.RESOLVED, version

    @staticmethod
    def _locate(
        candidate: str,
        environment: dict[str, str],
    ) -> str | None:
        return shutil.which(
            candidate,
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
