"""Typed, implementation-independent external tool execution contracts."""

import codecs
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast


def _validated_identifier(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip().lower()
        or not (value[0].isascii() and value[0].islower())
        or value[-1] == "_"
        or "__" in value
        or any(
            not (character.isascii() and character.isalnum())
            and character != "_"
            for character in value
        )
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _positive_number(value: object, *, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{label} must be a positive finite number")
    return float(value)


def _string_tuple(
    values: Iterable[str],
    *,
    label: str,
    allow_empty_items: bool = False,
) -> tuple[str, ...]:
    if isinstance(cast(object, values), (str, bytes)):
        raise TypeError(f"{label} must be a collection")
    try:
        items = tuple(values)
    except TypeError as error:
        raise TypeError(f"{label} must be iterable") from error
    for item in items:
        if not isinstance(cast(object, item), str):
            raise TypeError(f"{label} must contain strings")
        if "\x00" in item or (not allow_empty_items and not item):
            raise ValueError(f"{label} contains an invalid value")
    return items


def _environment(
    values: Mapping[str, str] | Iterable[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    if isinstance(values, Mapping):
        raw: tuple[tuple[str, str], ...] = tuple(
            cast(Mapping[str, str], values).items()
        )
    else:
        if isinstance(cast(object, values), (str, bytes)):
            raise TypeError("environment must be a mapping or pair collection")
        try:
            raw = tuple(values)
        except TypeError as error:
            raise TypeError("environment must be iterable") from error
    normalized: list[tuple[str, str]] = []
    for item in raw:
        if (
            not isinstance(cast(object, item), tuple)
            or len(item) != 2
            or not all(isinstance(cast(object, part), str) for part in item)
        ):
            raise TypeError("environment must contain string pairs")
        name, value = item
        if not name or "=" in name or "\x00" in name:
            raise ValueError("environment variable name is invalid")
        if "\x00" in value:
            raise ValueError("environment variable value is invalid")
        normalized.append((name, value))
    names = tuple(name for name, _ in normalized)
    folded_names = tuple(name.casefold() for name in names)
    if len(folded_names) != len(set(folded_names)):
        raise ValueError("environment contains duplicate variable names")
    return tuple(sorted(normalized))


@dataclass(frozen=True, slots=True, order=True)
class ToolId:
    """Stable serialized identity for an external execution provider."""

    value: str

    def __post_init__(self) -> None:
        _validated_identifier(cast(object, self.value), label="tool ID")

    def __str__(self) -> str:
        """Return the stable serialized identity."""
        return self.value


def normalize_tool_id(value: ToolId | str) -> ToolId:
    """Normalize a typed or migration-boundary string tool identity."""
    if isinstance(value, ToolId):
        return value
    if isinstance(cast(object, value), str):
        return ToolId(value)
    raise TypeError("tool identity must be ToolId or string")


def _tags(values: Iterable[str]) -> tuple[str, ...]:
    items = _string_tuple(values, label="tags")
    normalized = tuple(item.strip().lower() for item in items)
    for tag in normalized:
        _validated_identifier(tag, label="tool tag")
    if len(normalized) != len(set(normalized)):
        raise ValueError("tool tags contain duplicates")
    return tuple(sorted(normalized))


def _executable_candidate(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or any(character in value for character in "\r\n\t")
        or (
            any(character.isspace() for character in value)
            and not Path(value).is_absolute()
        )
    ):
        raise ValueError("tool executable must be one executable token")
    return value


@dataclass(frozen=True, slots=True, init=False, repr=False)
class ToolDefinition:
    """Immutable static metadata for one replaceable external executable."""

    tool_id: ToolId
    display_name: str
    description: str
    executable_candidates: tuple[str, ...]
    version_argument: tuple[str, ...]
    identity_output_pattern: str | None
    identity_timeout_seconds: float
    default_timeout_seconds: float
    tags: tuple[str, ...]

    def __init__(
        self,
        tool_id: ToolId | str,
        display_name: str,
        description: str,
        executable: str | None = None,
        version_argument: Iterable[str] = ("--version",),
        default_timeout_seconds: float = 300.0,
        tags: Iterable[str] = (),
        executable_candidates: Iterable[str] | None = None,
        identity_output_pattern: str | None = None,
        identity_timeout_seconds: float = 5.0,
    ) -> None:
        if executable is not None and executable_candidates is not None:
            raise ValueError(
                "tool executable and executable candidates are mutually exclusive"
            )
        if executable_candidates is None:
            if executable is None:
                raise ValueError("tool executable candidates must not be empty")
            candidates = (_executable_candidate(executable),)
        else:
            candidates = tuple(
                _executable_candidate(item)
                for item in _string_tuple(
                    executable_candidates,
                    label="executable candidates",
                )
            )
            if not candidates:
                raise ValueError("tool executable candidates must not be empty")
        if len(candidates) != len(set(candidates)):
            raise ValueError("tool executable candidates contain duplicates")
        pattern: str | None
        if identity_output_pattern is None:
            pattern = None
        elif (
            not isinstance(cast(object, identity_output_pattern), str)
            or not identity_output_pattern
            or len(identity_output_pattern) > 512
            or any(
                character in identity_output_pattern
                for character in "\x00\r\n"
            )
        ):
            raise ValueError("tool identity output pattern is invalid")
        else:
            try:
                compiled = re.compile(identity_output_pattern)
            except re.error:
                raise ValueError(
                    "tool identity output pattern is invalid"
                ) from None
            if "version" not in compiled.groupindex:
                raise ValueError(
                    "tool identity output pattern requires a version group"
                )
            pattern = identity_output_pattern
        for label, value in (
            ("display name", display_name),
            ("description", description),
        ):
            if not isinstance(cast(object, value), str) or not value.strip():
                raise ValueError(f"tool {label} must not be empty")
        object.__setattr__(self, "tool_id", normalize_tool_id(tool_id))
        object.__setattr__(self, "display_name", display_name.strip())
        object.__setattr__(self, "description", description.strip())
        object.__setattr__(self, "executable_candidates", candidates)
        object.__setattr__(
            self,
            "version_argument",
            _string_tuple(
                version_argument,
                label="version argument",
                allow_empty_items=False,
            ),
        )
        object.__setattr__(self, "identity_output_pattern", pattern)
        object.__setattr__(
            self,
            "identity_timeout_seconds",
            _positive_number(
                identity_timeout_seconds,
                label="identity timeout",
            ),
        )
        object.__setattr__(
            self,
            "default_timeout_seconds",
            _positive_number(
                default_timeout_seconds,
                label="default timeout",
            ),
        )
        object.__setattr__(self, "tags", _tags(tags))

    @property
    def executable(self) -> str:
        """Return the preferred executable candidate for compatibility."""
        return self.executable_candidates[0]

    def __repr__(self) -> str:
        """Return metadata without exposing an executable filesystem path."""
        return (
            "ToolDefinition("
            f"tool_id={self.tool_id!r}, "
            f"display_name={self.display_name!r}, "
            f"executable_candidate_count={len(self.executable_candidates)!r}, "
            f"identity_validation={self.identity_output_pattern is not None!r}, "
            f"default_timeout_seconds={self.default_timeout_seconds!r}, "
            f"tags={self.tags!r})"
        )


@dataclass(frozen=True, slots=True, init=False, repr=False)
class ToolInvocation:
    """Immutable argv, working-directory, environment, and stdin request."""

    tool_id: ToolId
    arguments: tuple[str, ...]
    timeout_seconds: float | None
    cwd: Path | None
    environment: tuple[tuple[str, str], ...]
    stdin: str | bytes | None

    def __init__(
        self,
        tool_id: ToolId | str,
        arguments: Iterable[str] = (),
        timeout_seconds: float | None = None,
        cwd: Path | str | None = None,
        environment: (
            Mapping[str, str] | Iterable[tuple[str, str]]
        ) = (),
        stdin: str | bytes | None = None,
    ) -> None:
        if timeout_seconds is not None:
            timeout = _positive_number(
                timeout_seconds,
                label="invocation timeout",
            )
        else:
            timeout = None
        if stdin is not None and not isinstance(cast(object, stdin), (str, bytes)):
            raise TypeError("tool stdin must be text, bytes, or None")
        object.__setattr__(self, "tool_id", normalize_tool_id(tool_id))
        object.__setattr__(
            self,
            "arguments",
            _string_tuple(
                arguments,
                label="tool arguments",
                allow_empty_items=True,
            ),
        )
        object.__setattr__(self, "timeout_seconds", timeout)
        object.__setattr__(self, "cwd", Path(cwd) if cwd is not None else None)
        object.__setattr__(self, "environment", _environment(environment))
        object.__setattr__(self, "stdin", stdin)

    def __repr__(self) -> str:
        """Return safe request metadata without argument or secret values."""
        stdin_size = (
            0
            if self.stdin is None
            else len(
                self.stdin.encode("utf-8")
                if isinstance(self.stdin, str)
                else self.stdin
            )
        )
        return (
            "ToolInvocation("
            f"tool_id={self.tool_id!r}, "
            f"argument_count={len(self.arguments)}, "
            f"timeout_seconds={self.timeout_seconds!r}, "
            f"has_cwd={self.cwd is not None}, "
            f"environment_names={tuple(name for name, _ in self.environment)!r}, "
            f"stdin_bytes={stdin_size})"
        )


class ToolExecutionStatus(StrEnum):
    """Implementation-level outcome of one external process execution."""

    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"


class ToolExecutableResolutionStatus(StrEnum):
    """Sanitized outcome of deterministic executable candidate resolution."""

    RESOLVED = "resolved"
    UNAVAILABLE = "unavailable"
    INCOMPATIBLE = "incompatible"
    ERROR = "error"


@dataclass(frozen=True, slots=True, repr=False)
class ToolExecutableResolution:
    """Resolved candidate metadata without an absolute executable path."""

    tool_id: ToolId
    status: ToolExecutableResolutionStatus
    executable_candidate: str | None = None
    version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.tool_id), ToolId):
            raise TypeError("tool resolution identity must be a ToolId")
        if not isinstance(
            cast(object, self.status),
            ToolExecutableResolutionStatus,
        ):
            raise TypeError("tool resolution status is invalid")
        if self.status is ToolExecutableResolutionStatus.RESOLVED:
            if self.executable_candidate is None:
                raise ValueError(
                    "resolved tool requires an executable candidate"
                )
            _executable_candidate(self.executable_candidate)
            if (
                "/" in self.executable_candidate
                or "\\" in self.executable_candidate
            ):
                raise ValueError(
                    "resolved tool candidate must not expose a path"
                )
            if self.version is not None and (
                not isinstance(cast(object, self.version), str)
                or not self.version
                or len(self.version) > 128
                or any(character in self.version for character in "\r\n")
            ):
                raise ValueError("resolved tool version is invalid")
        elif (
            self.executable_candidate is not None
            or self.version is not None
        ):
            raise ValueError(
                "unresolved tool cannot expose candidate metadata"
            )

    def __repr__(self) -> str:
        """Return resolution state without candidate or path disclosure."""
        return (
            "ToolExecutableResolution("
            f"tool_id={self.tool_id!r}, "
            f"status={self.status!r}, "
            f"has_version={self.version is not None!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ToolExecutionResult:
    """Bounded process evidence with a safe metadata-only representation."""

    tool_id: ToolId
    status: ToolExecutionStatus
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    truncated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.tool_id), ToolId):
            raise TypeError("tool result identity must be a ToolId")
        if not isinstance(cast(object, self.status), ToolExecutionStatus):
            raise TypeError("tool result status must be ToolExecutionStatus")
        if self.exit_code is not None and (
            not isinstance(cast(object, self.exit_code), int)
            or isinstance(cast(object, self.exit_code), bool)
        ):
            raise TypeError("tool result exit code must be an integer or None")
        if not all(
            isinstance(cast(object, value), str)
            for value in (self.stdout, self.stderr)
        ):
            raise TypeError("tool result output must be text")
        duration = cast(object, self.duration_seconds)
        if (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(duration)
            or duration < 0
        ):
            raise ValueError("tool result duration must be non-negative")
        if self.status is ToolExecutionStatus.SUCCESS and self.exit_code != 0:
            raise ValueError("successful tool result must have exit code zero")
        if self.status is ToolExecutionStatus.FAILURE and (
            self.exit_code is None or self.exit_code == 0
        ):
            raise ValueError("failed tool result must have a non-zero exit code")
        if self.status in (
            ToolExecutionStatus.TIMEOUT,
            ToolExecutionStatus.NOT_FOUND,
        ) and self.exit_code is not None:
            raise ValueError("timeout and not-found results have no exit code")
        if not isinstance(cast(object, self.timed_out), bool):
            raise TypeError("timed_out must be boolean")
        if not isinstance(cast(object, self.truncated), bool):
            raise TypeError("truncated must be boolean")
        if self.timed_out != (self.status is ToolExecutionStatus.TIMEOUT):
            raise ValueError("timed_out must match timeout status")

    def __repr__(self) -> str:
        """Return evidence metadata without captured output."""
        return (
            "ToolExecutionResult("
            f"tool_id={self.tool_id!r}, "
            f"status={self.status!r}, "
            f"exit_code={self.exit_code!r}, "
            f"duration_seconds={self.duration_seconds!r}, "
            f"stdout_chars={len(self.stdout)}, "
            f"stderr_chars={len(self.stderr)}, "
            f"timed_out={self.timed_out!r}, "
            f"truncated={self.truncated!r})"
        )


_SAFE_INHERITED_ENVIRONMENT_KEYS = (
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "WINDIR",
)


@dataclass(frozen=True, slots=True)
class ToolRunnerConfig:
    """Immutable generic limits and explicit environment inheritance policy."""

    max_stdout_bytes: int = 1_048_576
    max_stderr_bytes: int = 1_048_576
    max_stdin_bytes: int = 1_048_576
    encoding: str = "utf-8"
    inherit_environment: bool = False
    inherited_environment_keys: tuple[str, ...] = (
        _SAFE_INHERITED_ENVIRONMENT_KEYS
    )

    def __post_init__(self) -> None:
        for label, value in (
            ("stdout limit", self.max_stdout_bytes),
            ("stderr limit", self.max_stderr_bytes),
            ("stdin limit", self.max_stdin_bytes),
        ):
            if (
                not isinstance(cast(object, value), int)
                or isinstance(cast(object, value), bool)
                or value <= 0
            ):
                raise ValueError(f"{label} must be a positive integer")
        if not isinstance(cast(object, self.encoding), str) or not self.encoding:
            raise ValueError("tool runner encoding must not be empty")
        if not isinstance(cast(object, self.inherit_environment), bool):
            raise TypeError("inherit_environment must be boolean")
        try:
            codecs.lookup(self.encoding)
        except LookupError:
            raise ValueError("tool runner encoding is invalid") from None
        keys = _string_tuple(
            self.inherited_environment_keys,
            label="inherited environment keys",
        )
        if any("=" in key for key in keys):
            raise ValueError("inherited environment key is invalid")
        folded_keys = tuple(key.casefold() for key in keys)
        if len(folded_keys) != len(set(folded_keys)):
            raise ValueError("inherited environment keys contain duplicates")
        object.__setattr__(self, "inherited_environment_keys", tuple(sorted(keys)))


class ToolRunner(Protocol):
    """Synchronous, implementation-independent external execution port."""

    def run(
        self,
        definition: ToolDefinition,
        invocation: ToolInvocation,
    ) -> ToolExecutionResult:
        """Execute one validated invocation."""
        ...

    def is_available(self, definition: ToolDefinition) -> bool:
        """Return whether the executable can currently be resolved."""
        ...


class ToolExecutableResolver(Protocol):
    """Resolve and validate executable candidates without scan input."""

    def resolve(
        self,
        definition: ToolDefinition,
    ) -> ToolExecutableResolution:
        """Return one sanitized target-free executable resolution."""
        ...
