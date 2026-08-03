"""Immutable provider-neutral environment diagnostic contracts."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, cast

from redforge.composition.profile import CompositionProfile
from redforge.sdk.readiness import ReadinessProbeResult
from redforge.sdk.tool import ToolDefinition, ToolId


class DoctorStatus(StrEnum):
    """Stable outcome of one environment check."""

    READY = "ready"
    WARNING = "warning"
    UNAVAILABLE = "unavailable"
    INCOMPATIBLE = "incompatible"
    MISCONFIGURED = "misconfigured"
    ERROR = "error"


class DoctorCheckKind(StrEnum):
    """Stable categories inspected without a target."""

    PLATFORM = "platform"
    PYTHON = "python"
    PACKAGE = "package"
    CAPABILITY_REGISTRY = "capability_registry"
    FACTORY_REGISTRY = "factory_registry"
    TOOL_REGISTRY = "tool_registry"
    COMPOSITION = "composition"
    TOOL_EXECUTABLE = "tool_executable"
    CONFIGURATION = "configuration"
    READINESS_METADATA = "readiness_metadata"
    PROVIDER = "provider"


class PlatformSupport(StrEnum):
    """Documented execution-platform classification."""

    PRIMARY = "primary"
    BEST_EFFORT = "best_effort"
    DEVELOPMENT = "development"
    LIBRARY_ONLY = "library_only"
    UNSUPPORTED = "unsupported"


class ToolCompatibility(StrEnum):
    """Compatibility confidence independent from availability."""

    UNVERIFIED = "unverified"
    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"


class ToolVersionProbeStatus(StrEnum):
    """Sanitized outcome of an optional target-free version probe."""

    DETECTED = "detected"
    UNAVAILABLE = "unavailable"
    MALFORMED = "malformed"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class PlatformInformation:
    """Bounded non-identifying operating-system metadata."""

    family: str
    architecture: str
    distribution: str | None
    support: PlatformSupport

    def __post_init__(self) -> None:
        _safe_text(self.family, "platform family", maximum=64)
        _safe_text(self.architecture, "platform architecture", maximum=64)
        if self.distribution is not None:
            _safe_text(
                self.distribution,
                "platform distribution",
                maximum=64,
            )
        if not isinstance(cast(object, self.support), PlatformSupport):
            raise TypeError("platform support is invalid")


@dataclass(frozen=True, slots=True)
class PythonRuntimeInformation:
    """Bounded Python implementation and version metadata."""

    implementation: str
    major: int
    minor: int
    supported: bool

    def __post_init__(self) -> None:
        _safe_text(
            self.implementation,
            "Python implementation",
            maximum=64,
        )
        for value in (self.major, self.minor):
            if (
                not isinstance(cast(object, value), int)
                or isinstance(cast(object, value), bool)
                or value < 0
            ):
                raise TypeError("Python version is invalid")
        if not isinstance(cast(object, self.supported), bool):
            raise TypeError("Python support status is invalid")

    @property
    def version(self) -> str:
        """Return stable major/minor display text."""
        return f"{self.major}.{self.minor}"


@dataclass(frozen=True, slots=True)
class ToolVersionProbeResult:
    """Sanitized bounded optional tool-version evidence."""

    status: ToolVersionProbeStatus
    version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.status), ToolVersionProbeStatus):
            raise TypeError("tool version probe status is invalid")
        if self.status is ToolVersionProbeStatus.DETECTED:
            if (
                not isinstance(cast(object, self.version), str)
                or not self.version
                or len(self.version) > 128
                or any(character in self.version for character in "\r\n")
            ):
                raise ValueError("detected tool version is invalid")
        elif self.version is not None:
            raise ValueError("non-detected version probe cannot contain a version")


@dataclass(frozen=True, slots=True)
class ToolDiagnostic:
    """One registry-derived external-tool diagnostic."""

    tool_id: ToolId
    status: DoctorStatus
    version: str | None = None
    compatibility: ToolCompatibility = ToolCompatibility.UNVERIFIED

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.tool_id), ToolId):
            raise TypeError("tool diagnostic identity is invalid")
        if not isinstance(cast(object, self.status), DoctorStatus):
            raise TypeError("tool diagnostic status is invalid")
        if self.version is not None:
            _safe_text(self.version, "tool version", maximum=128)
        if not isinstance(
            cast(object, self.compatibility), ToolCompatibility
        ):
            raise TypeError("tool compatibility is invalid")


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """One deterministic sanitized diagnostic check."""

    kind: DoctorCheckKind
    subject: str
    status: DoctorStatus
    required: bool = True

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.kind), DoctorCheckKind):
            raise TypeError("doctor check kind is invalid")
        _safe_text(self.subject, "doctor check subject", maximum=128)
        if not isinstance(cast(object, self.status), DoctorStatus):
            raise TypeError("doctor check status is invalid")
        if not isinstance(cast(object, self.required), bool):
            raise TypeError("doctor check requirement is invalid")


@dataclass(frozen=True, slots=True, repr=False)
class DoctorResult:
    """Complete immutable environment diagnostic without scan state."""

    profile: CompositionProfile
    platform: PlatformInformation
    python: PythonRuntimeInformation
    tools: tuple[ToolDiagnostic, ...] = field(repr=False)
    checks: tuple[DoctorCheck, ...] = field(repr=False)
    ready: bool

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.profile), CompositionProfile):
            raise TypeError("doctor result profile is invalid")
        if not isinstance(cast(object, self.platform), PlatformInformation):
            raise TypeError("doctor result platform is invalid")
        if not isinstance(
            cast(object, self.python), PythonRuntimeInformation
        ):
            raise TypeError("doctor result Python runtime is invalid")
        if (
            not isinstance(cast(object, self.tools), tuple)
            or not all(
                isinstance(item, ToolDiagnostic)
                for item in cast(tuple[object, ...], self.tools)
            )
        ):
            raise TypeError("doctor tools must be an immutable tuple")
        if (
            not isinstance(cast(object, self.checks), tuple)
            or not all(
                isinstance(item, DoctorCheck)
                for item in cast(tuple[object, ...], self.checks)
            )
        ):
            raise TypeError("doctor checks must be an immutable tuple")
        if not isinstance(cast(object, self.ready), bool):
            raise TypeError("doctor ready status is invalid")
        expected = all(
            not check.required
            or check.status in {DoctorStatus.READY, DoctorStatus.WARNING}
            for check in self.checks
        )
        if self.ready is not expected:
            raise ValueError("doctor ready flag does not match required checks")

    def __repr__(self) -> str:
        failures = sum(
            check.required
            and check.status
            not in {DoctorStatus.READY, DoctorStatus.WARNING}
            for check in self.checks
        )
        return (
            "DoctorResult("
            f"ready={self.ready!r}, "
            f"profile={self.profile.value!r}, "
            f"check_count={len(self.checks)}, "
            f"failure_count={failures})"
        )


class PlatformInformationProbe(Protocol):
    """Read bounded local platform metadata without subprocess or network."""

    def inspect(self) -> PlatformInformation:
        """Return sanitized platform information."""
        ...


class PythonRuntimeInformationProbe(Protocol):
    """Read current Python runtime metadata."""

    def inspect(self) -> PythonRuntimeInformation:
        """Return sanitized runtime information."""
        ...


class ExecutableAvailabilityProbe(Protocol):
    """Check one executable definition without executing it."""

    def check(self, definition: ToolDefinition) -> ReadinessProbeResult:
        """Return static executable readiness."""
        ...


class ToolVersionProbe(Protocol):
    """Optionally execute one bounded target-free version probe."""

    def probe(self, definition: ToolDefinition) -> ToolVersionProbeResult:
        """Return sanitized version evidence."""
        ...


def _safe_text(value: str, label: str, *, maximum: int) -> None:
    if (
        not isinstance(cast(object, value), str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{label} is invalid")
