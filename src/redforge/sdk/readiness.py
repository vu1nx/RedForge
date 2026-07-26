"""Provider-neutral readiness values and probe ports."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from redforge.sdk.capability_id import CapabilityId
from redforge.sdk.tool import ToolDefinition, ToolId


class ReadinessStatus(StrEnum):
    """Outcome of one preflight readiness check."""

    READY = "ready"
    UNAVAILABLE = "unavailable"
    MISCONFIGURED = "misconfigured"
    INCOMPATIBLE = "incompatible"
    ERROR = "error"


class ReadinessSubjectKind(StrEnum):
    """Sanitized category of a checked composition component."""

    CAPABILITY_FACTORY = "capability_factory"
    CAPABILITY_BINDING = "capability_binding"
    TOOL_DEFINITION = "tool_definition"
    TOOL_EXECUTABLE = "tool_executable"
    PROVIDER = "provider"
    PROVIDER_CONFIGURATION = "provider_configuration"


class ReadinessReason(StrEnum):
    """Fixed sanitized reason for a non-ready check."""

    FACTORY_MISSING = "factory_missing"
    FACTORY_BINDING_MISMATCH = "factory_binding_mismatch"
    TOOL_DEFINITION_MISSING = "tool_definition_missing"
    TOOL_PROBE_MISSING = "tool_probe_missing"
    EXECUTABLE_UNAVAILABLE = "executable_unavailable"
    PROVIDER_ABSENT = "provider_absent"
    PROVIDER_MISCONFIGURED = "provider_misconfigured"
    BINDING_INCOMPATIBLE = "binding_incompatible"
    PROBE_FAILED = "probe_failed"


@dataclass(frozen=True, slots=True, order=True)
class ProviderRole:
    """Stable non-secret identity for one provider composition role."""

    value: str

    def __post_init__(self) -> None:
        try:
            CapabilityId(cast(str, cast(object, self.value)))
        except (TypeError, ValueError):
            raise ValueError("provider role is invalid") from None


@dataclass(frozen=True, slots=True)
class ReadinessSubject:
    """Typed sanitized identity of one checked composition component."""

    kind: ReadinessSubjectKind
    capability_id: CapabilityId | None = None
    tool_id: ToolId | None = None
    provider_role: ProviderRole | None = None

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.kind), ReadinessSubjectKind):
            raise TypeError("readiness subject kind is invalid")
        identities = tuple(
            item
            for item in (
                self.capability_id,
                self.tool_id,
                self.provider_role,
            )
            if item is not None
        )
        if len(identities) != 1:
            raise ValueError("readiness subject requires one typed identity")


@dataclass(frozen=True, slots=True)
class ReadinessCheckResult:
    """Immutable sanitized result of one required readiness check."""

    subject: ReadinessSubject
    status: ReadinessStatus
    reason: ReadinessReason | None = None

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.subject), ReadinessSubject):
            raise TypeError("readiness check subject is invalid")
        if not isinstance(cast(object, self.status), ReadinessStatus):
            raise TypeError("readiness check status is invalid")
        if self.status is ReadinessStatus.READY:
            if self.reason is not None:
                raise ValueError("ready check cannot contain a failure reason")
        elif not isinstance(cast(object, self.reason), ReadinessReason):
            raise ValueError("non-ready check requires a sanitized reason")


class ReadinessRequirementKind(StrEnum):
    """Composition requirement derivable without constructing a capability."""

    TOOL = "tool"
    PROVIDER = "provider"


@dataclass(frozen=True, slots=True, order=True)
class ReadinessRequirement:
    """Immutable factory metadata for one tool or provider dependency."""

    kind: ReadinessRequirementKind
    tool_id: ToolId | None = None
    provider_role: ProviderRole | None = None
    configuration_present: bool = True

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.kind), ReadinessRequirementKind):
            raise TypeError("readiness requirement kind is invalid")
        if not isinstance(cast(object, self.configuration_present), bool):
            raise TypeError("provider configuration flag must be boolean")
        if self.kind is ReadinessRequirementKind.TOOL:
            if self.tool_id is None or self.provider_role is not None:
                raise ValueError("tool requirement identity is invalid")
            if not self.configuration_present:
                raise ValueError("tool requirement cannot store provider state")
        elif self.provider_role is None or self.tool_id is not None:
            raise ValueError("provider requirement identity is invalid")

    @classmethod
    def tool(cls, tool_id: ToolId) -> "ReadinessRequirement":
        """Describe one external tool required by a lazy factory."""
        return cls(kind=ReadinessRequirementKind.TOOL, tool_id=tool_id)

    @classmethod
    def provider(
        cls,
        provider_role: ProviderRole,
        *,
        configuration_present: bool,
    ) -> "ReadinessRequirement":
        """Describe one provider role and its static configuration presence."""
        return cls(
            kind=ReadinessRequirementKind.PROVIDER,
            provider_role=provider_role,
            configuration_present=configuration_present,
        )


@dataclass(frozen=True, slots=True)
class ReadinessProbeResult:
    """Typed sanitized result returned by a readiness probe."""

    status: ReadinessStatus
    reason: ReadinessReason | None = None

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.status), ReadinessStatus):
            raise TypeError("readiness probe status is invalid")
        if self.status is ReadinessStatus.READY:
            if self.reason is not None:
                raise ValueError("ready probe cannot contain a reason")
        elif not isinstance(cast(object, self.reason), ReadinessReason):
            raise ValueError("non-ready probe requires a sanitized reason")


class ReadinessProbeError(RuntimeError):
    """Expected sanitized boundary failure from a readiness probe."""


class ToolReadinessProbe(Protocol):
    """Check static executable readiness without running a tool."""

    def check(self, definition: ToolDefinition) -> ReadinessProbeResult:
        """Check one registered definition without scan arguments."""
        ...


class ProviderReadinessProbe(Protocol):
    """Check provider configuration/readiness without a scan target."""

    def check(self) -> ReadinessProbeResult:
        """Return a sanitized static provider readiness outcome."""
        ...
