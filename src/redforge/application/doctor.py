"""Provider-neutral environment diagnostic coordination."""

from typing import cast

from redforge.composition.profile import CompositionProfile
from redforge.doctor import (
    DoctorCheck,
    DoctorCheckKind,
    DoctorResult,
    DoctorStatus,
    ExecutableAvailabilityProbe,
    PlatformInformationProbe,
    PlatformSupport,
    PythonRuntimeInformationProbe,
    ToolCompatibility,
    ToolDiagnostic,
    ToolVersionProbe,
    ToolVersionProbeStatus,
)
from redforge.planning.factories import CapabilityFactoryRegistry
from redforge.planning.registry import CapabilityRegistry
from redforge.sdk.readiness import (
    ReadinessRequirementKind,
    ReadinessStatus,
)
from redforge.sdk.tool_registry import ToolRegistry


class RedForgeDoctor:
    """Inspect static environment and composition readiness without a target."""

    __slots__ = (
        "_availability",
        "_capabilities",
        "_configuration_valid",
        "_factories",
        "_platform",
        "_profile",
        "_python",
        "_tools",
        "_versions",
    )

    def __init__(
        self,
        *,
        profile: CompositionProfile,
        platform_probe: PlatformInformationProbe,
        python_probe: PythonRuntimeInformationProbe,
        capability_registry: CapabilityRegistry,
        factory_registry: CapabilityFactoryRegistry,
        tool_registry: ToolRegistry,
        availability_probe: ExecutableAvailabilityProbe,
        configuration_valid: bool,
        version_probe: ToolVersionProbe | None = None,
    ) -> None:
        if not isinstance(cast(object, profile), CompositionProfile):
            raise TypeError("doctor profile is invalid")
        if not isinstance(cast(object, configuration_valid), bool):
            raise TypeError("doctor configuration status is invalid")
        self._profile = profile
        self._platform = platform_probe
        self._python = python_probe
        self._capabilities = capability_registry
        self._factories = factory_registry
        self._tools = tool_registry
        self._availability = availability_probe
        self._configuration_valid = configuration_valid
        self._versions = version_probe

    def inspect(self) -> DoctorResult:
        """Return deterministic static diagnostics without scan construction."""
        platform = self._platform.inspect()
        python = self._python.inspect()
        checks: list[DoctorCheck] = [
            DoctorCheck(
                DoctorCheckKind.PLATFORM,
                platform.family,
                _platform_status(platform.support),
            ),
            DoctorCheck(
                DoctorCheckKind.PYTHON,
                python.implementation,
                (
                    DoctorStatus.READY
                    if python.supported
                    else DoctorStatus.INCOMPATIBLE
                ),
            ),
            DoctorCheck(
                DoctorCheckKind.PACKAGE,
                "redforge",
                DoctorStatus.READY,
            ),
        ]

        registry_status = DoctorStatus.READY
        factory_status = DoctorStatus.READY
        try:
            if not self._capabilities.ids():
                registry_status = DoctorStatus.MISCONFIGURED
            self._factories.validate_against(self._capabilities)
            if self._factories.ids != self._capabilities.ids():
                factory_status = DoctorStatus.MISCONFIGURED
        except Exception:
            factory_status = DoctorStatus.ERROR
        checks.extend(
            (
                DoctorCheck(
                    DoctorCheckKind.CAPABILITY_REGISTRY,
                    "capabilities",
                    registry_status,
                ),
                DoctorCheck(
                    DoctorCheckKind.FACTORY_REGISTRY,
                    "factories",
                    factory_status,
                ),
                DoctorCheck(
                    DoctorCheckKind.TOOL_REGISTRY,
                    "tools",
                    DoctorStatus.READY,
                ),
            )
        )

        tools: list[ToolDiagnostic] = []
        for definition in self._tools.all():
            try:
                readiness = self._availability.check(definition)
                status = _readiness_status(readiness.status)
            except Exception:
                status = DoctorStatus.ERROR
            version: str | None = None
            compatibility = ToolCompatibility.UNVERIFIED
            if status is DoctorStatus.READY and self._versions is not None:
                try:
                    version_result = self._versions.probe(definition)
                except Exception:
                    version_result = None
                if version_result is None:
                    status = DoctorStatus.ERROR
                elif (
                    version_result.status
                    is ToolVersionProbeStatus.DETECTED
                ):
                    version = version_result.version
                elif (
                    version_result.status
                    is ToolVersionProbeStatus.ERROR
                ):
                    status = DoctorStatus.ERROR
                elif (
                    version_result.status
                    is ToolVersionProbeStatus.MALFORMED
                ):
                    status = DoctorStatus.WARNING
            tools.append(
                ToolDiagnostic(
                    tool_id=definition.tool_id,
                    status=status,
                    version=version,
                    compatibility=compatibility,
                )
            )
            checks.append(
                DoctorCheck(
                    DoctorCheckKind.TOOL_EXECUTABLE,
                    definition.tool_id.value,
                    status,
                )
            )

        metadata_status = DoctorStatus.READY
        provider_status = DoctorStatus.READY
        for capability_id in self._factories.ids:
            definition = self._factories.definition_for(capability_id)
            if definition is None:
                metadata_status = DoctorStatus.MISCONFIGURED
                continue
            for requirement in definition.requirements:
                if requirement.kind is ReadinessRequirementKind.TOOL:
                    if (
                        requirement.tool_id is None
                        or not self._tools.contains(requirement.tool_id)
                    ):
                        metadata_status = DoctorStatus.MISCONFIGURED
                elif not requirement.configuration_present:
                    provider_status = DoctorStatus.MISCONFIGURED

        checks.extend(
            (
                DoctorCheck(
                    DoctorCheckKind.CONFIGURATION,
                    "default",
                    (
                        DoctorStatus.READY
                        if self._configuration_valid
                        else DoctorStatus.MISCONFIGURED
                    ),
                ),
                DoctorCheck(
                    DoctorCheckKind.READINESS_METADATA,
                    "alignment",
                    metadata_status,
                ),
                DoctorCheck(
                    DoctorCheckKind.COMPOSITION,
                    self._profile.value,
                    (
                        DoctorStatus.READY
                        if registry_status is DoctorStatus.READY
                        and factory_status is DoctorStatus.READY
                        and metadata_status is DoctorStatus.READY
                        else DoctorStatus.MISCONFIGURED
                    ),
                ),
            )
        )
        if provider_status is not DoctorStatus.READY:
            checks.append(
                DoctorCheck(
                    DoctorCheckKind.PROVIDER,
                    "required_provider",
                    provider_status,
                )
            )

        immutable_checks = tuple(checks)
        return DoctorResult(
            profile=self._profile,
            platform=platform,
            python=python,
            tools=tuple(tools),
            checks=immutable_checks,
            ready=all(
                check.status
                in {DoctorStatus.READY, DoctorStatus.WARNING}
                for check in immutable_checks
            ),
        )


def _platform_status(support: PlatformSupport) -> DoctorStatus:
    return {
        PlatformSupport.PRIMARY: DoctorStatus.READY,
        PlatformSupport.BEST_EFFORT: DoctorStatus.WARNING,
        PlatformSupport.DEVELOPMENT: DoctorStatus.WARNING,
        PlatformSupport.LIBRARY_ONLY: DoctorStatus.WARNING,
        PlatformSupport.UNSUPPORTED: DoctorStatus.INCOMPATIBLE,
    }[support]


def _readiness_status(status: ReadinessStatus) -> DoctorStatus:
    return {
        ReadinessStatus.READY: DoctorStatus.READY,
        ReadinessStatus.UNAVAILABLE: DoctorStatus.UNAVAILABLE,
        ReadinessStatus.MISCONFIGURED: DoctorStatus.MISCONFIGURED,
        ReadinessStatus.INCOMPATIBLE: DoctorStatus.INCOMPATIBLE,
        ReadinessStatus.ERROR: DoctorStatus.ERROR,
    }[status]
