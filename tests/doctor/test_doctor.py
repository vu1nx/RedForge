"""Offline tests for provider-neutral environment diagnostics."""

from dataclasses import FrozenInstanceError

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters import create_default_tool_registry
from redforge.application import RedForgeDoctor
from redforge.composition import ApplicationComposition, CompositionProfile
from redforge.doctor import (
    DoctorCheck,
    DoctorCheckKind,
    DoctorResult,
    DoctorStatus,
    PlatformInformation,
    PlatformSupport,
    PythonRuntimeInformation,
    ToolVersionProbeResult,
    ToolVersionProbeStatus,
)
from redforge.planning import (
    CapabilityRegistry,
    create_default_factory_registry,
    create_default_registry,
)
from redforge.sdk import (
    HOST_RESOLUTION,
    HTTP_PROBE,
    SUBDOMAIN_DISCOVERY,
    TECHNOLOGY_DETECTION,
    WEB_CRAWL,
    ReadinessProbeResult,
    ReadinessReason,
    ReadinessStatus,
    ToolDefinition,
    ToolId,
)

_RECON_IDS = (
    SUBDOMAIN_DISCOVERY,
    HOST_RESOLUTION,
    HTTP_PROBE,
    WEB_CRAWL,
    TECHNOLOGY_DETECTION,
)


class _PlatformProbe:
    def __init__(
        self,
        support: PlatformSupport = PlatformSupport.PRIMARY,
        *,
        family: str = "linux",
        distribution: str | None = "kali",
    ) -> None:
        self._information = PlatformInformation(
            family=family,
            architecture="x86_64",
            distribution=distribution,
            support=support,
        )

    def inspect(self) -> PlatformInformation:
        return self._information


class _PythonProbe:
    def __init__(self, *, supported: bool = True) -> None:
        self._supported = supported

    def inspect(self) -> PythonRuntimeInformation:
        return PythonRuntimeInformation(
            implementation="cpython",
            major=3,
            minor=12 if self._supported else 11,
            supported=self._supported,
        )


class _AvailabilityProbe:
    def __init__(
        self,
        unavailable: ToolId | None = None,
        *,
        fail: bool = False,
    ) -> None:
        self._unavailable = unavailable
        self._fail = fail

    def check(self, definition: ToolDefinition) -> ReadinessProbeResult:
        if self._fail:
            raise OSError("sensitive local failure")
        if definition.tool_id == self._unavailable:
            return ReadinessProbeResult(
                status=ReadinessStatus.UNAVAILABLE,
                reason=ReadinessReason.EXECUTABLE_UNAVAILABLE,
            )
        return ReadinessProbeResult(status=ReadinessStatus.READY)


class _VersionProbe:
    def __init__(self, result: ToolVersionProbeResult) -> None:
        self._result = result
        self.calls: list[ToolId] = []

    def probe(self, definition: ToolDefinition) -> ToolVersionProbeResult:
        self.calls.append(definition.tool_id)
        return self._result


def _doctor(
    *,
    profile: CompositionProfile = CompositionProfile.RECONNAISSANCE,
    platform: _PlatformProbe | None = None,
    python: _PythonProbe | None = None,
    availability: _AvailabilityProbe | None = None,
    version: _VersionProbe | None = None,
    configuration_valid: bool = True,
) -> RedForgeDoctor:
    default_registry = create_default_registry()
    if profile is CompositionProfile.RECONNAISSANCE:
        registry = CapabilityRegistry(
            definition
            for definition in default_registry.all()
            if definition.capability_id in _RECON_IDS
        )
        enabled = _RECON_IDS
    else:
        registry = default_registry
        enabled = None
    return RedForgeDoctor(
        profile=profile,
        platform_probe=platform or _PlatformProbe(),
        python_probe=python or _PythonProbe(),
        capability_registry=registry,
        factory_registry=create_default_factory_registry(
            enabled_capabilities=enabled
        ),
        tool_registry=create_default_tool_registry(),
        availability_probe=availability or _AvailabilityProbe(),
        version_probe=version,
        configuration_valid=configuration_valid,
    )


def test_models_are_immutable_deterministic_and_safe() -> None:
    platform = PlatformInformation(
        "linux",
        "x86_64",
        "kali",
        PlatformSupport.PRIMARY,
    )
    python = PythonRuntimeInformation("cpython", 3, 12, True)
    checks = (
        DoctorCheck(
            DoctorCheckKind.PLATFORM,
            "linux",
            DoctorStatus.READY,
        ),
    )
    first = DoctorResult(
        CompositionProfile.RECONNAISSANCE,
        platform,
        python,
        (),
        checks,
        True,
    )
    second = DoctorResult(
        CompositionProfile.RECONNAISSANCE,
        platform,
        python,
        (),
        checks,
        True,
    )

    assert first == second
    assert "tools=" not in repr(first)
    with pytest.raises(FrozenInstanceError):
        first.ready = False  # type: ignore[misc]


@pytest.mark.parametrize(
    ("support", "ready", "status"),
    (
        (PlatformSupport.PRIMARY, True, DoctorStatus.READY),
        (PlatformSupport.BEST_EFFORT, True, DoctorStatus.WARNING),
        (PlatformSupport.DEVELOPMENT, True, DoctorStatus.WARNING),
        (PlatformSupport.LIBRARY_ONLY, True, DoctorStatus.WARNING),
        (PlatformSupport.UNSUPPORTED, False, DoctorStatus.INCOMPATIBLE),
    ),
)
def test_platform_policy(
    support: PlatformSupport,
    ready: bool,
    status: DoctorStatus,
) -> None:
    result = _doctor(platform=_PlatformProbe(support)).inspect()

    assert result.ready is ready
    assert result.checks[0].status is status


def test_unsupported_python_is_incompatible() -> None:
    result = _doctor(python=_PythonProbe(supported=False)).inspect()

    assert not result.ready
    assert result.checks[1].status is DoctorStatus.INCOMPATIBLE


def test_tool_inventory_is_registry_derived_and_deterministic() -> None:
    result = _doctor().inspect()

    assert tuple(tool.tool_id.value for tool in result.tools) == (
        "httpx",
        "katana",
        "subfinder",
        "whatweb",
    )
    assert result.ready


def test_missing_executable_and_probe_failure_are_not_ready() -> None:
    missing = _doctor(
        availability=_AvailabilityProbe(ToolId("katana"))
    ).inspect()
    failed = _doctor(
        availability=_AvailabilityProbe(fail=True)
    ).inspect()

    assert not missing.ready
    assert next(
        tool for tool in missing.tools if tool.tool_id == ToolId("katana")
    ).status is DoctorStatus.UNAVAILABLE
    assert not failed.ready
    assert all(tool.status is DoctorStatus.ERROR for tool in failed.tools)
    assert "sensitive" not in repr(failed)


def test_detected_version_is_sanitized_and_unverified() -> None:
    versions = _VersionProbe(
        ToolVersionProbeResult(
            ToolVersionProbeStatus.DETECTED,
            "1.2.3",
        )
    )

    result = _doctor(version=versions).inspect()

    assert result.ready
    assert all(tool.version == "1.2.3" for tool in result.tools)
    assert len(versions.calls) == 4
    assert all(
        tool.compatibility.value == "unverified"
        for tool in result.tools
    )


def test_malformed_version_warns_and_probe_error_fails() -> None:
    malformed = _doctor(
        version=_VersionProbe(
            ToolVersionProbeResult(ToolVersionProbeStatus.MALFORMED)
        )
    ).inspect()
    failed = _doctor(
        version=_VersionProbe(
            ToolVersionProbeResult(ToolVersionProbeStatus.ERROR)
        )
    ).inspect()

    assert malformed.ready
    assert all(tool.status is DoctorStatus.WARNING for tool in malformed.tools)
    assert not failed.ready
    assert all(tool.status is DoctorStatus.ERROR for tool in failed.tools)


def test_unavailable_version_probe_preserves_availability() -> None:
    result = _doctor(
        version=_VersionProbe(
            ToolVersionProbeResult(ToolVersionProbeStatus.UNAVAILABLE)
        )
    ).inspect()

    assert result.ready
    assert all(tool.version is None for tool in result.tools)
    assert all(tool.status is DoctorStatus.READY for tool in result.tools)


def test_full_profile_reports_expected_missing_provider() -> None:
    result = _doctor(
        profile=CompositionProfile.FULL_ASSESSMENT
    ).inspect()

    assert not result.ready
    assert any(
        check.kind is DoctorCheckKind.PROVIDER
        and check.status is DoctorStatus.MISCONFIGURED
        for check in result.checks
    )


def test_configuration_failure_is_misconfigured() -> None:
    result = _doctor(configuration_valid=False).inspect()

    assert not result.ready
    assert any(
        check.kind is DoctorCheckKind.CONFIGURATION
        and check.status is DoctorStatus.MISCONFIGURED
        for check in result.checks
    )


def test_composition_supplies_registry_derived_doctor_without_target() -> None:
    doctor = ApplicationComposition(
        CompositionProfile.RECONNAISSANCE,
        tool_readiness_probe=_AvailabilityProbe(),
    ).create_doctor()

    result = doctor.inspect()

    assert tuple(tool.tool_id.value for tool in result.tools) == (
        "httpx",
        "katana",
        "subfinder",
        "whatweb",
    )
