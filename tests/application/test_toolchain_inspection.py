"""Execution-free toolchain manifest and readiness tests."""

from dataclasses import FrozenInstanceError

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters import create_default_tool_registry
from redforge.application import (
    ReadinessRegistry,
    ReadinessStatus,
    ScanConfig,
    ScanInspector,
    ToolchainManifest,
)
from redforge.planning import (
    CapabilityDependencies,
    create_default_factory_registry,
    create_default_registry,
)
from redforge.sdk import (
    CapabilityId,
    ReadinessProbeResult,
    ReadinessReason,
    ToolDefinition,
    ToolId,
)

_RECON_CAPABILITIES = (
    "subdomain_discovery",
    "host_resolution",
    "http_probe",
    "web_crawl",
    "technology_detection",
)
_RECON_TOOLS = ("subfinder", "httpx", "katana", "whatweb")


class StaticToolProbe:
    """Return deterministic availability without resolving or executing."""

    def __init__(self, unavailable: tuple[ToolId, ...] = ()) -> None:
        self.unavailable = unavailable
        self.calls: list[ToolId] = []

    def check(self, definition: ToolDefinition) -> ReadinessProbeResult:
        self.calls.append(definition.tool_id)
        if definition.tool_id in self.unavailable:
            return ReadinessProbeResult(
                ReadinessStatus.UNAVAILABLE,
                ReadinessReason.EXECUTABLE_UNAVAILABLE,
            )
        return ReadinessProbeResult(ReadinessStatus.READY)


def _inspector(probe: StaticToolProbe) -> ScanInspector:
    return ScanInspector(
        capability_registry=create_default_registry(),
        factory_registry=create_default_factory_registry(
            dependencies=CapabilityDependencies()
        ),
        readiness_registry=ReadinessRegistry(
            tool_registry=create_default_tool_registry(),
            tool_probe=probe,
        ),
    )


def test_reconnaissance_manifest_is_derived_in_plan_order() -> None:
    probe = StaticToolProbe()

    inspection = _inspector(probe).inspect(
        ScanConfig.for_reconnaissance("authorized.example")
    )

    assert tuple(
        item.value for item in inspection.manifest.capability_ids
    ) == _RECON_CAPABILITIES
    assert tuple(item.value for item in inspection.manifest.tool_ids) == (
        _RECON_TOOLS
    )
    assert inspection.manifest.provider_ids == ()
    assert tuple(item.value for item in probe.calls) == _RECON_TOOLS
    assert inspection.preflight.ready
    assert inspection.plan.required_capability_ids == (
        inspection.manifest.capability_ids
    )


def test_default_reconnaissance_tool_definitions_are_stable_and_path_free() -> None:
    definitions = create_default_tool_registry().all()

    assert tuple(
        (item.tool_id.value, item.executable_candidates)
        for item in definitions
    ) == (
        ("httpx", ("httpx-toolkit", "httpx")),
        ("katana", ("katana",)),
        ("nuclei", ("nuclei",)),
        ("subfinder", ("subfinder",)),
        ("whatweb", ("whatweb",)),
    )
    assert all(
        "/" not in candidate and "\\" not in candidate
        for item in definitions
        for candidate in item.executable_candidates
    )
    assert len({item.tool_id for item in definitions}) == len(definitions)


def test_missing_middle_tool_is_reported_without_execution() -> None:
    probe = StaticToolProbe((ToolId("katana"),))

    inspection = _inspector(probe).inspect(
        ScanConfig.for_reconnaissance("authorized.example")
    )

    failures = tuple(
        check
        for check in inspection.preflight.checks
        if check.status is not ReadinessStatus.READY
    )
    assert not inspection.preflight.ready
    assert len(failures) == 1
    assert failures[0].subject.tool_id == ToolId("katana")
    assert failures[0].status is ReadinessStatus.UNAVAILABLE
    assert tuple(item.value for item in probe.calls) == _RECON_TOOLS


def test_full_manifest_includes_absent_vulnerability_provider_requirement() -> None:
    inspection = _inspector(StaticToolProbe()).inspect(
        ScanConfig.for_full_assessment("authorized.example")
    )

    assert tuple(item.value for item in inspection.manifest.tool_ids) == (
        _RECON_TOOLS
    )
    assert tuple(
        item.value for item in inspection.manifest.provider_ids
    ) == ("vulnerability_provider",)
    assert not inspection.preflight.ready
    failure = next(
        check
        for check in inspection.preflight.checks
        if check.status is not ReadinessStatus.READY
    )
    assert failure.subject.provider_role is not None
    assert failure.subject.provider_role.value == "vulnerability_provider"


def test_manifest_is_immutable_and_rejects_duplicate_identities() -> None:
    manifest = ToolchainManifest(
        capability_ids=(CapabilityId("example_capability"),),
        tool_ids=(ToolId("example_tool"),),
    )

    with pytest.raises(FrozenInstanceError):
        manifest.tool_ids = ()  # type: ignore[misc]
    with pytest.raises(ValueError, match="duplicates"):
        ToolchainManifest(
            capability_ids=(
                CapabilityId("example_capability"),
                CapabilityId("example_capability"),
            )
        )


def test_inspection_repr_excludes_target_and_implementation_objects() -> None:
    inspection = _inspector(StaticToolProbe()).inspect(
        ScanConfig.for_reconnaissance("authorized.example")
    )

    rendered = repr(inspection)
    assert "authorized.example" not in rendered
    assert "factory" not in rendered.lower()
    assert "executable" not in rendered.lower()
