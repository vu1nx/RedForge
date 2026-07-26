"""Deterministic, offline composition readiness preflight tests."""

from dataclasses import FrozenInstanceError
from typing import Any, cast

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters import create_default_tool_registry
from redforge.application import (
    PreflightResult,
    PreparedScan,
    ProviderRole,
    ReadinessProbeError,
    ReadinessProbeResult,
    ReadinessReason,
    ReadinessRegistry,
    ReadinessStatus,
    ReadinessSubjectKind,
    ScanConfig,
    ScanPreflight,
    prepare_scan,
)
from redforge.planning import (
    VULNERABILITY_PROVIDER_ROLE,
    CapabilityDefinition,
    CapabilityDependencies,
    CapabilityFactoryRegistry,
    CapabilityId,
    CapabilityRegistry,
    create_default_factory_registry,
    create_default_registry,
)
from redforge.sdk import Capability, Context, PipelineStateKey, Result
from redforge.sdk.readiness import ReadinessRequirement
from redforge.sdk.tool import ToolDefinition, ToolId
from redforge.sdk.tool_registry import ToolRegistry


class NeverBuiltCapability(Capability):
    def __init__(self, capability_id: CapabilityId) -> None:
        self._capability_id = capability_id

    @property
    def name(self) -> str:
        return self._capability_id.value

    def execute(self, context: Context) -> Result[Any]:  # noqa: ARG002
        raise AssertionError("preflight must not execute capabilities")


class FakeToolProbe:
    def __init__(
        self,
        outcomes: dict[ToolId, ReadinessProbeResult] | None = None,
        *,
        raising: tuple[ToolId, ...] = (),
    ) -> None:
        self.outcomes = outcomes or {}
        self.raising = raising
        self.calls: list[ToolId] = []

    def check(self, definition: ToolDefinition) -> ReadinessProbeResult:
        self.calls.append(definition.tool_id)
        if definition.tool_id in self.raising:
            raise ReadinessProbeError("sanitized readiness boundary")
        return self.outcomes.get(
            definition.tool_id,
            ReadinessProbeResult(ReadinessStatus.READY),
        )


class FakeProviderProbe:
    def __init__(
        self,
        outcome: ReadinessProbeResult | None = None,
        *,
        raises: bool = False,
    ) -> None:
        self.outcome = outcome or ReadinessProbeResult(
            ReadinessStatus.READY
        )
        self.raises = raises
        self.calls = 0

    def check(self) -> ReadinessProbeResult:
        self.calls += 1
        if self.raises:
            raise ReadinessProbeError("secret raw provider detail")
        return self.outcome


def _default_preflight(
    *,
    config: ScanConfig,
    factories: CapabilityFactoryRegistry,
    tools: ToolRegistry | None = None,
    tool_probe: FakeToolProbe | None = None,
    provider_probe: FakeProviderProbe | None = None,
) -> PreflightResult:
    provider_probes = (
        (
            (VULNERABILITY_PROVIDER_ROLE, provider_probe),
        )
        if provider_probe is not None
        else ()
    )
    return ScanPreflight(
        ReadinessRegistry(
            tool_registry=tools,
            tool_probe=tool_probe,
            provider_probes=provider_probes,
        )
    ).run(
        prepared_scan=prepare_scan(
            config=config,
            registry=create_default_registry(),
        ),
        factory_registry=factories,
    )


def _tool_backed_factories(
    *,
    vulnerability_configured: bool,
) -> CapabilityFactoryRegistry:
    return create_default_factory_registry(
        dependencies=CapabilityDependencies(
            vulnerability_provider=(
                cast(Any, object())
                if vulnerability_configured
                else None
            )
        )
    )


def test_full_preflight_checks_four_tools_and_vulnerability_without_building() -> None:
    tool_probe = FakeToolProbe()
    provider_probe = FakeProviderProbe()
    factories = _tool_backed_factories(vulnerability_configured=True)

    result = _default_preflight(
        config=ScanConfig.for_full_assessment("example.com"),
        factories=factories,
        tools=create_default_tool_registry(),
        tool_probe=tool_probe,
        provider_probe=provider_probe,
    )

    assert result.ready
    assert all(
        check.status is ReadinessStatus.READY for check in result.checks
    )
    assert tuple(sorted(tool_probe.calls)) == (
        ToolId("httpx"),
        ToolId("katana"),
        ToolId("subfinder"),
        ToolId("whatweb"),
    )
    assert provider_probe.calls == 1
    assert len(result.checks) == 18
    definition = factories.definition_for(CapabilityId("http_probe"))
    assert definition is not None
    assert not hasattr(definition, "__dict__")
    with pytest.raises(FrozenInstanceError):
        definition.requirements = ()  # type: ignore[misc]


def test_recon_preflight_ignores_unplanned_vulnerability_provider() -> None:
    tool_probe = FakeToolProbe()
    unused_provider = FakeProviderProbe(
        ReadinessProbeResult(
            ReadinessStatus.ERROR,
            ReadinessReason.PROBE_FAILED,
        )
    )

    result = _default_preflight(
        config=ScanConfig.for_reconnaissance("example.com"),
        factories=_tool_backed_factories(vulnerability_configured=False),
        tools=create_default_tool_registry(),
        tool_probe=tool_probe,
        provider_probe=unused_provider,
    )

    assert result.ready
    assert len(result.checks) == 13
    assert unused_provider.calls == 0


def _single_prepared() -> tuple[
    PreparedScan,
    CapabilityRegistry,
    CapabilityId,
]:
    identity = CapabilityId("technology_source")
    registry = CapabilityRegistry(
        (
            CapabilityDefinition(
                capability_id=identity,
                display_name="Technology Source",
                description="Test readiness source.",
                version="1.0",
                provides=(PipelineStateKey.TECHNOLOGIES,),
            ),
        )
    )
    prepared = prepare_scan(
        config=ScanConfig.for_reconnaissance("example.com"),
        registry=registry,
    )
    return prepared, registry, identity


def test_missing_factory_is_unavailable_without_factory_execution() -> None:
    prepared, _, identity = _single_prepared()

    result = ScanPreflight().run(
        prepared_scan=cast(Any, prepared),
        factory_registry=CapabilityFactoryRegistry(),
    )

    assert not result.ready
    assert result.checks[0].subject.capability_id == identity
    assert result.checks[0].status is ReadinessStatus.UNAVAILABLE
    assert result.checks[0].reason is ReadinessReason.FACTORY_MISSING


def test_declared_factory_identity_mismatch_is_incompatible_without_call() -> None:
    prepared, _, identity = _single_prepared()
    calls = 0

    def factory() -> NeverBuiltCapability:
        nonlocal calls
        calls += 1
        return NeverBuiltCapability(identity)

    factories = CapabilityFactoryRegistry()
    factories.register(
        identity,
        factory,
        declared_capability_id=CapabilityId("wrong_identity"),
    )

    result = ScanPreflight().run(
        prepared_scan=cast(Any, prepared),
        factory_registry=factories,
    )

    assert not result.ready
    assert result.checks[0].subject.kind is (
        ReadinessSubjectKind.CAPABILITY_BINDING
    )
    assert result.checks[0].status is ReadinessStatus.INCOMPATIBLE
    assert calls == 0


def test_missing_tool_definition_skips_executable_probe() -> None:
    probe = FakeToolProbe()

    result = _default_preflight(
        config=ScanConfig.for_reconnaissance("example.com"),
        factories=_tool_backed_factories(vulnerability_configured=False),
        tools=ToolRegistry(),
        tool_probe=probe,
    )

    missing = tuple(
        check
        for check in result.checks
        if check.subject.kind is ReadinessSubjectKind.TOOL_DEFINITION
    )
    assert not result.ready
    assert len(missing) == 4
    assert all(
        check.reason is ReadinessReason.TOOL_DEFINITION_MISSING
        for check in missing
    )
    assert probe.calls == []


def test_missing_executable_and_probe_error_are_sanitized_and_aggregated() -> None:
    probe = FakeToolProbe(
        outcomes={
            ToolId("subfinder"): ReadinessProbeResult(
                ReadinessStatus.UNAVAILABLE,
                ReadinessReason.EXECUTABLE_UNAVAILABLE,
            ),
            ToolId("httpx"): ReadinessProbeResult(
                ReadinessStatus.UNAVAILABLE,
                ReadinessReason.EXECUTABLE_UNAVAILABLE,
            ),
        },
        raising=(ToolId("katana"),),
    )

    result = _default_preflight(
        config=ScanConfig.for_full_assessment("example.com"),
        factories=_tool_backed_factories(vulnerability_configured=False),
        tools=create_default_tool_registry(),
        tool_probe=probe,
    )

    failures = tuple(
        check
        for check in result.checks
        if check.status is not ReadinessStatus.READY
    )
    assert not result.ready
    assert {check.status for check in failures} == {
        ReadinessStatus.UNAVAILABLE,
        ReadinessStatus.ERROR,
        ReadinessStatus.MISCONFIGURED,
    }
    assert len(failures) == 4
    assert "secret" not in repr(result)


def test_multiple_independent_failures_include_binding_and_provider_once() -> None:
    original = _tool_backed_factories(vulnerability_configured=False)
    factories = CapabilityFactoryRegistry()
    for capability_id in original.ids:
        definition = original.definition_for(capability_id)
        assert definition is not None
        factories.register(
            capability_id,
            definition.factory,
            declared_capability_id=(
                CapabilityId("wrong_risk_binding")
                if capability_id == CapabilityId("risk_intelligence")
                else capability_id
            ),
            requirements=definition.requirements,
        )
    probe = FakeToolProbe(
        outcomes={
            ToolId("subfinder"): ReadinessProbeResult(
                ReadinessStatus.UNAVAILABLE,
                ReadinessReason.EXECUTABLE_UNAVAILABLE,
            ),
            ToolId("httpx"): ReadinessProbeResult(
                ReadinessStatus.UNAVAILABLE,
                ReadinessReason.EXECUTABLE_UNAVAILABLE,
            ),
        }
    )

    result = _default_preflight(
        config=ScanConfig.for_full_assessment("example.com"),
        factories=factories,
        tools=create_default_tool_registry(),
        tool_probe=probe,
    )

    failures = tuple(
        check
        for check in result.checks
        if check.status is not ReadinessStatus.READY
    )
    assert tuple(check.status for check in failures) == (
        ReadinessStatus.UNAVAILABLE,
        ReadinessStatus.UNAVAILABLE,
        ReadinessStatus.MISCONFIGURED,
        ReadinessStatus.INCOMPATIBLE,
    )
    assert len(
        {
            (
                check.subject.kind,
                check.subject.capability_id,
                check.subject.tool_id,
                check.subject.provider_role,
            )
            for check in failures
        }
    ) == len(failures)


@pytest.mark.parametrize(
    ("status", "reason"),
    (
        (
            ReadinessStatus.MISCONFIGURED,
            ReadinessReason.PROVIDER_MISCONFIGURED,
        ),
        (ReadinessStatus.INCOMPATIBLE, ReadinessReason.BINDING_INCOMPATIBLE),
    ),
)
def test_provider_probe_non_ready_outcomes_are_preserved(
    status: ReadinessStatus,
    reason: ReadinessReason,
) -> None:
    probe = FakeProviderProbe(ReadinessProbeResult(status, reason))

    result = _default_preflight(
        config=ScanConfig.for_full_assessment("example.com"),
        factories=_tool_backed_factories(vulnerability_configured=True),
        tools=create_default_tool_registry(),
        tool_probe=FakeToolProbe(),
        provider_probe=probe,
    )

    assert not result.ready
    assert any(
        check.status is status and check.reason is reason
        for check in result.checks
    )


def test_provider_probe_expected_error_is_sanitized() -> None:
    result = _default_preflight(
        config=ScanConfig.for_full_assessment("example.com"),
        factories=_tool_backed_factories(vulnerability_configured=True),
        tools=create_default_tool_registry(),
        tool_probe=FakeToolProbe(),
        provider_probe=FakeProviderProbe(raises=True),
    )

    failure = next(
        check
        for check in result.checks
        if check.status is ReadinessStatus.ERROR
    )
    assert failure.status is ReadinessStatus.ERROR
    assert failure.reason is ReadinessReason.PROBE_FAILED
    assert "secret" not in repr(result)


def test_requirements_are_deduplicated_once_per_preflight() -> None:
    source_id = CapabilityId("endpoint_source")
    technology_id = CapabilityId("technology_source")
    registry = CapabilityRegistry(
        (
            CapabilityDefinition(
                capability_id=source_id,
                display_name="Endpoint Source",
                description="Test readiness source.",
                version="1.0",
                provides=(PipelineStateKey.ENDPOINTS,),
            ),
            CapabilityDefinition(
                capability_id=technology_id,
                display_name="Technology Source",
                description="Test readiness consumer.",
                version="1.0",
                requires=(PipelineStateKey.ENDPOINTS,),
                provides=(PipelineStateKey.TECHNOLOGIES,),
            ),
        )
    )
    prepared = prepare_scan(
        config=ScanConfig.for_reconnaissance("example.com"),
        registry=registry,
    )
    role = ProviderRole("shared_provider")
    provider_probe = FakeProviderProbe()
    calls = 0

    def factory(
        identity: CapabilityId,
    ) -> NeverBuiltCapability:
        nonlocal calls
        calls += 1
        return NeverBuiltCapability(identity)

    factories = CapabilityFactoryRegistry()
    requirement = ReadinessRequirement.provider(
        role,
        configuration_present=True,
    )
    for identity in (source_id, technology_id):
        factories.register(
            identity,
            lambda identity=identity: factory(identity),
            requirements=(requirement,),
        )
    result = ScanPreflight(
        ReadinessRegistry(
            provider_probes=((role, provider_probe),),
        )
    ).run(
        prepared_scan=prepared,
        factory_registry=factories,
    )

    assert result.ready
    assert provider_probe.calls == 1
    assert calls == 0
    assert len(result.checks) == 3
    assert not hasattr(result, "__dict__")
    with pytest.raises(FrozenInstanceError):
        result.ready = False  # type: ignore[misc]
