"""Provider-neutral application scan readiness coordination."""

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import cast

from redforge.application.scan_config import PreparedScan
from redforge.planning.factories import CapabilityFactoryRegistry
from redforge.sdk.capability_id import CapabilityId
from redforge.sdk.readiness import (
    ProviderReadinessProbe,
    ProviderRole,
    ReadinessCheckResult,
    ReadinessProbeError,
    ReadinessReason,
    ReadinessRequirement,
    ReadinessRequirementKind,
    ReadinessStatus,
    ReadinessSubject,
    ReadinessSubjectKind,
    ToolReadinessProbe,
)
from redforge.sdk.tool_registry import ToolRegistry


@dataclass(frozen=True, slots=True, repr=False)
class PreflightResult:
    """Immutable aggregate of deterministic planned-composition checks."""

    ready: bool
    checks: tuple[ReadinessCheckResult, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.ready), bool):
            raise TypeError("preflight ready flag must be boolean")
        checks_value = cast(object, self.checks)
        if not isinstance(checks_value, tuple) or not all(
            isinstance(item, ReadinessCheckResult)
            for item in cast(tuple[object, ...], checks_value)
        ):
            raise TypeError("preflight checks must be an immutable tuple")
        expected = all(
            item.status is ReadinessStatus.READY for item in self.checks
        )
        if self.ready is not expected:
            raise ValueError("preflight ready flag does not match checks")

    def __repr__(self) -> str:
        """Return only aggregate counts, never component implementation data."""
        failures = sum(
            item.status is not ReadinessStatus.READY for item in self.checks
        )
        return (
            "PreflightResult("
            f"ready={self.ready!r}, "
            f"check_count={len(self.checks)}, "
            f"failure_count={failures})"
        )


class ScanPreflightError(RuntimeError):
    """Typed sanitized failure raised before construction or execution."""

    def __init__(self, result: PreflightResult) -> None:
        if not isinstance(cast(object, result), PreflightResult):
            raise TypeError("scan preflight error requires PreflightResult")
        self.result = result
        failure_count = sum(
            item.status is not ReadinessStatus.READY
            for item in result.checks
        )
        super().__init__(
            f"Scan preflight failed with {failure_count} readiness issue(s)"
        )


class ReadinessRegistry:
    """Per-composition probe lookup without cross-scan caching."""

    def __init__(
        self,
        *,
        tool_registry: ToolRegistry | None = None,
        tool_probe: ToolReadinessProbe | None = None,
        provider_probes: Iterable[
            tuple[ProviderRole, ProviderReadinessProbe]
        ] = (),
    ) -> None:
        if tool_registry is not None and not isinstance(
            cast(object, tool_registry), ToolRegistry
        ):
            raise TypeError("readiness requires a ToolRegistry")
        if tool_probe is not None and not callable(
            getattr(cast(object, tool_probe), "check", None)
        ):
            raise TypeError("tool readiness probe is invalid")
        self._tools = tool_registry or ToolRegistry()
        self._tool_probe = tool_probe
        providers: dict[ProviderRole, ProviderReadinessProbe] = {}
        for item in provider_probes:
            if (
                not isinstance(cast(object, item), tuple)
                or len(item) != 2
            ):
                raise TypeError("provider probes must be role/probe pairs")
            role, probe = item
            if not isinstance(cast(object, role), ProviderRole) or not callable(
                getattr(cast(object, probe), "check", None)
            ):
                raise TypeError("provider readiness probe is invalid")
            if role in providers:
                raise ValueError("duplicate provider readiness role")
            providers[role] = probe
        self._provider_probes = providers

    @property
    def tool_registry(self) -> ToolRegistry:
        """Return the definition registry used by this composition."""
        return self._tools

    @property
    def tool_probe(self) -> ToolReadinessProbe | None:
        """Return the optional executable readiness probe."""
        return self._tool_probe

    def provider_probe(
        self,
        role: ProviderRole,
    ) -> ProviderReadinessProbe | None:
        """Return a provider probe without invoking it."""
        return self._provider_probes.get(role)


class ScanPreflight:
    """Check only readiness requirements derived from one prepared plan."""

    __slots__ = ("_readiness",)

    def __init__(
        self,
        readiness_registry: ReadinessRegistry | None = None,
    ) -> None:
        if readiness_registry is not None and not isinstance(
            cast(object, readiness_registry), ReadinessRegistry
        ):
            raise TypeError("ScanPreflight requires a ReadinessRegistry")
        self._readiness = readiness_registry or ReadinessRegistry()

    def run(
        self,
        *,
        prepared_scan: PreparedScan,
        factory_registry: CapabilityFactoryRegistry,
    ) -> PreflightResult:
        """Aggregate all independent readiness issues without construction."""
        if not isinstance(cast(object, prepared_scan), PreparedScan):
            raise TypeError("preflight requires a PreparedScan")
        if not isinstance(
            cast(object, factory_registry), CapabilityFactoryRegistry
        ):
            raise TypeError("preflight requires a factory registry")

        checks: list[ReadinessCheckResult] = []
        seen_requirements: set[ReadinessRequirement] = set()
        for step in prepared_scan.plan.steps:
            definition = factory_registry.definition_for(
                step.capability_id
            )
            if definition is None:
                checks.append(
                    _check(
                        ReadinessSubjectKind.CAPABILITY_FACTORY,
                        step.capability_id,
                        ReadinessStatus.UNAVAILABLE,
                        ReadinessReason.FACTORY_MISSING,
                    )
                )
                continue
            if definition.capability_id != step.capability_id:
                checks.append(
                    _check(
                        ReadinessSubjectKind.CAPABILITY_BINDING,
                        step.capability_id,
                        ReadinessStatus.INCOMPATIBLE,
                        ReadinessReason.FACTORY_BINDING_MISMATCH,
                    )
                )
                continue
            checks.append(
                _check(
                    ReadinessSubjectKind.CAPABILITY_FACTORY,
                    step.capability_id,
                    ReadinessStatus.READY,
                )
            )
            for requirement in definition.requirements:
                if requirement in seen_requirements:
                    continue
                seen_requirements.add(requirement)
                checks.extend(self._check_requirement(requirement))

        immutable_checks = tuple(checks)
        return PreflightResult(
            ready=all(
                item.status is ReadinessStatus.READY
                for item in immutable_checks
            ),
            checks=immutable_checks,
        )

    def _check_requirement(
        self,
        requirement: ReadinessRequirement,
    ) -> tuple[ReadinessCheckResult, ...]:
        if requirement.kind is ReadinessRequirementKind.TOOL:
            return self._check_tool(requirement)
        return (self._check_provider(requirement),)

    def _check_tool(
        self,
        requirement: ReadinessRequirement,
    ) -> tuple[ReadinessCheckResult, ...]:
        tool_id = requirement.tool_id
        if tool_id is None:
            raise RuntimeError("invalid tool readiness requirement")
        definition = self._readiness.tool_registry.get(tool_id)
        definition_subject = ReadinessSubject(
            kind=ReadinessSubjectKind.TOOL_DEFINITION,
            tool_id=tool_id,
        )
        if definition is None:
            return (
                ReadinessCheckResult(
                    subject=definition_subject,
                    status=ReadinessStatus.UNAVAILABLE,
                    reason=ReadinessReason.TOOL_DEFINITION_MISSING,
                ),
            )
        checks = [
            ReadinessCheckResult(
                subject=definition_subject,
                status=ReadinessStatus.READY,
            )
        ]
        executable_subject = ReadinessSubject(
            kind=ReadinessSubjectKind.TOOL_EXECUTABLE,
            tool_id=tool_id,
        )
        probe = self._readiness.tool_probe
        if probe is None:
            checks.append(
                ReadinessCheckResult(
                    subject=executable_subject,
                    status=ReadinessStatus.MISCONFIGURED,
                    reason=ReadinessReason.TOOL_PROBE_MISSING,
                )
            )
        else:
            try:
                outcome = probe.check(definition)
            except ReadinessProbeError:
                checks.append(
                    ReadinessCheckResult(
                        subject=executable_subject,
                        status=ReadinessStatus.ERROR,
                        reason=ReadinessReason.PROBE_FAILED,
                    )
                )
            else:
                checks.append(
                    ReadinessCheckResult(
                        subject=executable_subject,
                        status=outcome.status,
                        reason=outcome.reason,
                    )
                )
        return tuple(checks)

    def _check_provider(
        self,
        requirement: ReadinessRequirement,
    ) -> ReadinessCheckResult:
        role = requirement.provider_role
        if role is None:
            raise RuntimeError("invalid provider readiness requirement")
        if not requirement.configuration_present:
            return ReadinessCheckResult(
                subject=ReadinessSubject(
                    kind=ReadinessSubjectKind.PROVIDER_CONFIGURATION,
                    provider_role=role,
                ),
                status=ReadinessStatus.MISCONFIGURED,
                reason=ReadinessReason.PROVIDER_ABSENT,
            )
        probe = self._readiness.provider_probe(role)
        if probe is None:
            return ReadinessCheckResult(
                subject=ReadinessSubject(
                    kind=ReadinessSubjectKind.PROVIDER_CONFIGURATION,
                    provider_role=role,
                ),
                status=ReadinessStatus.READY,
            )
        subject = ReadinessSubject(
            kind=ReadinessSubjectKind.PROVIDER,
            provider_role=role,
        )
        try:
            outcome = probe.check()
        except ReadinessProbeError:
            return ReadinessCheckResult(
                subject=subject,
                status=ReadinessStatus.ERROR,
                reason=ReadinessReason.PROBE_FAILED,
            )
        return ReadinessCheckResult(
            subject=subject,
            status=outcome.status,
            reason=outcome.reason,
        )


def _check(
    kind: ReadinessSubjectKind,
    capability_id: CapabilityId,
    status: ReadinessStatus,
    reason: ReadinessReason | None = None,
) -> ReadinessCheckResult:
    """Build one capability-scoped check without implementation details."""
    if not isinstance(cast(object, capability_id), CapabilityId):
        raise TypeError("readiness capability identity is invalid")
    return ReadinessCheckResult(
        subject=ReadinessSubject(
            kind=kind,
            capability_id=capability_id,
        ),
        status=status,
        reason=reason,
    )
