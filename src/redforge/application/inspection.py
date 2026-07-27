"""Execution-free application inspection derived from planning metadata."""

from dataclasses import dataclass, field
from typing import cast

from redforge.application.preflight import (
    PreflightResult,
    ReadinessRegistry,
    ScanPreflight,
)
from redforge.application.scan_config import ScanConfig, prepare_scan
from redforge.planning.factories import CapabilityFactoryRegistry
from redforge.planning.models import ExecutionPlan
from redforge.planning.registry import CapabilityRegistry
from redforge.sdk.capability_id import CapabilityId
from redforge.sdk.readiness import ProviderRole
from redforge.sdk.tool import ToolId


@dataclass(frozen=True, slots=True)
class ToolchainManifest:
    """Immutable plan-derived external requirement summary."""

    capability_ids: tuple[CapabilityId, ...]
    tool_ids: tuple[ToolId, ...] = ()
    provider_ids: tuple[ProviderRole, ...] = ()

    def __post_init__(self) -> None:
        _validate_unique_tuple(
            self.capability_ids,
            CapabilityId,
            "manifest capability IDs",
        )
        _validate_unique_tuple(
            self.tool_ids,
            ToolId,
            "manifest tool IDs",
        )
        _validate_unique_tuple(
            self.provider_ids,
            ProviderRole,
            "manifest provider IDs",
        )


@dataclass(frozen=True, slots=True, repr=False)
class ScanInspection:
    """Validated plan, requirements, and readiness without a runtime."""

    config: ScanConfig = field(repr=False)
    plan: ExecutionPlan
    manifest: ToolchainManifest
    preflight: PreflightResult

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.config), ScanConfig):
            raise TypeError("scan inspection config is invalid")
        if not isinstance(cast(object, self.plan), ExecutionPlan):
            raise TypeError("scan inspection plan is invalid")
        if not isinstance(cast(object, self.manifest), ToolchainManifest):
            raise TypeError("scan inspection manifest is invalid")
        if not isinstance(cast(object, self.preflight), PreflightResult):
            raise TypeError("scan inspection preflight is invalid")
        if self.manifest.capability_ids != self.plan.required_capability_ids:
            raise ValueError("scan inspection manifest does not match plan")


class ScanInspector:
    """Prepare and preflight a scan without construction or execution."""

    __slots__ = ("_capabilities", "_factories", "_preflight")

    def __init__(
        self,
        *,
        capability_registry: CapabilityRegistry,
        factory_registry: CapabilityFactoryRegistry,
        readiness_registry: ReadinessRegistry | None = None,
    ) -> None:
        if not isinstance(
            cast(object, capability_registry), CapabilityRegistry
        ):
            raise TypeError("ScanInspector requires a CapabilityRegistry")
        if not isinstance(
            cast(object, factory_registry), CapabilityFactoryRegistry
        ):
            raise TypeError(
                "ScanInspector requires a CapabilityFactoryRegistry"
            )
        self._capabilities = capability_registry
        self._factories = factory_registry
        self._preflight = ScanPreflight(readiness_registry)

    def inspect(self, config: ScanConfig) -> ScanInspection:
        """Return a deterministic inspection without creating a Context."""
        prepared = prepare_scan(
            config=config,
            registry=self._capabilities,
        )
        manifest = _manifest_for_plan(
            prepared.plan,
            self._factories,
        )
        preflight = self._preflight.run(
            prepared_scan=prepared,
            factory_registry=self._factories,
        )
        return ScanInspection(
            config=config,
            plan=prepared.plan,
            manifest=manifest,
            preflight=preflight,
        )


def _manifest_for_plan(
    plan: ExecutionPlan,
    factories: CapabilityFactoryRegistry,
) -> ToolchainManifest:
    tool_ids: list[ToolId] = []
    provider_ids: list[ProviderRole] = []
    seen_tools: set[ToolId] = set()
    seen_providers: set[ProviderRole] = set()
    for step in plan.steps:
        definition = factories.definition_for(step.capability_id)
        if definition is None:
            continue
        for requirement in definition.requirements:
            tool_id = requirement.tool_id
            if tool_id is not None and tool_id not in seen_tools:
                seen_tools.add(tool_id)
                tool_ids.append(tool_id)
            provider_id = requirement.provider_role
            if (
                provider_id is not None
                and provider_id not in seen_providers
            ):
                seen_providers.add(provider_id)
                provider_ids.append(provider_id)
    return ToolchainManifest(
        capability_ids=plan.required_capability_ids,
        tool_ids=tuple(tool_ids),
        provider_ids=tuple(provider_ids),
    )


def _validate_unique_tuple(
    value: object,
    item_type: type[object],
    label: str,
) -> None:
    if not isinstance(value, tuple) or not all(
        isinstance(item, item_type)
        for item in cast(tuple[object, ...], value)
    ):
        raise TypeError(f"{label} must be an immutable typed tuple")
    items = cast(tuple[object, ...], value)
    if len(items) != len(set(items)):
        raise ValueError(f"{label} contain duplicates")


__all__ = [
    "ScanInspection",
    "ScanInspector",
    "ToolchainManifest",
]
