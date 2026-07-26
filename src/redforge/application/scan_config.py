"""Provider-neutral application scan configuration and plan preparation."""

from dataclasses import dataclass, field
from typing import cast

from redforge.application.errors import (
    DisabledCapabilityError,
    ScanConfigurationError,
    ScanPreparationError,
)
from redforge.domain.scan_scope import ScanScope, ScanTarget
from redforge.planning.errors import PlanningError
from redforge.planning.models import ExecutionPlan
from redforge.planning.planner import ExecutionPlanner
from redforge.planning.registry import CapabilityRegistry
from redforge.sdk.capability_id import CapabilityId
from redforge.sdk.context import Context
from redforge.sdk.state import PipelineStateKey

_APPLICATION_OUTPUTS = frozenset(
    (
        PipelineStateKey.ENDPOINTS,
        PipelineStateKey.TECHNOLOGIES,
        PipelineStateKey.ASSET_INTELLIGENCE,
        PipelineStateKey.VULNERABILITY_INTELLIGENCE,
        PipelineStateKey.KNOWLEDGE_GRAPH,
        PipelineStateKey.RISK_INTELLIGENCE,
    )
)


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Bounded provider-neutral limits for future orchestration enforcement."""

    max_subdomains: int = 1_000
    max_hosts: int = 1_000
    max_alive_hosts: int = 500
    max_http_endpoints: int = 2_000
    max_crawl_endpoints: int = 10_000
    max_technologies: int = 5_000
    overall_timeout_seconds: int = 1_800

    _BOUNDS = (
        ("max_subdomains", 100_000),
        ("max_hosts", 100_000),
        ("max_alive_hosts", 100_000),
        ("max_http_endpoints", 200_000),
        ("max_crawl_endpoints", 1_000_000),
        ("max_technologies", 200_000),
        ("overall_timeout_seconds", 86_400),
    )

    def __post_init__(self) -> None:
        for name, maximum in self._BOUNDS:
            value = cast(object, getattr(self, name))
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 1 <= value <= maximum
            ):
                raise ScanConfigurationError(f"scan limit '{name}' is invalid")


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Complete immutable application intent for one authorized DNS-root scan."""

    scope: ScanScope
    requested_outputs: tuple[PipelineStateKey, ...]
    limits: ScanLimits = field(default_factory=ScanLimits)
    disabled_capabilities: tuple[CapabilityId, ...] = ()
    allow_partial_results: bool = True

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.scope), ScanScope):
            raise ScanConfigurationError("scan scope is invalid")
        if not isinstance(cast(object, self.limits), ScanLimits):
            raise ScanConfigurationError("scan limits are invalid")
        outputs_value = cast(object, self.requested_outputs)
        if not isinstance(outputs_value, tuple) or not outputs_value:
            raise ScanConfigurationError(
                "at least one requested output is required"
            )
        if not all(
            isinstance(item, PipelineStateKey)
            for item in cast(tuple[object, ...], outputs_value)
        ):
            raise ScanConfigurationError("requested outputs are invalid")
        outputs = cast(tuple[PipelineStateKey, ...], outputs_value)
        if len(outputs) != len(set(outputs)):
            raise ScanConfigurationError("requested outputs contain duplicates")
        if any(output not in _APPLICATION_OUTPUTS for output in outputs):
            raise ScanConfigurationError("requested output is not application-facing")
        object.__setattr__(self, "requested_outputs", tuple(sorted(outputs)))

        disabled_value = cast(object, self.disabled_capabilities)
        if not isinstance(disabled_value, tuple) or not all(
            isinstance(item, CapabilityId)
            for item in cast(tuple[object, ...], disabled_value)
        ):
            raise ScanConfigurationError("disabled capabilities are invalid")
        disabled = cast(tuple[CapabilityId, ...], disabled_value)
        if len(disabled) != len(set(disabled)):
            raise ScanConfigurationError(
                "disabled capabilities contain duplicates"
            )
        object.__setattr__(self, "disabled_capabilities", tuple(sorted(disabled)))
        if not isinstance(cast(object, self.allow_partial_results), bool):
            raise ScanConfigurationError("partial-result policy is invalid")

    @classmethod
    def for_reconnaissance(
        cls,
        target: ScanTarget | str,
        *,
        limits: ScanLimits | None = None,
        disabled_capabilities: tuple[CapabilityId, ...] = (),
        allow_partial_results: bool = True,
    ) -> "ScanConfig":
        """Request provider-neutral technology evidence for one DNS root."""
        return cls(
            scope=ScanScope(_target(target)),
            requested_outputs=(PipelineStateKey.TECHNOLOGIES,),
            limits=limits or ScanLimits(),
            disabled_capabilities=disabled_capabilities,
            allow_partial_results=allow_partial_results,
        )

    @classmethod
    def for_full_assessment(
        cls,
        target: ScanTarget | str,
        *,
        limits: ScanLimits | None = None,
        disabled_capabilities: tuple[CapabilityId, ...] = (),
        allow_partial_results: bool = True,
    ) -> "ScanConfig":
        """Request the complete implemented risk-intelligence closure."""
        return cls(
            scope=ScanScope(_target(target)),
            requested_outputs=(PipelineStateKey.RISK_INTELLIGENCE,),
            limits=limits or ScanLimits(),
            disabled_capabilities=disabled_capabilities,
            allow_partial_results=allow_partial_results,
        )


@dataclass(frozen=True, slots=True)
class PreparedScan:
    """Immutable validated planner input, without runtime or provider objects."""

    config: ScanConfig
    plan: ExecutionPlan
    allowed_capabilities: tuple[CapabilityId, ...]


def prepare_scan(
    *,
    config: ScanConfig,
    registry: CapabilityRegistry,
) -> PreparedScan:
    """Validate capability policy and prepare a deterministic execution plan."""
    if not isinstance(cast(object, config), ScanConfig):
        raise TypeError("prepare_scan requires a ScanConfig")
    if not isinstance(cast(object, registry), CapabilityRegistry):
        raise TypeError("prepare_scan requires a CapabilityRegistry")

    registered = set(registry.ids())
    unknown = tuple(
        item for item in config.disabled_capabilities if item not in registered
    )
    if unknown:
        raise ScanConfigurationError("disabled capability is not registered")

    try:
        complete_plan = ExecutionPlanner(registry).plan(
            goals=config.requested_outputs
        )
    except PlanningError:
        raise ScanPreparationError(
            "requested outputs cannot be planned"
        ) from None
    disabled = set(config.disabled_capabilities)
    required_disabled = tuple(
        item
        for item in complete_plan.required_capability_ids
        if item in disabled
    )
    if required_disabled:
        raise DisabledCapabilityError(required_disabled[0].value)

    allowed_definitions = tuple(
        definition
        for definition in registry.all()
        if definition.capability_id not in disabled
    )
    filtered_registry = CapabilityRegistry(allowed_definitions)
    try:
        plan = ExecutionPlanner(filtered_registry).plan(
            goals=config.requested_outputs
        )
    except PlanningError:
        raise ScanPreparationError(
            "requested outputs cannot be planned"
        ) from None
    return PreparedScan(
        config=config,
        plan=plan,
        allowed_capabilities=filtered_registry.ids(),
    )


def create_initial_context(config: ScanConfig) -> Context:
    """Seed an empty runtime Context from only the canonical validated target."""
    if not isinstance(cast(object, config), ScanConfig):
        raise TypeError("initial context requires a ScanConfig")
    return Context(target_id=config.scope.root.value)


def _target(value: ScanTarget | str) -> ScanTarget:
    if isinstance(value, ScanTarget):
        return value
    try:
        return ScanTarget(value)
    except (TypeError, ValueError):
        raise ScanConfigurationError("scan target is invalid") from None
