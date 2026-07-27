"""Immutable format-neutral configuration models and translation."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import cast

from redforge.application import ScanConfig, ScanConfigurationError, ScanLimits
from redforge.composition.profile import CompositionProfile
from redforge.configuration.errors import (
    ConfigurationReasonCode,
    ConfigurationValidationError,
)

CONFIGURATION_SCHEMA_VERSION = 1
_DEFAULT_LIMITS = ScanLimits()


class ScanPreset(StrEnum):
    """Canonical configured application scan intent."""

    RECONNAISSANCE = "reconnaissance"
    FULL = "full"


class OutputFormat(StrEnum):
    """Canonical configured terminal representation."""

    HUMAN = "human"
    JSON = "json"


class ObservabilityLevel(StrEnum):
    """Configured minimum diagnostic severity or explicit silence."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    OFF = "off"


@dataclass(frozen=True, slots=True)
class LimitConfiguration:
    """Typed values translated through the accepted ScanLimits validator."""

    max_subdomains: int = _DEFAULT_LIMITS.max_subdomains
    max_hosts: int = _DEFAULT_LIMITS.max_hosts
    max_alive_hosts: int = _DEFAULT_LIMITS.max_alive_hosts
    max_http_endpoints: int = _DEFAULT_LIMITS.max_http_endpoints
    max_crawl_endpoints: int = _DEFAULT_LIMITS.max_crawl_endpoints
    max_technologies: int = _DEFAULT_LIMITS.max_technologies
    overall_timeout_seconds: int = _DEFAULT_LIMITS.overall_timeout_seconds

    def __post_init__(self) -> None:
        self.to_scan_limits()

    def to_scan_limits(self) -> ScanLimits:
        """Delegate all numeric bounds and boolean rejection to ScanLimits."""
        try:
            return ScanLimits(
                max_subdomains=self.max_subdomains,
                max_hosts=self.max_hosts,
                max_alive_hosts=self.max_alive_hosts,
                max_http_endpoints=self.max_http_endpoints,
                max_crawl_endpoints=self.max_crawl_endpoints,
                max_technologies=self.max_technologies,
                overall_timeout_seconds=self.overall_timeout_seconds,
            )
        except ScanConfigurationError:
            raise ConfigurationValidationError(
                ConfigurationReasonCode.VALUE_INVALID,
                "configuration limit value is invalid",
                field_path="scan.limits",
            ) from None


@dataclass(frozen=True, slots=True)
class ScanConfiguration:
    """Configured scan preset, acceptance, and neutral limits."""

    preset: ScanPreset = ScanPreset.RECONNAISSANCE
    allow_partial_results: bool = False
    limits: LimitConfiguration = field(default_factory=LimitConfiguration)

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.preset), ScanPreset):
            raise TypeError("scan preset is invalid")
        if not isinstance(cast(object, self.allow_partial_results), bool):
            raise TypeError("partial-result configuration is invalid")
        if not isinstance(cast(object, self.limits), LimitConfiguration):
            raise TypeError("limit configuration is invalid")
        self.limits.to_scan_limits()


@dataclass(frozen=True, slots=True)
class CompositionConfiguration:
    """Explicit composition profile selection."""

    profile: CompositionProfile = CompositionProfile.RECONNAISSANCE

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.profile), CompositionProfile):
            raise TypeError("composition profile is invalid")


@dataclass(frozen=True, slots=True)
class OutputConfiguration:
    """Configured terminal output selection."""

    format: OutputFormat = OutputFormat.HUMAN

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.format), OutputFormat):
            raise TypeError("output format is invalid")


@dataclass(frozen=True, slots=True)
class ObservabilityConfiguration:
    """Minimal provider-neutral diagnostic selection."""

    level: ObservabilityLevel = ObservabilityLevel.OFF

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.level), ObservabilityLevel):
            raise TypeError("observability level is invalid")


@dataclass(frozen=True, slots=True)
class RedForgeConfiguration:
    """Complete schema-versioned reusable configuration without a target."""

    schema_version: int
    scan: ScanConfiguration = field(default_factory=ScanConfiguration)
    composition: CompositionConfiguration = field(
        default_factory=CompositionConfiguration
    )
    output: OutputConfiguration = field(default_factory=OutputConfiguration)
    observability: ObservabilityConfiguration = field(
        default_factory=ObservabilityConfiguration
    )

    def __post_init__(self) -> None:
        if (
            not isinstance(cast(object, self.schema_version), int)
            or isinstance(cast(object, self.schema_version), bool)
            or self.schema_version != CONFIGURATION_SCHEMA_VERSION
        ):
            raise TypeError("configuration schema version is invalid")
        if not isinstance(cast(object, self.scan), ScanConfiguration):
            raise TypeError("scan configuration is invalid")
        if not isinstance(
            cast(object, self.composition), CompositionConfiguration
        ):
            raise TypeError("composition configuration is invalid")
        if not isinstance(cast(object, self.output), OutputConfiguration):
            raise TypeError("output configuration is invalid")
        if not isinstance(
            cast(object, self.observability),
            ObservabilityConfiguration,
        ):
            raise TypeError("observability configuration is invalid")
        validate_profile_compatibility(
            self.scan.preset,
            self.composition.profile,
        )

    @classmethod
    def default(cls) -> "RedForgeConfiguration":
        """Return deterministic existing CLI defaults without file access."""
        return cls(schema_version=CONFIGURATION_SCHEMA_VERSION)


@dataclass(frozen=True, slots=True)
class ResolvedConfiguration:
    """Pure translation result consumed by CLI and composition boundaries."""

    scan_config: ScanConfig
    composition_profile: CompositionProfile
    output_format: OutputFormat
    scan_preset: ScanPreset
    observability_level: ObservabilityLevel


def resolve_configuration(
    *,
    target: str,
    configuration: RedForgeConfiguration,
    preset_override: ScanPreset | None = None,
    allow_partial_results_override: bool | None = None,
    output_override: OutputFormat | None = None,
    observability_level_override: ObservabilityLevel | None = None,
) -> ResolvedConfiguration:
    """Apply explicit overrides and construct stable application inputs."""
    preset = preset_override or configuration.scan.preset
    profile = configuration.composition.profile
    if preset_override is ScanPreset.FULL:
        profile = CompositionProfile.FULL_ASSESSMENT
    validate_profile_compatibility(preset, profile)
    allow_partial = (
        allow_partial_results_override
        if allow_partial_results_override is not None
        else configuration.scan.allow_partial_results
    )
    limits = configuration.scan.limits.to_scan_limits()
    constructor = (
        ScanConfig.for_reconnaissance
        if preset is ScanPreset.RECONNAISSANCE
        else ScanConfig.for_full_assessment
    )
    return ResolvedConfiguration(
        scan_config=constructor(
            target,
            limits=limits,
            allow_partial_results=allow_partial,
        ),
        composition_profile=profile,
        output_format=output_override or configuration.output.format,
        scan_preset=preset,
        observability_level=(
            observability_level_override
            or configuration.observability.level
        ),
    )


def validate_profile_compatibility(
    preset: ScanPreset,
    profile: CompositionProfile,
) -> None:
    """Reject only a full scan requested from a reconnaissance composition."""
    if (
        preset is ScanPreset.FULL
        and profile is CompositionProfile.RECONNAISSANCE
    ):
        raise ConfigurationValidationError(
            ConfigurationReasonCode.PROFILE_INCOMPATIBLE,
            "scan preset is incompatible with composition profile",
            field_path="composition.profile",
        )
