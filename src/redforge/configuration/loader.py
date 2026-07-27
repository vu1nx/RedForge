"""Strict one-file TOML configuration loader."""

import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn, cast

from redforge.composition.profile import CompositionProfile
from redforge.configuration.errors import (
    ConfigurationFileError,
    ConfigurationParseError,
    ConfigurationReasonCode,
    ConfigurationValidationError,
    UnknownConfigurationFieldError,
    UnsupportedConfigurationVersionError,
)
from redforge.configuration.models import (
    CONFIGURATION_SCHEMA_VERSION,
    CompositionConfiguration,
    LimitConfiguration,
    ObservabilityConfiguration,
    ObservabilityLevel,
    OutputConfiguration,
    OutputFormat,
    RedForgeConfiguration,
    ScanConfiguration,
    ScanPreset,
)

_ROOT_FIELDS = frozenset(
    ("schema_version", "scan", "composition", "output", "observability")
)
_SCAN_FIELDS = frozenset(("preset", "allow_partial_results", "limits"))
_LIMIT_FIELDS = frozenset(
    (
        "max_subdomains",
        "max_hosts",
        "max_alive_hosts",
        "max_http_endpoints",
        "max_crawl_endpoints",
        "max_technologies",
        "overall_timeout_seconds",
    )
)
_COMPOSITION_FIELDS = frozenset(("profile",))
_OUTPUT_FIELDS = frozenset(("format",))
_OBSERVABILITY_FIELDS = frozenset(("level",))


def load_configuration(path: Path) -> RedForgeConfiguration:
    """Read and parse exactly one explicit UTF-8 TOML file."""
    if not isinstance(cast(object, path), Path):
        raise TypeError("configuration path must be a Path")
    if str(path) == "-" or "://" in str(path):
        raise ConfigurationFileError(
            ConfigurationReasonCode.FILE_UNAVAILABLE,
            "configuration file is unavailable",
        )
    try:
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeError):
        raise ConfigurationFileError(
            ConfigurationReasonCode.FILE_UNAVAILABLE,
            "configuration file is unavailable",
        ) from None
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        raise ConfigurationParseError(
            ConfigurationReasonCode.PARSE_FAILED,
            "configuration file could not be parsed",
        ) from None
    return _build_configuration(cast(dict[str, object], parsed))


def _build_configuration(raw: dict[str, object]) -> RedForgeConfiguration:
    _reject_unknown(raw, _ROOT_FIELDS, "")
    if "schema_version" not in raw:
        raise ConfigurationValidationError(
            ConfigurationReasonCode.VERSION_MISSING,
            "configuration schema version is required",
            field_path="schema_version",
        )
    version = raw["schema_version"]
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != CONFIGURATION_SCHEMA_VERSION
    ):
        raise UnsupportedConfigurationVersionError(
            ConfigurationReasonCode.VERSION_UNSUPPORTED,
            "configuration schema version is unsupported",
            field_path="schema_version",
        )
    scan_raw = _section(raw, "scan")
    composition_raw = _section(raw, "composition")
    output_raw = _section(raw, "output")
    observability_raw = _section(raw, "observability")
    _reject_unknown(scan_raw, _SCAN_FIELDS, "scan")
    limits_raw = _nested_section(scan_raw, "limits", "scan.limits")
    _reject_unknown(limits_raw, _LIMIT_FIELDS, "scan.limits")
    _reject_unknown(composition_raw, _COMPOSITION_FIELDS, "composition")
    _reject_unknown(output_raw, _OUTPUT_FIELDS, "output")
    _reject_unknown(
        observability_raw,
        _OBSERVABILITY_FIELDS,
        "observability",
    )

    defaults = RedForgeConfiguration.default()
    limits = defaults.scan.limits
    limit_configuration = LimitConfiguration(
        max_subdomains=_integer(
            limits_raw,
            "max_subdomains",
            limits.max_subdomains,
            "scan.limits.max_subdomains",
        ),
        max_hosts=_integer(
            limits_raw, "max_hosts", limits.max_hosts, "scan.limits.max_hosts"
        ),
        max_alive_hosts=_integer(
            limits_raw,
            "max_alive_hosts",
            limits.max_alive_hosts,
            "scan.limits.max_alive_hosts",
        ),
        max_http_endpoints=_integer(
            limits_raw,
            "max_http_endpoints",
            limits.max_http_endpoints,
            "scan.limits.max_http_endpoints",
        ),
        max_crawl_endpoints=_integer(
            limits_raw,
            "max_crawl_endpoints",
            limits.max_crawl_endpoints,
            "scan.limits.max_crawl_endpoints",
        ),
        max_technologies=_integer(
            limits_raw,
            "max_technologies",
            limits.max_technologies,
            "scan.limits.max_technologies",
        ),
        overall_timeout_seconds=_integer(
            limits_raw,
            "overall_timeout_seconds",
            limits.overall_timeout_seconds,
            "scan.limits.overall_timeout_seconds",
        ),
    )
    scan = ScanConfiguration(
        preset=_enum(
            scan_raw,
            "preset",
            ScanPreset,
            defaults.scan.preset,
            "scan.preset",
        ),
        allow_partial_results=_boolean(
            scan_raw,
            "allow_partial_results",
            defaults.scan.allow_partial_results,
            "scan.allow_partial_results",
        ),
        limits=limit_configuration,
    )
    composition = CompositionConfiguration(
        profile=_enum(
            composition_raw,
            "profile",
            CompositionProfile,
            defaults.composition.profile,
            "composition.profile",
        )
    )
    output = OutputConfiguration(
        format=_enum(
            output_raw,
            "format",
            OutputFormat,
            defaults.output.format,
            "output.format",
        )
    )
    observability = ObservabilityConfiguration(
        level=_enum(
            observability_raw,
            "level",
            ObservabilityLevel,
            defaults.observability.level,
            "observability.level",
        )
    )
    try:
        return RedForgeConfiguration(
            schema_version=version,
            scan=scan,
            composition=composition,
            output=output,
            observability=observability,
        )
    except ConfigurationValidationError:
        raise
    except (TypeError, ValueError):
        raise ConfigurationValidationError(
            ConfigurationReasonCode.VALUE_INVALID,
            "configuration value is invalid",
        ) from None


def _section(raw: dict[str, object], key: str) -> dict[str, object]:
    value = raw.get(key, {})
    if not isinstance(value, dict):
        _invalid(key)
    return cast(dict[str, object], value)


def _nested_section(
    raw: dict[str, object],
    key: str,
    path: str,
) -> dict[str, object]:
    value = raw.get(key, {})
    if not isinstance(value, dict):
        _invalid(path)
    return cast(dict[str, object], value)


def _reject_unknown(
    raw: dict[str, object],
    allowed: frozenset[str],
    prefix: str,
) -> None:
    unknown = tuple(sorted(set(raw).difference(allowed)))
    if unknown:
        path = f"{prefix}.{unknown[0]}" if prefix else unknown[0]
        raise UnknownConfigurationFieldError(
            ConfigurationReasonCode.FIELD_UNKNOWN,
            f"unknown configuration field: {path}",
            field_path=path,
        )


def _integer(
    raw: dict[str, object],
    key: str,
    default: int,
    path: str,
) -> int:
    value = raw.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        _invalid(path)
    return value


def _boolean(
    raw: dict[str, object],
    key: str,
    default: bool,
    path: str,
) -> bool:
    value = raw.get(key, default)
    if not isinstance(value, bool):
        _invalid(path)
    return value


def _enum[E](
    raw: dict[str, object],
    key: str,
    enum_type: Callable[[str], E],
    default: E,
    path: str,
) -> E:
    value = raw.get(key)
    if value is None:
        return default
    if not isinstance(value, str):
        _invalid(path)
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        _invalid(path)


def _invalid(path: str) -> NoReturn:
    raise ConfigurationValidationError(
        ConfigurationReasonCode.VALUE_INVALID,
        f"invalid configuration value: {path}",
        field_path=path,
    )
