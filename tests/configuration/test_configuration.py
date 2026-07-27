"""Typed deterministic TOML configuration tests."""

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest  # type: ignore[reportMissingImports]

from redforge.application import ScanLimits
from redforge.composition import CompositionProfile
from redforge.configuration import (
    CONFIGURATION_SCHEMA_VERSION,
    CompositionConfiguration,
    ConfigurationFileError,
    ConfigurationParseError,
    ConfigurationReasonCode,
    ConfigurationValidationError,
    LimitConfiguration,
    ObservabilityConfiguration,
    ObservabilityLevel,
    OutputConfiguration,
    OutputFormat,
    RedForgeConfiguration,
    ScanConfiguration,
    ScanPreset,
    UnknownConfigurationFieldError,
    UnsupportedConfigurationVersionError,
    load_configuration,
    resolve_configuration,
)
from redforge.sdk import PipelineStateKey


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "redforge.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_default_configuration_is_immutable_typed_and_deterministic() -> None:
    first = RedForgeConfiguration.default()
    second = RedForgeConfiguration.default()

    assert first == second
    assert first.schema_version == CONFIGURATION_SCHEMA_VERSION == 1
    assert first.scan.preset is ScanPreset.RECONNAISSANCE
    assert not first.scan.allow_partial_results
    assert first.scan.limits.to_scan_limits() == ScanLimits()
    assert (
        first.composition.profile
        is CompositionProfile.RECONNAISSANCE
    )
    assert first.output.format is OutputFormat.HUMAN
    assert first.observability.level is ObservabilityLevel.OFF
    assert "dict" not in repr(first)
    with pytest.raises(FrozenInstanceError):
        first.schema_version = 2  # type: ignore[misc]


def test_minimal_toml_uses_typed_section_defaults(tmp_path: Path) -> None:
    configuration = load_configuration(
        _write(tmp_path, "schema_version = 1\n")
    )

    assert configuration == RedForgeConfiguration.default()


def test_complete_toml_maps_all_supported_values(tmp_path: Path) -> None:
    configuration = load_configuration(
        _write(
            tmp_path,
            """
schema_version = 1
[scan]
preset = "full"
allow_partial_results = true
[scan.limits]
max_subdomains = 10
max_hosts = 11
max_alive_hosts = 12
max_http_endpoints = 13
max_crawl_endpoints = 14
max_technologies = 15
overall_timeout_seconds = 16
[composition]
profile = "full_assessment"
[output]
format = "json"
[observability]
level = "info"
""",
        )
    )

    assert configuration.scan == ScanConfiguration(
        preset=ScanPreset.FULL,
        allow_partial_results=True,
        limits=LimitConfiguration(
            max_subdomains=10,
            max_hosts=11,
            max_alive_hosts=12,
            max_http_endpoints=13,
            max_crawl_endpoints=14,
            max_technologies=15,
            overall_timeout_seconds=16,
        ),
    )
    assert (
        configuration.composition.profile
        is CompositionProfile.FULL_ASSESSMENT
    )
    assert configuration.output.format is OutputFormat.JSON
    assert configuration.observability == ObservabilityConfiguration(
        level=ObservabilityLevel.INFO
    )


def test_missing_file_and_non_file_path_are_sanitized(tmp_path: Path) -> None:
    for path in (tmp_path / "missing.toml", tmp_path):
        with pytest.raises(ConfigurationFileError) as caught:
            load_configuration(path)
        assert (
            caught.value.reason_code
            is ConfigurationReasonCode.FILE_UNAVAILABLE
        )
        assert str(path) not in str(caught.value)


@pytest.mark.parametrize(
    "text",
    (
        "schema_version = ",
        "schema_version = 1\nschema_version = 1\n",
        b"\xff".decode("latin-1"),
    ),
)
def test_malformed_duplicate_and_non_utf8_content_is_rejected(
    tmp_path: Path,
    text: str,
) -> None:
    path = tmp_path / "redforge.toml"
    if text == "ÿ":
        path.write_bytes(b"\xff")
    else:
        path.write_text(text, encoding="utf-8")
    expected = (
        ConfigurationFileError
        if text == "ÿ"
        else ConfigurationParseError
    )
    with pytest.raises(expected):
        load_configuration(path)


def test_missing_and_unsupported_schema_versions_are_distinct(
    tmp_path: Path,
) -> None:
    with pytest.raises(ConfigurationValidationError) as missing:
        load_configuration(_write(tmp_path, "[scan]\n"))
    assert missing.value.reason_code is ConfigurationReasonCode.VERSION_MISSING

    with pytest.raises(UnsupportedConfigurationVersionError) as unsupported:
        load_configuration(_write(tmp_path, "schema_version = 2\n"))
    assert (
        unsupported.value.reason_code
        is ConfigurationReasonCode.VERSION_UNSUPPORTED
    )


@pytest.mark.parametrize(
    ("text", "path"),
    (
        ("schema_version = 1\nunknown = true\n", "unknown"),
        (
            'schema_version = 1\n[scan]\npresett = "full"\n',
            "scan.presett",
        ),
        (
            "schema_version = 1\n[scan.limits]\nmax_hostz = 1\n",
            "scan.limits.max_hostz",
        ),
        (
            "schema_version = 1\n[output]\npretty = true\n",
            "output.pretty",
        ),
        (
            "schema_version = 1\n[composition]\nprovider = true\n",
            "composition.provider",
        ),
        (
            "schema_version = 1\n[observability]\nformat = true\n",
            "observability.format",
        ),
    ),
)
def test_unknown_fields_are_rejected_with_safe_paths(
    tmp_path: Path,
    text: str,
    path: str,
) -> None:
    with pytest.raises(UnknownConfigurationFieldError) as caught:
        load_configuration(_write(tmp_path, text))

    assert caught.value.reason_code is ConfigurationReasonCode.FIELD_UNKNOWN
    assert caught.value.field_path == path


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("max_hosts", "-1"),
        ("max_hosts", "false"),
        ("max_hosts", '"10"'),
        ("overall_timeout_seconds", "0"),
        ("overall_timeout_seconds", "1.5"),
    ),
)
def test_limit_values_reuse_scan_limits_without_coercion(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    with pytest.raises(ConfigurationValidationError) as caught:
        load_configuration(
            _write(
                tmp_path,
                f"schema_version = 1\n[scan.limits]\n{field} = {value}\n",
            )
        )

    assert caught.value.reason_code is ConfigurationReasonCode.VALUE_INVALID


def test_limit_values_accept_exact_existing_application_boundaries() -> None:
    configured = LimitConfiguration(
        max_subdomains=100_000,
        max_hosts=100_000,
        max_alive_hosts=100_000,
        max_http_endpoints=200_000,
        max_crawl_endpoints=1_000_000,
        max_technologies=200_000,
        overall_timeout_seconds=86_400,
    )

    assert configured.to_scan_limits() == ScanLimits(
        max_subdomains=100_000,
        max_hosts=100_000,
        max_alive_hosts=100_000,
        max_http_endpoints=200_000,
        max_crawl_endpoints=1_000_000,
        max_technologies=200_000,
        overall_timeout_seconds=86_400,
    )


def test_zero_limit_is_rejected_by_existing_application_contract() -> None:
    with pytest.raises(ConfigurationValidationError):
        LimitConfiguration(max_hosts=0)


@pytest.mark.parametrize(
    "text",
    (
        'schema_version = 1\n[scan]\npreset = "FULL"\n',
        'schema_version = 1\n[scan]\npreset = 1\n',
        'schema_version = 1\n[scan]\nallow_partial_results = "true"\n',
        'schema_version = 1\n[composition]\nprofile = "full"\n',
        'schema_version = 1\n[output]\nformat = "JSON"\n',
        'schema_version = 1\n[observability]\nlevel = "INFO"\n',
        'schema_version = 1\n[observability]\nlevel = 1\n',
    ),
)
def test_wrong_primitive_types_and_aliases_are_not_coerced(
    tmp_path: Path,
    text: str,
) -> None:
    with pytest.raises(ConfigurationValidationError):
        load_configuration(_write(tmp_path, text))


@pytest.mark.parametrize(
    ("preset", "profile", "valid"),
    (
        (
            ScanPreset.RECONNAISSANCE,
            CompositionProfile.RECONNAISSANCE,
            True,
        ),
        (
            ScanPreset.RECONNAISSANCE,
            CompositionProfile.FULL_ASSESSMENT,
            True,
        ),
        (ScanPreset.FULL, CompositionProfile.FULL_ASSESSMENT, True),
        (ScanPreset.FULL, CompositionProfile.RECONNAISSANCE, False),
    ),
)
def test_profile_compatibility_is_centralized(
    preset: ScanPreset,
    profile: CompositionProfile,
    valid: bool,
) -> None:
    if not valid:
        with pytest.raises(ConfigurationValidationError):
            RedForgeConfiguration(
                schema_version=1,
                scan=ScanConfiguration(preset=preset),
                composition=CompositionConfiguration(profile=profile),
            )
        return
    configuration = RedForgeConfiguration(
        schema_version=1,
        scan=ScanConfiguration(preset=preset),
        composition=CompositionConfiguration(profile=profile),
    )
    assert configuration.scan.preset is preset


def test_translation_applies_overrides_without_file_or_composition_work() -> None:
    configuration = RedForgeConfiguration(
        schema_version=1,
        scan=ScanConfiguration(
            allow_partial_results=False,
            limits=LimitConfiguration(max_hosts=7),
        ),
        composition=CompositionConfiguration(
            profile=CompositionProfile.RECONNAISSANCE
        ),
        output=OutputConfiguration(format=OutputFormat.HUMAN),
        observability=ObservabilityConfiguration(
            level=ObservabilityLevel.WARNING
        ),
    )

    resolved = resolve_configuration(
        target="AUTHORIZED.example.",
        configuration=configuration,
        preset_override=ScanPreset.FULL,
        allow_partial_results_override=True,
        output_override=OutputFormat.JSON,
        observability_level_override=ObservabilityLevel.DEBUG,
    )

    assert resolved.scan_config.scope.root.value == "authorized.example"
    assert resolved.scan_config.requested_outputs == (
        PipelineStateKey.RISK_INTELLIGENCE,
    )
    assert resolved.scan_config.allow_partial_results
    assert resolved.scan_config.limits.max_hosts == 7
    assert resolved.composition_profile is CompositionProfile.FULL_ASSESSMENT
    assert resolved.output_format is OutputFormat.JSON
    assert resolved.observability_level is ObservabilityLevel.DEBUG


@pytest.mark.parametrize("level", tuple(ObservabilityLevel))
def test_all_observability_levels_load_without_side_effects(
    tmp_path: Path,
    level: ObservabilityLevel,
) -> None:
    configuration = load_configuration(
        _write(
            tmp_path,
            "schema_version = 1\n"
            "[observability]\n"
            f'level = "{level.value}"\n',
        )
    )

    assert configuration.observability.level is level
