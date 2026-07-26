"""Secure scan target, scope, configuration, and preparation tests."""

from dataclasses import FrozenInstanceError, fields
from typing import cast

import pytest  # type: ignore[reportMissingImports]

from redforge.application import (
    DisabledCapabilityError,
    PreparedScan,
    ScanConfig,
    ScanConfigurationError,
    ScanLimits,
    ScanScope,
    ScanTarget,
    create_initial_context,
    prepare_scan,
)
from redforge.domain import Endpoint
from redforge.planning import (
    CapabilityId,
    create_default_registry,
)
from redforge.sdk import PipelineStateKey


@pytest.mark.parametrize(
    ("raw", "expected"),
    (
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("api.example.com", "api.example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        (f"{'a' * 63}.example", f"{'a' * 63}.example"),
    ),
)
def test_scan_target_normalizes_valid_dns_roots(
    raw: str, expected: str
) -> None:
    assert ScanTarget(raw).value == expected


@pytest.mark.parametrize(
    "raw",
    (
        "",
        " ",
        " example.com",
        "example.com ",
        "example com",
        "example.com\n",
        "example.com\t",
        "https://example.com",
        "example.com/path",
        "example.com?query",
        "example.com#fragment",
        "user@example.com",
        "example.com:443",
        "*.example.com",
        "example..com",
        "-example.com",
        "example-.com",
        f"{'a' * 64}.example",
        f"{'a' * 63}.{'b' * 63}.{'c' * 63}.{'d' * 62}.com",
        "192.0.2.10",
        "2001:db8::1",
    ),
)
def test_scan_target_rejects_non_dns_root_input(raw: str) -> None:
    with pytest.raises(ValueError, match="scan target"):
        ScanTarget(raw)


def test_scan_target_rejects_non_string_input() -> None:
    with pytest.raises(ValueError, match="scan target"):
        ScanTarget(123)  # type: ignore[arg-type]


def test_scan_target_is_immutable_slotted_and_deterministic() -> None:
    target = ScanTarget("EXAMPLE.com.")

    assert target == ScanTarget("example.com")
    assert not hasattr(target, "__dict__")
    with pytest.raises(FrozenInstanceError):
        target.value = "changed.example"  # type: ignore[misc]


def test_unicode_and_ascii_idna_scan_targets_are_equal() -> None:
    assert ScanTarget("bücher.example") == ScanTarget(
        "xn--bcher-kva.example"
    )


def test_scan_target_accepts_maximum_dns_length() -> None:
    value = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))

    assert len(value) == 253
    assert ScanTarget(value).value == value


@pytest.mark.parametrize(
    "hostname",
    ("example.com", "api.example.com", "a.b.example.com", "API.EXAMPLE.COM."),
)
def test_scan_scope_accepts_root_and_true_subdomains(hostname: str) -> None:
    assert ScanScope(ScanTarget("example.com")).contains_hostname(hostname)


@pytest.mark.parametrize(
    "hostname",
    (
        "example.com.attacker.test",
        "notexample.com",
        "attacker.test",
        "com",
        "example.org",
        "example.com\n",
        "192.0.2.10",
        "2001:db8::1",
    ),
)
def test_scan_scope_rejects_invalid_suffix_confusion_and_ip_hosts(
    hostname: str,
) -> None:
    assert not ScanScope(ScanTarget("example.com")).contains_hostname(hostname)


def test_scan_scope_handles_idna_on_both_sides() -> None:
    scope = ScanScope(ScanTarget("bücher.example"))

    assert scope.contains_hostname("shop.bücher.example")
    assert scope.contains_hostname("shop.xn--bcher-kva.example")


def test_scan_scope_rejects_invalid_root_type() -> None:
    with pytest.raises(TypeError, match="ScanTarget"):
        ScanScope("example.com")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "endpoint",
    (
        Endpoint("example.com", 80, "http", "/"),
        Endpoint("api.example.com", 443, "https", "/nested?query=yes"),
        Endpoint("deep.api.example.com", 8443, "https", "/"),
    ),
)
def test_endpoint_scope_accepts_http_dns_targets(endpoint: Endpoint) -> None:
    assert ScanScope(ScanTarget("example.com")).contains_endpoint(endpoint)


def test_endpoint_scope_accepts_canonical_hostname_equivalence() -> None:
    scope = ScanScope(ScanTarget("BÜCHER.example."))

    assert scope.contains_endpoint(
        Endpoint("shop.xn--bcher-kva.example.", 443, "https", "/")
    )


@pytest.mark.parametrize(
    "endpoint",
    (
        Endpoint("example.com.attacker.test", 443, "https", "/"),
        Endpoint("notexample.com", 443, "https", "/"),
        Endpoint("com", 443, "https", "/"),
        Endpoint("attacker.test", 443, "https", "/"),
        Endpoint("user@example.com", 443, "https", "/"),
        Endpoint("192.0.2.10", 443, "https", "/"),
        Endpoint("2001:db8::1", 443, "https", "/"),
        Endpoint("example.com", 443, "ftp", "/"),
        Endpoint("example.com", 0, "https", "/"),
    ),
)
def test_endpoint_scope_rejects_widening_and_unsupported_targets(
    endpoint: Endpoint,
) -> None:
    assert not ScanScope(ScanTarget("example.com")).contains_endpoint(endpoint)


def test_endpoint_scope_rejects_non_endpoint_input() -> None:
    assert not ScanScope(ScanTarget("example.com")).contains_endpoint(
        cast(Endpoint, object())
    )


def test_scan_limits_defaults_bounds_and_immutability() -> None:
    limits = ScanLimits()

    assert limits.max_subdomains == 1_000
    assert limits.overall_timeout_seconds == 1_800
    assert not hasattr(limits, "__dict__")
    assert all(
        "tool" not in item.name
        and "thread" not in item.name
        and "argument" not in item.name
        for item in fields(ScanLimits)
    )
    with pytest.raises(FrozenInstanceError):
        limits.max_hosts = 2  # type: ignore[misc]


@pytest.mark.parametrize("invalid", (0, -1, 100_001, 1.5, True, "10"))
def test_scan_limits_reject_invalid_values(invalid: object) -> None:
    with pytest.raises(ScanConfigurationError, match="max_subdomains"):
        ScanLimits(max_subdomains=invalid)  # type: ignore[arg-type]


def test_scan_limits_accept_documented_minimum_and_maximum() -> None:
    assert ScanLimits(max_subdomains=1).max_subdomains == 1
    assert ScanLimits(max_subdomains=100_000).max_subdomains == 100_000
    assert ScanLimits(overall_timeout_seconds=86_400).overall_timeout_seconds == 86_400


@pytest.mark.parametrize(
    ("field_name", "maximum"),
    (
        ("max_hosts", 100_000),
        ("max_alive_hosts", 100_000),
        ("max_http_endpoints", 200_000),
        ("max_crawl_endpoints", 1_000_000),
        ("max_technologies", 200_000),
        ("overall_timeout_seconds", 86_400),
    ),
)
def test_each_scan_limit_rejects_values_above_its_bound(
    field_name: str,
    maximum: int,
) -> None:
    with pytest.raises(ScanConfigurationError, match=field_name):
        ScanLimits(**{field_name: maximum + 1})  # type: ignore[arg-type]


def test_scan_config_normalizes_outputs_and_disabled_ids() -> None:
    config = ScanConfig(
        scope=ScanScope(ScanTarget("example.com")),
        requested_outputs=(
            PipelineStateKey.RISK_INTELLIGENCE,
            PipelineStateKey.TECHNOLOGIES,
        ),
        disabled_capabilities=(
            CapabilityId("risk_intelligence"),
            CapabilityId("knowledge_graph"),
        ),
        allow_partial_results=False,
    )

    assert config.requested_outputs == (
        PipelineStateKey.RISK_INTELLIGENCE,
        PipelineStateKey.TECHNOLOGIES,
    )
    assert config.disabled_capabilities == (
        CapabilityId("knowledge_graph"),
        CapabilityId("risk_intelligence"),
    )
    assert not config.allow_partial_results
    assert not hasattr(config, "__dict__")


def test_scan_config_defaults_are_isolated_and_deterministic() -> None:
    first = ScanConfig.for_reconnaissance("example.com")
    second = ScanConfig.for_reconnaissance("EXAMPLE.COM.")

    assert first == second
    assert first.limits is not second.limits
    assert first.disabled_capabilities == ()
    assert first.allow_partial_results


@pytest.mark.parametrize(
    "outputs",
    (
        (),
        (PipelineStateKey.HOSTS,),
        (PipelineStateKey.TECHNOLOGIES, PipelineStateKey.TECHNOLOGIES),
        ("technologies",),
    ),
)
def test_scan_config_rejects_invalid_requested_outputs(
    outputs: tuple[object, ...],
) -> None:
    with pytest.raises(ScanConfigurationError):
        ScanConfig(
            scope=ScanScope(ScanTarget("example.com")),
            requested_outputs=outputs,  # type: ignore[arg-type]
        )


def test_scan_config_rejects_invalid_nested_or_policy_values() -> None:
    with pytest.raises(ScanConfigurationError, match="scope"):
        ScanConfig(
            scope="example.com",  # type: ignore[arg-type]
            requested_outputs=(PipelineStateKey.TECHNOLOGIES,),
        )
    with pytest.raises(ScanConfigurationError, match="limits"):
        ScanConfig(
            scope=ScanScope(ScanTarget("example.com")),
            requested_outputs=(PipelineStateKey.TECHNOLOGIES,),
            limits=object(),  # type: ignore[arg-type]
        )
    with pytest.raises(ScanConfigurationError, match="partial"):
        ScanConfig(
            scope=ScanScope(ScanTarget("example.com")),
            requested_outputs=(PipelineStateKey.TECHNOLOGIES,),
            allow_partial_results=1,  # type: ignore[arg-type]
        )


def test_scan_config_rejects_duplicate_or_untyped_disabled_capabilities() -> None:
    scope = ScanScope(ScanTarget("example.com"))
    with pytest.raises(ScanConfigurationError, match="duplicates"):
        ScanConfig(
            scope=scope,
            requested_outputs=(PipelineStateKey.TECHNOLOGIES,),
            disabled_capabilities=(
                CapabilityId("http_probe"),
                CapabilityId("http_probe"),
            ),
        )
    with pytest.raises(ScanConfigurationError, match="disabled"):
        ScanConfig(
            scope=scope,
            requested_outputs=(PipelineStateKey.TECHNOLOGIES,),
            disabled_capabilities=("http_probe",),  # type: ignore[arg-type]
        )


def test_presets_request_final_states_and_planner_derives_dependencies() -> None:
    registry = create_default_registry()
    recon = ScanConfig.for_reconnaissance("EXAMPLE.com.")
    full = ScanConfig.for_full_assessment("example.com")

    recon_prepared = prepare_scan(config=recon, registry=registry)
    full_prepared = prepare_scan(config=full, registry=registry)

    assert recon.requested_outputs == (PipelineStateKey.TECHNOLOGIES,)
    assert recon_prepared.plan.required_capabilities == (
        "subdomain_discovery",
        "host_resolution",
        "http_probe",
        "web_crawl",
        "technology_detection",
    )
    assert full.requested_outputs == (PipelineStateKey.RISK_INTELLIGENCE,)
    assert full_prepared.plan.required_capabilities == (
        "subdomain_discovery",
        "host_resolution",
        "http_probe",
        "web_crawl",
        "technology_detection",
        "asset_intelligence",
        "vulnerability_intelligence",
        "knowledge_graph",
        "risk_intelligence",
    )


def test_prepare_scan_is_deterministic_and_immutable() -> None:
    config = ScanConfig.for_full_assessment("example.com")
    registry = create_default_registry()

    first = prepare_scan(config=config, registry=registry)
    second = prepare_scan(config=config, registry=registry)

    assert first == second
    assert isinstance(first, PreparedScan)
    assert first.allowed_capabilities == registry.ids()
    assert not hasattr(first, "__dict__")
    with pytest.raises(FrozenInstanceError):
        first.config = config  # type: ignore[misc]


def test_unrelated_disabled_capability_is_filtered_without_changing_plan() -> None:
    config = ScanConfig(
        scope=ScanScope(ScanTarget("example.com")),
        requested_outputs=(PipelineStateKey.ENDPOINTS,),
        disabled_capabilities=(CapabilityId("risk_intelligence"),),
    )

    prepared = prepare_scan(config=config, registry=create_default_registry())

    assert CapabilityId("risk_intelligence") not in prepared.allowed_capabilities
    assert prepared.plan.required_capabilities == (
        "subdomain_discovery",
        "host_resolution",
        "http_probe",
        "web_crawl",
    )


@pytest.mark.parametrize(
    "disabled",
    ("technology_detection", "host_resolution", "risk_intelligence"),
)
def test_required_disabled_capability_fails_before_build_or_execution(
    disabled: str,
) -> None:
    config = ScanConfig.for_full_assessment(
        "example.com",
        disabled_capabilities=(CapabilityId(disabled),),
    )

    with pytest.raises(DisabledCapabilityError, match=disabled):
        prepare_scan(config=config, registry=create_default_registry())


def test_unknown_disabled_capability_is_rejected() -> None:
    config = ScanConfig.for_reconnaissance(
        "example.com",
        disabled_capabilities=(CapabilityId("custom_unknown"),),
    )

    with pytest.raises(ScanConfigurationError, match="not registered"):
        prepare_scan(config=config, registry=create_default_registry())


def test_initial_context_contains_only_canonical_target() -> None:
    config = ScanConfig.for_full_assessment("BÜCHER.example.")

    context = create_initial_context(config)

    assert context.target_id == "xn--bcher-kva.example"
    assert context.state == {}
    assert context.config == {}
    assert context.metadata == {}
    with pytest.raises(FrozenInstanceError):
        context.target_id = "changed.example"  # type: ignore[misc]


def test_invalid_value_cannot_seed_initial_context() -> None:
    with pytest.raises(TypeError, match="ScanConfig"):
        create_initial_context(object())  # type: ignore[arg-type]


def test_public_models_have_no_tool_runtime_or_secret_fields() -> None:
    names = {
        item.name
        for model in (ScanTarget, ScanScope, ScanLimits, ScanConfig, PreparedScan)
        for item in fields(model)
    }
    forbidden = {
        "tool_id",
        "executable",
        "arguments",
        "argv",
        "provider",
        "runner",
        "context",
        "password",
        "credential",
        "cookie",
        "proxy",
        "output_path",
    }

    assert names.isdisjoint(forbidden)
