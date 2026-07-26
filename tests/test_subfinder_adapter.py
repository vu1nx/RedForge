"""Tests for the ToolRunner-backed passive Subfinder provider."""

from dataclasses import FrozenInstanceError, fields

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters import (
    SUBFINDER_TOOL,
    SUBFINDER_TOOL_ID,
    SubfinderConfig,
    SubfinderSubdomainProvider,
    create_default_tool_registry,
)
from redforge.sdk import (
    SubdomainDiscoveryStatus,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolId,
)
from redforge.testing import FakeToolRunner


def _result(
    status: ToolExecutionStatus,
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int | None = None,
    timed_out: bool = False,
    truncated: bool = False,
) -> ToolExecutionResult:
    if exit_code is None and status is ToolExecutionStatus.SUCCESS:
        exit_code = 0
    return ToolExecutionResult(
        tool_id=SUBFINDER_TOOL_ID,
        status=status,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0,
        timed_out=timed_out,
        truncated=truncated,
    )


def _provider(
    result: ToolExecutionResult,
    *,
    config: SubfinderConfig | None = None,
) -> tuple[SubfinderSubdomainProvider, FakeToolRunner]:
    runner = FakeToolRunner()
    runner.add_result(SUBFINDER_TOOL_ID, result)
    return (
        SubfinderSubdomainProvider(runner=runner, config=config),
        runner,
    )


def test_canonical_definition_and_registry_are_static() -> None:
    registry = create_default_tool_registry()

    assert ToolId("subfinder") == SUBFINDER_TOOL_ID
    assert SUBFINDER_TOOL.tool_id is SUBFINDER_TOOL_ID
    assert SUBFINDER_TOOL.executable == "subfinder"
    assert SUBFINDER_TOOL.version_argument == ("-version",)
    assert SUBFINDER_TOOL.default_timeout_seconds == 600.0
    assert SUBFINDER_TOOL.tags == ("passive", "recon", "subdomain")
    assert registry.require(SUBFINDER_TOOL_ID) is SUBFINDER_TOOL
    assert registry.ids() == (ToolId("httpx"), SUBFINDER_TOOL_ID)
    assert not hasattr(SUBFINDER_TOOL, "runner")
    assert not hasattr(SUBFINDER_TOOL, "capability")


def test_default_configuration_is_immutable_and_narrow() -> None:
    config = SubfinderConfig()

    assert config.timeout_seconds is None
    assert config.max_enumeration_minutes is None
    assert config.rate_limit_per_second is None
    assert config.sources == ()
    assert config.excluded_sources == ()
    assert not config.recursive
    assert not config.use_all_sources
    assert tuple(field.name for field in fields(SubfinderConfig)) == (
        "timeout_seconds",
        "max_enumeration_minutes",
        "rate_limit_per_second",
        "sources",
        "excluded_sources",
        "recursive",
        "use_all_sources",
    )
    with pytest.raises(FrozenInstanceError):
        config.recursive = True  # type: ignore[misc]


def test_configuration_normalizes_sources_and_builds_exact_argv() -> None:
    config = SubfinderConfig(
        timeout_seconds=30,
        max_enumeration_minutes=5,
        rate_limit_per_second=20,
        sources=["Github", "crtsh"],
        excluded_sources=["ZoomeyeAPI", "alienvault"],
        recursive=True,
    )
    provider, _ = _provider(
        _result(ToolExecutionStatus.SUCCESS),
        config=config,
    )

    invocation = provider.build_invocation("Example.COM.")

    assert config.sources == ("crtsh", "github")
    assert config.excluded_sources == ("alienvault", "zoomeyeapi")
    assert invocation.tool_id == SUBFINDER_TOOL_ID
    assert invocation.timeout_seconds == 30.0
    assert invocation.arguments == (
        "-d",
        "example.com",
        "-json",
        "-silent",
        "-disable-update-check",
        "-max-time",
        "5",
        "-rl",
        "20",
        "-recursive",
        "-s",
        "crtsh,github",
        "-es",
        "alienvault,zoomeyeapi",
    )
    assert "-active" not in invocation.arguments
    assert "-o" not in invocation.arguments
    assert "-update" not in invocation.arguments


def test_all_sources_has_deterministic_flag_position() -> None:
    provider, _ = _provider(
        _result(ToolExecutionStatus.SUCCESS),
        config=SubfinderConfig(use_all_sources=True),
    )

    assert provider.build_invocation("example.com").arguments == (
        "-d",
        "example.com",
        "-json",
        "-silent",
        "-disable-update-check",
        "-all",
    )


@pytest.mark.parametrize(
    "arguments",
    (
        {"timeout_seconds": 0},
        {"timeout_seconds": float("inf")},
        {"max_enumeration_minutes": 0},
        {"rate_limit_per_second": -1},
        {"sources": ("bad source",)},
        {"sources": ("github", "Github")},
        {
            "sources": ("github",),
            "excluded_sources": ("github",),
        },
        {"sources": ("github",), "use_all_sources": True},
    ),
)
def test_configuration_rejects_invalid_or_contradictory_values(
    arguments: dict[str, object],
) -> None:
    with pytest.raises((TypeError, ValueError)):
        SubfinderConfig(**arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "domain",
    (
        "https://example.com",
        "http://example.com/path",
        "example.com:443",
        "example.com/path",
        "example.com?x=1",
        "example.com#fragment",
        "*.example.com",
        "example.com;whoami",
        "$(whoami)",
        "example..com",
        " example.com",
        "127.0.0.1",
    ),
)
def test_invalid_domain_never_invokes_runner(domain: str) -> None:
    provider, runner = _provider(_result(ToolExecutionStatus.SUCCESS))

    result = provider.discover(domain)

    assert result.status is SubdomainDiscoveryStatus.ERROR
    assert result.message == "Subdomain discovery target is invalid."
    assert runner.invocations == ()


@pytest.mark.parametrize(
    ("domain", "normalized"),
    (
        ("example.com", "example.com"),
        ("api.example.com", "api.example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
    ),
)
def test_valid_domain_normalization_is_used_in_invocation(
    domain: str,
    normalized: str,
) -> None:
    provider, _ = _provider(_result(ToolExecutionStatus.SUCCESS))

    invocation = provider.build_invocation(domain)

    assert invocation.arguments[1] == normalized


def test_jsonl_normalizes_deduplicates_and_ignores_unknown_fields() -> None:
    stdout = "\n".join(
        (
            '{"host":"B.Example.COM","source":"crtsh","unknown":{"x":1}}',
            "",
            '{"host":"a.example.com.","source":"github"}',
            '{"host":"b.example.com","source":"dnsdumpster"}',
            "",
        )
    )
    provider, _ = _provider(
        _result(ToolExecutionStatus.SUCCESS, stdout=stdout)
    )

    result = provider.discover("example.com")

    assert result.status is SubdomainDiscoveryStatus.SUCCESS
    assert result.hostnames == ("a.example.com", "b.example.com")
    assert result.duplicate_count == 1
    assert result.malformed_record_count == 0
    assert result.out_of_scope_count == 0


def test_partial_malformed_jsonl_preserves_valid_findings() -> None:
    stdout = "\n".join(
        (
            '{"host":"api.example.com"}',
            "{malformed",
            '["not","an","object"]',
            '{"domain":"missing-host.example.com"}',
            '{"host":7}',
            '{"host":"*.example.com"}',
            '{"host":"https://url.example.com"}',
            '{"host":"192.0.2.1"}',
            '{"host":"bad\\u0001.example.com"}',
            "",
        )
    )
    provider, _ = _provider(
        _result(ToolExecutionStatus.SUCCESS, stdout=stdout)
    )

    result = provider.discover("example.com")

    assert result.status is SubdomainDiscoveryStatus.PARTIAL
    assert result.hostnames == ("api.example.com",)
    assert result.malformed_record_count == 8
    assert "api.example.com" not in (result.message or "")


def test_incomplete_final_line_is_malformed() -> None:
    provider, _ = _provider(
        _result(
            ToolExecutionStatus.TIMEOUT,
            stdout='{"host":"api.example.com"}\n{"host":"lost.example.com"}',
            timed_out=True,
        )
    )

    result = provider.discover("example.com")

    assert result.status is SubdomainDiscoveryStatus.PARTIAL
    assert result.hostnames == ("api.example.com",)
    assert result.malformed_record_count == 1


def test_successful_complete_json_record_does_not_require_terminal_newline() -> None:
    provider, _ = _provider(
        _result(
            ToolExecutionStatus.SUCCESS,
            stdout='{"host":"api.example.com"}',
        )
    )

    result = provider.discover("example.com")

    assert result.status is SubdomainDiscoveryStatus.SUCCESS
    assert result.hostnames == ("api.example.com",)


def test_scope_filter_uses_label_boundary_and_excludes_root() -> None:
    candidates = (
        "api.example.com",
        "deep.api.example.com",
        "example.com",
        "notexample.com",
        "fakeexample.com",
        "example.com.attacker.test",
        "api.example.com.attacker.test",
    )
    stdout = "".join(f'{{"host":"{host}"}}\n' for host in candidates)
    provider, _ = _provider(
        _result(ToolExecutionStatus.SUCCESS, stdout=stdout)
    )

    result = provider.discover("example.com")

    assert result.status is SubdomainDiscoveryStatus.PARTIAL
    assert result.hostnames == (
        "api.example.com",
        "deep.api.example.com",
    )
    assert result.out_of_scope_count == 5


def test_empty_success_is_successful_empty_discovery() -> None:
    provider, _ = _provider(_result(ToolExecutionStatus.SUCCESS))

    result = provider.discover("example.com")

    assert result.status is SubdomainDiscoveryStatus.SUCCESS
    assert result.hostnames == ()
    assert result.message is None


def test_only_malformed_or_out_of_scope_output_is_failure() -> None:
    provider, _ = _provider(
        _result(
            ToolExecutionStatus.SUCCESS,
            stdout='{"host":"other.test"}\nnot-json\n',
        )
    )

    result = provider.discover("example.com")

    assert result.status is SubdomainDiscoveryStatus.FAILURE
    assert result.hostnames == ()
    assert result.malformed_record_count == 1
    assert result.out_of_scope_count == 1


@pytest.mark.parametrize(
    ("tool_result", "expected_status", "expected_message"),
    (
        (
            _result(ToolExecutionStatus.FAILURE, exit_code=2),
            SubdomainDiscoveryStatus.FAILURE,
            "Subfinder returned a non-zero exit status.",
        ),
        (
            _result(
                ToolExecutionStatus.TIMEOUT,
                timed_out=True,
            ),
            SubdomainDiscoveryStatus.FAILURE,
            "Subfinder enumeration timed out.",
        ),
        (
            _result(ToolExecutionStatus.NOT_FOUND),
            SubdomainDiscoveryStatus.UNAVAILABLE,
            "Subfinder executable is unavailable.",
        ),
        (
            _result(ToolExecutionStatus.ERROR),
            SubdomainDiscoveryStatus.ERROR,
            "Subfinder execution failed.",
        ),
    ),
)
def test_tool_status_mapping_is_sanitized(
    tool_result: ToolExecutionResult,
    expected_status: SubdomainDiscoveryStatus,
    expected_message: str,
) -> None:
    provider, _ = _provider(tool_result)

    result = provider.discover("example.com")

    assert result.status is expected_status
    assert result.message == expected_message
    assert result.hostnames == ()


def test_timeout_with_complete_partial_jsonl_preserves_findings() -> None:
    provider, _ = _provider(
        _result(
            ToolExecutionStatus.TIMEOUT,
            stdout='{"host":"api.example.com"}\n',
            timed_out=True,
        )
    )

    result = provider.discover("example.com")

    assert result.status is SubdomainDiscoveryStatus.PARTIAL
    assert result.hostnames == ("api.example.com",)
    assert result.message == (
        "Subfinder enumeration timed out with partial findings."
    )


def test_truncation_marks_valid_output_partial() -> None:
    provider, _ = _provider(
        _result(
            ToolExecutionStatus.SUCCESS,
            stdout='{"host":"api.example.com"}\n',
            truncated=True,
        )
    )

    result = provider.discover("example.com")

    assert result.status is SubdomainDiscoveryStatus.PARTIAL
    assert result.hostnames == ("api.example.com",)
    assert result.truncated


def test_sensitive_stderr_is_not_copied_to_provider_diagnostics() -> None:
    provider, _ = _provider(
        _result(
            ToolExecutionStatus.FAILURE,
            stderr="api-key=secret-token C:\\private\\provider",
            exit_code=3,
        )
    )

    result = provider.discover("example.com")

    rendered = repr(result)
    assert "secret-token" not in rendered
    assert "private" not in rendered
