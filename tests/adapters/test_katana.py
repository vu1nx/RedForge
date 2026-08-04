"""ToolRunner-backed Katana provider contract tests."""

from dataclasses import FrozenInstanceError, fields
from ipaddress import IPv4Address, IPv6Address

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters import (
    HTTPX_TOOL_ID,
    KATANA_TOOL,
    KATANA_TOOL_ID,
    SUBFINDER_TOOL_ID,
    WHATWEB_TOOL_ID,
    KatanaConfig,
    KatanaWebCrawlProvider,
    create_default_tool_registry,
)
from redforge.domain.endpoint import Endpoint
from redforge.domain.host import Host
from redforge.sdk import ToolExecutionResult, ToolExecutionStatus, ToolId
from redforge.sdk.web_crawl import WebCrawlProviderStatus
from redforge.testing import FakeToolRunner


def _host(
    hostname: str | None = "api.example.com",
    *,
    address: IPv4Address | IPv6Address | None = IPv4Address("192.0.2.10"),
) -> Host:
    return Host(hostname=hostname, address=address)


def _tool_result(
    *,
    status: ToolExecutionStatus = ToolExecutionStatus.SUCCESS,
    stdout: str = "",
    stderr: str = "",
    exit_code: int | None = 0,
    truncated: bool = False,
) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_id=KATANA_TOOL_ID,
        status=status,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0,
        timed_out=status is ToolExecutionStatus.TIMEOUT,
        truncated=truncated,
    )


def _provider(result: ToolExecutionResult) -> tuple[KatanaWebCrawlProvider, FakeToolRunner]:
    runner = FakeToolRunner()
    runner.add_result(KATANA_TOOL_ID, result)
    return KatanaWebCrawlProvider(runner=runner), runner


def _json(url: str, *, method: str = "GET") -> str:
    return (
        '{"request":{"method":"'
        f'{method}","endpoint":"{url}"'
        '}}'
    )


def test_tool_identity_definition_and_default_registry() -> None:
    assert ToolId("katana") == KATANA_TOOL_ID
    assert KATANA_TOOL.tool_id is KATANA_TOOL_ID
    assert KATANA_TOOL.executable == "katana"
    assert KATANA_TOOL.version_argument == ("-version",)
    assert KATANA_TOOL.default_timeout_seconds == 120.0
    assert KATANA_TOOL.tags == ("crawl", "recon", "web")
    assert create_default_tool_registry().ids() == (
        HTTPX_TOOL_ID,
        KATANA_TOOL_ID,
        ToolId("nuclei"),
        SUBFINDER_TOOL_ID,
        WHATWEB_TOOL_ID,
    )
    assert not hasattr(KATANA_TOOL, "runner")
    with pytest.raises(FrozenInstanceError):
        KATANA_TOOL.tags = ()  # type: ignore[misc]


def test_config_is_frozen_slotted_bounded_and_has_no_unsafe_options() -> None:
    config = KatanaConfig()
    assert not hasattr(config, "__dict__")
    assert tuple(item.name for item in fields(KatanaConfig)) == (
        "timeout_seconds",
        "depth",
        "crawl_duration_seconds",
        "request_timeout_seconds",
        "concurrency",
        "parallelism",
        "rate_limit_per_second",
        "max_response_bytes",
    )
    with pytest.raises(FrozenInstanceError):
        config.depth = 3  # type: ignore[misc]
    for forbidden in (
        "extra_args",
        "headers",
        "cookies",
        "credentials",
        "proxy",
        "config_path",
        "output_path",
        "resume_path",
        "headless",
    ):
        assert not hasattr(config, forbidden)


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("timeout_seconds", 0),
        ("timeout_seconds", float("inf")),
        ("depth", 0),
        ("crawl_duration_seconds", 0),
        ("request_timeout_seconds", 0),
        ("concurrency", 0),
        ("parallelism", 0),
        ("rate_limit_per_second", 0),
        ("max_response_bytes", 0),
    ),
)
def test_config_rejects_invalid_limits(field_name: str, value: object) -> None:
    with pytest.raises(ValueError):
        KatanaConfig(**{field_name: value})  # type: ignore[arg-type]


def test_invocation_is_exact_safe_deterministic_and_uses_stdin() -> None:
    provider, _ = _provider(_tool_result())
    hosts = (
        _host("API.Example.COM."),
        _host("api.example.com"),
        _host(None, address=IPv6Address("2001:db8::10")),
    )

    invocation = provider.build_invocation(hosts)

    assert invocation.tool_id is KATANA_TOOL_ID
    assert invocation.arguments == (
        "-jsonl",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-omit-raw",
        "-omit-body",
        "-retry",
        "0",
        "-depth",
        "2",
        "-crawl-duration",
        "30s",
        "-timeout",
        "10",
        "-concurrency",
        "5",
        "-parallelism",
        "2",
        "-rate-limit",
        "20",
        "-max-response-size",
        "1048576",
        "-field-scope",
        "fqdn",
    )
    assert invocation.stdin == (
        "http://[2001:db8::10]\n"
        "http://api.example.com\n"
        "https://[2001:db8::10]\n"
        "https://api.example.com\n"
    )
    rendered = " ".join(invocation.arguments)
    for forbidden in (
        "headless",
        "screenshot",
        "store-response",
        "-output",
        "-config",
        "-resume",
        "-headers",
        "-proxy",
        "form",
        "js-crawl",
    ):
        assert forbidden not in rendered


def test_idna_seed_normalization_and_invalid_host_rejection() -> None:
    provider, _ = _provider(_tool_result())
    invocation = provider.build_invocation(
        (_host("BÜCHER.Example.", address=None),)
    )
    assert invocation.stdin == (
        "http://xn--bcher-kva.example\n"
        "https://xn--bcher-kva.example\n"
    )

    result = provider.crawl((Host(hostname="invalid"),))
    assert result.status is WebCrawlProviderStatus.ERROR
    assert result.message == "Web crawl input is invalid."


def test_empty_input_skips_runner() -> None:
    runner = FakeToolRunner()
    result = KatanaWebCrawlProvider(runner=runner).crawl(())
    assert result.status is WebCrawlProviderStatus.SUCCESS
    assert result.endpoints == ()
    assert runner.invocations == ()


def test_clean_empty_output_is_success_after_one_invocation() -> None:
    provider, runner = _provider(_tool_result(stdout=""))
    result = provider.crawl((_host(),))
    assert result.status is WebCrawlProviderStatus.SUCCESS
    assert result.endpoints == ()
    assert len(runner.invocations) == 1


def test_valid_jsonl_normalizes_paths_queries_ips_and_deduplicates() -> None:
    stdout = "\n".join(
        (
            _json("HTTPS://API.Example.COM:443"),
            _json("https://api.example.com/users"),
            _json("https://api.example.com/search?q=one"),
            _json("https://api.example.com/users"),
            '{"request":{"method":"GET",'
            '"endpoint":"https://api.example.com/unknown"},'
            '"unknown":{"raw":"ignored"}}',
            "",
        )
    )
    provider, runner = _provider(_tool_result(stdout=stdout))

    result = provider.crawl((_host(),))

    assert result.status is WebCrawlProviderStatus.SUCCESS
    assert result.endpoints == (
        Endpoint("api.example.com", 443, "https", "/"),
        Endpoint("api.example.com", 443, "https", "/search?q=one"),
        Endpoint("api.example.com", 443, "https", "/unknown"),
        Endpoint("api.example.com", 443, "https", "/users"),
    )
    assert result.duplicate_count == 1
    assert len(runner.invocations) == 1


def test_top_level_url_compatibility_and_explicit_port() -> None:
    provider, _ = _provider(
        _tool_result(
            stdout='{"url":"https://api.example.com:8443/admin"}\n'
        )
    )
    result = provider.crawl((_host(),))
    assert result.endpoints == (
        Endpoint("api.example.com", 8443, "https", "/admin"),
    )


def test_exact_scope_rejects_suffix_confusion_and_external_hosts() -> None:
    stdout = "\n".join(
        _json(url)
        for url in (
            "https://api.example.com/",
            "https://notexample.com/",
            "https://api.example.com.attacker.test/",
            "https://attacker.test/",
        )
    ) + "\n"
    provider, _ = _provider(_tool_result(stdout=stdout))

    result = provider.crawl((_host(),))

    assert result.status is WebCrawlProviderStatus.PARTIAL
    assert result.endpoints == (
        Endpoint("api.example.com", 443, "https", "/"),
    )
    assert result.out_of_scope_count == 3


def test_only_out_of_scope_records_are_failure() -> None:
    provider, _ = _provider(
        _tool_result(stdout=_json("https://attacker.test/") + "\n")
    )
    result = provider.crawl((_host(),))
    assert result.status is WebCrawlProviderStatus.FAILURE
    assert result.endpoints == ()
    assert result.out_of_scope_count == 1


@pytest.mark.parametrize(
    "url",
    (
        "ftp://api.example.com/file",
        "file://api.example.com/file",
        "javascript://api.example.com/",
        "data://api.example.com/",
        "ws://api.example.com/",
        "mailto://api.example.com/",
        "https://user:secret@api.example.com/",
        "https://api.example.com/path#fragment",
        "https://api.example.com/?token=secret",
    ),
)
def test_unsafe_urls_are_rejected_without_payload_leak(url: str) -> None:
    provider, _ = _provider(_tool_result(stdout=_json(url) + "\n"))
    result = provider.crawl((_host(),))
    assert result.status is WebCrawlProviderStatus.FAILURE
    assert result.endpoints == ()
    assert url not in repr(result)


def test_malformed_records_preserve_valid_partial_evidence() -> None:
    provider, _ = _provider(
        _tool_result(
            stdout=(
                _json("https://api.example.com/valid")
                + "\nnot-json\n[]\n{}\n"
                + _json("https://api.example.com/post", method="POST")
                + "\n"
            )
        )
    )
    result = provider.crawl((_host(),))
    assert result.status is WebCrawlProviderStatus.PARTIAL
    assert result.endpoints == (
        Endpoint("api.example.com", 443, "https", "/valid"),
    )
    assert result.malformed_record_count == 4


def test_truncated_unterminated_final_line_is_discarded() -> None:
    provider, _ = _provider(
        _tool_result(
            stdout=(
                _json("https://api.example.com/complete")
                + "\n"
                + '{"request":{"endpoint":"https://api.example.com/incomplete'
            ),
            truncated=True,
        )
    )
    result = provider.crawl((_host(),))
    assert result.status is WebCrawlProviderStatus.PARTIAL
    assert result.endpoints == (
        Endpoint("api.example.com", 443, "https", "/complete"),
    )
    assert result.malformed_record_count == 1


@pytest.mark.parametrize(
    ("tool_result", "expected_status", "message"),
    (
        (
            _tool_result(
                status=ToolExecutionStatus.FAILURE,
                exit_code=2,
                stderr="Authorization: secret C:\\private",
            ),
            WebCrawlProviderStatus.FAILURE,
            "Katana returned a non-zero exit status.",
        ),
        (
            _tool_result(
                status=ToolExecutionStatus.TIMEOUT,
                exit_code=None,
            ),
            WebCrawlProviderStatus.FAILURE,
            "Web crawling timed out.",
        ),
        (
            _tool_result(
                status=ToolExecutionStatus.NOT_FOUND,
                exit_code=None,
            ),
            WebCrawlProviderStatus.UNAVAILABLE,
            "Katana executable is unavailable.",
        ),
        (
            _tool_result(
                status=ToolExecutionStatus.ERROR,
                exit_code=None,
            ),
            WebCrawlProviderStatus.ERROR,
            "Katana execution failed.",
        ),
    ),
)
def test_tool_statuses_map_to_sanitized_provider_results(
    tool_result: ToolExecutionResult,
    expected_status: WebCrawlProviderStatus,
    message: str,
) -> None:
    provider, _ = _provider(tool_result)
    result = provider.crawl((_host(),))
    assert result.status is expected_status
    assert result.message == message
    assert "Authorization" not in repr(result)
    assert "private" not in repr(result)


def test_timeout_with_complete_endpoint_is_partial() -> None:
    provider, _ = _provider(
        _tool_result(
            status=ToolExecutionStatus.TIMEOUT,
            exit_code=None,
            stdout=_json("https://api.example.com/partial") + "\n",
        )
    )
    result = provider.crawl((_host(),))
    assert result.status is WebCrawlProviderStatus.PARTIAL
    assert result.endpoints == (
        Endpoint("api.example.com", 443, "https", "/partial"),
    )


def test_ipv4_and_ipv6_scope_and_normalization() -> None:
    ipv4_provider, _ = _provider(
        _tool_result(stdout=_json("http://192.0.2.10/path") + "\n")
    )
    ipv4 = ipv4_provider.crawl((_host(None),))
    assert ipv4.endpoints == (
        Endpoint("192.0.2.10", 80, "http", "/path"),
    )

    ipv6_provider, _ = _provider(
        _tool_result(stdout=_json("https://[2001:0db8::10]/v6") + "\n")
    )
    ipv6 = ipv6_provider.crawl(
        (_host(None, address=IPv6Address("2001:db8::10")),)
    )
    assert ipv6.endpoints == (
        Endpoint("2001:db8::10", 443, "https", "/v6"),
    )
