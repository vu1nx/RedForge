"""Tests for the ToolRunner-backed HTTPX probe provider."""

from dataclasses import FrozenInstanceError, fields
from ipaddress import IPv4Address, IPv6Address

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters import (
    HTTPX_TOOL,
    HTTPX_TOOL_ID,
    HttpxConfig,
    HttpxProbeProvider,
    create_default_tool_registry,
)
from redforge.domain.host import Host
from redforge.domain.http_probe import normalize_http_url
from redforge.sdk import ToolExecutionResult, ToolExecutionStatus, ToolId
from redforge.sdk.http_probe import HttpProbeProviderStatus
from redforge.testing import FakeToolRunner


def _tool_result(
    status: ToolExecutionStatus,
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int | None = None,
    truncated: bool = False,
) -> ToolExecutionResult:
    if status is ToolExecutionStatus.SUCCESS and exit_code is None:
        exit_code = 0
    return ToolExecutionResult(
        tool_id=HTTPX_TOOL_ID,
        status=status,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0,
        timed_out=status is ToolExecutionStatus.TIMEOUT,
        truncated=truncated,
    )


def _provider(
    result: ToolExecutionResult,
    *,
    config: HttpxConfig | None = None,
) -> tuple[HttpxProbeProvider, FakeToolRunner]:
    runner = FakeToolRunner()
    runner.add_result(HTTPX_TOOL_ID, result)
    return HttpxProbeProvider(runner=runner, config=config), runner


def _host(
    hostname: str | None = "api.example.com",
    address: str = "192.0.2.10",
) -> Host:
    parsed = IPv6Address(address) if ":" in address else IPv4Address(address)
    return Host(hostname=hostname, address=parsed)


def _json(
    *,
    url: str = "https://api.example.com",
    status_code: object = 200,
    **extra: object,
) -> str:
    import json

    return json.dumps({"url": url, "status_code": status_code, **extra})


def test_canonical_definition_and_default_registry() -> None:
    registry = create_default_tool_registry()

    assert ToolId("httpx") == HTTPX_TOOL_ID
    assert HTTPX_TOOL.executable == "httpx-toolkit"
    assert HTTPX_TOOL.executable_candidates == ("httpx-toolkit", "httpx")
    assert HTTPX_TOOL.identity_output_pattern is not None
    assert HTTPX_TOOL.version_argument == ("-version",)
    assert HTTPX_TOOL.default_timeout_seconds == 300
    assert HTTPX_TOOL.tags == ("http", "probe", "recon")
    assert registry.require(HTTPX_TOOL_ID) is HTTPX_TOOL
    assert registry.require(
        ToolId("subfinder")
    ).executable_candidates == ("subfinder",)
    assert registry.require(
        ToolId("katana")
    ).executable_candidates == ("katana",)
    assert registry.require(
        ToolId("whatweb")
    ).executable_candidates == ("whatweb",)

    with pytest.raises(FrozenInstanceError):
        HTTPX_TOOL.tags = ()  # type: ignore[misc]


def test_default_configuration_is_narrow_immutable_and_slotted() -> None:
    config = HttpxConfig()

    assert tuple(field.name for field in fields(HttpxConfig)) == (
        "timeout_seconds",
        "request_timeout_seconds",
        "threads",
        "rate_limit_per_second",
        "follow_redirects",
        "probe_all_ips",
    )
    assert config == HttpxConfig(
        timeout_seconds=None,
        request_timeout_seconds=None,
        threads=None,
        rate_limit_per_second=None,
        follow_redirects=False,
        probe_all_ips=False,
    )
    assert not hasattr(config, "__dict__")
    assert not hasattr(config, "extra_args")
    assert not hasattr(config, "headers")
    assert not hasattr(config, "credentials")
    with pytest.raises(FrozenInstanceError):
        config.threads = 2  # type: ignore[misc]


@pytest.mark.parametrize(
    "arguments",
    (
        {"timeout_seconds": 0},
        {"timeout_seconds": float("inf")},
        {"request_timeout_seconds": 0},
        {"request_timeout_seconds": True},
        {"threads": -1},
        {"rate_limit_per_second": 0},
        {"follow_redirects": 1},
        {"probe_all_ips": "yes"},
    ),
)
def test_invalid_configuration_is_rejected(arguments: dict[str, object]) -> None:
    with pytest.raises((TypeError, ValueError)):
        HttpxConfig(**arguments)  # type: ignore[arg-type]


def test_exact_default_and_optional_invocation_contract() -> None:
    provider, _ = _provider(
        _tool_result(ToolExecutionStatus.SUCCESS),
        config=HttpxConfig(
            timeout_seconds=90,
            request_timeout_seconds=8,
            threads=4,
            rate_limit_per_second=12,
            follow_redirects=True,
            probe_all_ips=True,
        ),
    )
    hosts = (
        _host("Z.Example.COM"),
        _host("api.example.com", "192.0.2.11"),
        _host("api.example.com", "192.0.2.11"),
    )

    invocation = provider.build_invocation(hosts)

    assert invocation.tool_id == HTTPX_TOOL_ID
    assert invocation.arguments == (
        "-json",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-status-code",
        "-content-type",
        "-title",
        "-web-server",
        "-ip",
        "-location",
        "-response-time",
        "-timeout",
        "8",
        "-threads",
        "4",
        "-rate-limit",
        "12",
        "-follow-host-redirects",
        "-probe-all-ips",
    )
    assert invocation.timeout_seconds == 90
    assert invocation.stdin == "api.example.com\nz.example.com\n"
    for forbidden in (
        "-tech-detect",
        "-output",
        "-screenshot",
        "-unsafe",
        "-header",
        "-body",
        "-update",
    ):
        assert forbidden not in invocation.arguments


def test_ip_only_targets_and_ipv6_are_encoded_deterministically() -> None:
    provider, _ = _provider(_tool_result(ToolExecutionStatus.SUCCESS))

    invocation = provider.build_invocation(
        (
            _host(None, "2001:db8::1"),
            _host(None, "192.0.2.2"),
        )
    )

    assert invocation.stdin == "192.0.2.2\n2001:db8::1\n"


@pytest.mark.parametrize(
    "host",
    (
        Host(),
        Host(hostname="https://example.com"),
        Host(hostname="example.com/path"),
        Host(hostname="*.example.com"),
        Host(hostname=" example.com"),
        Host(hostname="example.com;whoami"),
    ),
)
def test_invalid_input_produces_no_tool_invocation(host: Host) -> None:
    provider, runner = _provider(_tool_result(ToolExecutionStatus.SUCCESS))

    result = provider.probe((host,))

    assert result.status is HttpProbeProviderStatus.ERROR
    assert runner.invocations == ()


def test_empty_input_is_success_without_tool_invocation() -> None:
    provider, runner = _provider(_tool_result(ToolExecutionStatus.SUCCESS))

    result = provider.probe(())

    assert result.status is HttpProbeProviderStatus.SUCCESS
    assert result.endpoints == result.responsive_hosts == ()
    assert runner.invocations == ()


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("HTTP://API.Example.COM:80", "http://api.example.com"),
        ("https://api.example.com:8443", "https://api.example.com:8443"),
        ("https://[2001:0db8::1]:443", "https://[2001:db8::1]"),
        ("https://bücher.example", "https://xn--bcher-kva.example"),
    ),
)
def test_url_normalization(value: str, expected: str) -> None:
    assert normalize_http_url(value).value == expected


@pytest.mark.parametrize(
    "value",
    (
        "ftp://api.example.com",
        "file://api.example.com",
        "javascript:alert(1)",
        "https://user:password@api.example.com",
        "https://api.example.com/#fragment",
        " https://api.example.com",
        "https://api.example.com:0",
        "https://api.example.com:70000",
    ),
)
def test_url_normalization_rejects_unsafe_values(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_http_url(value)


def test_valid_jsonl_metadata_normalization_and_duplicate_policy() -> None:
    stdout = "\n".join(
        (
            _json(
                url="HTTPS://API.Example.COM:443",
                status_code=401,
                host_ip="192.0.2.10",
                content_type=" text/html; charset=utf-8 ",
                title=" Login ",
                webserver=" nginx ",
                location="/signin",
                time="250ms",
                unknown={"ignored": True},
            ),
            _json(url="https://api.example.com", status_code=500),
            "",
        )
    )
    provider, _ = _provider(
        _tool_result(ToolExecutionStatus.SUCCESS, stdout=stdout)
    )

    result = provider.probe((_host(),))

    assert result.status is HttpProbeProviderStatus.SUCCESS
    assert len(result.endpoints) == 1
    endpoint = result.endpoints[0]
    assert endpoint.url == "https://api.example.com"
    assert endpoint.status_code == 401
    assert endpoint.ip_address == "192.0.2.10"
    assert endpoint.content_type == "text/html; charset=utf-8"
    assert endpoint.title == "Login"
    assert endpoint.web_server == "nginx"
    assert endpoint.redirect_location == "/signin"
    assert endpoint.response_time_seconds == pytest.approx(0.25)
    assert result.duplicate_count == 1
    assert result.responsive_hosts == (_host(),)


@pytest.mark.parametrize("status_code", (200, 301, 401, 404, 500))
def test_http_status_families_are_valid_probe_evidence(status_code: int) -> None:
    provider, _ = _provider(
        _tool_result(
            ToolExecutionStatus.SUCCESS,
            stdout=_json(status_code=status_code) + "\n",
        )
    )

    result = provider.probe((_host(),))

    assert result.status is HttpProbeProviderStatus.SUCCESS
    assert result.endpoints[0].status_code == status_code


def test_scope_filtering_rejects_unapproved_hosts_and_suffix_traps() -> None:
    stdout = "".join(
        _json(url=url) + "\n"
        for url in (
            "http://api.example.com",
            "https://api.example.com",
            "https://api.example.com:8443",
            "https://notexample.com",
            "https://api.example.com.attacker.test",
            "https://attacker.test",
        )
    )
    provider, _ = _provider(
        _tool_result(ToolExecutionStatus.SUCCESS, stdout=stdout)
    )

    result = provider.probe((_host(),))

    assert result.status is HttpProbeProviderStatus.PARTIAL
    assert tuple(endpoint.url for endpoint in result.endpoints) == (
        "http://api.example.com",
        "https://api.example.com",
        "https://api.example.com:8443",
    )
    assert result.out_of_scope_count == 3


def test_ip_scope_accepts_only_the_approved_ip() -> None:
    provider, _ = _provider(
        _tool_result(
            ToolExecutionStatus.SUCCESS,
            stdout=(
                _json(url="http://192.0.2.10")
                + "\n"
                + _json(url="http://192.0.2.11")
                + "\n"
            ),
        )
    )

    result = provider.probe((_host(None),))

    assert tuple(endpoint.hostname for endpoint in result.endpoints) == (
        "192.0.2.10",
    )
    assert result.out_of_scope_count == 1


def test_ipv6_json_endpoint_uses_bracketed_canonical_url() -> None:
    provider, _ = _provider(
        _tool_result(
            ToolExecutionStatus.SUCCESS,
            stdout=_json(url="https://[2001:0db8::1]:443") + "\n",
        )
    )

    result = provider.probe((_host(None, "2001:db8::1"),))

    assert result.status is HttpProbeProviderStatus.SUCCESS
    assert result.endpoints[0].url == "https://[2001:db8::1]"
    assert result.endpoints[0].hostname == "2001:db8::1"


def test_redirect_metadata_does_not_expand_approved_endpoints() -> None:
    provider, _ = _provider(
        _tool_result(
            ToolExecutionStatus.SUCCESS,
            stdout=(
                _json(
                    location="https://attacker.test/login",
                )
                + "\n"
            ),
        )
    )

    result = provider.probe((_host(),))

    assert len(result.endpoints) == 1
    assert result.endpoints[0].redirect_location == (
        "https://attacker.test/login"
    )
    assert all(
        endpoint.hostname != "attacker.test" for endpoint in result.endpoints
    )


def test_malformed_records_are_partial_when_valid_evidence_exists() -> None:
    stdout = "\n".join(
        (
            _json(),
            "{bad-json",
            '["not","object"]',
            '{"status_code":200}',
            _json(url="ws://api.example.com"),
            _json(status_code="200"),
            _json(status_code=99),
            _json(title=7),
            _json(title="bad\x01title"),
            _json(url="https://user:secret@api.example.com"),
            "",
        )
    )
    provider, _ = _provider(
        _tool_result(ToolExecutionStatus.SUCCESS, stdout=stdout)
    )

    result = provider.probe((_host(),))

    assert result.status is HttpProbeProviderStatus.PARTIAL
    assert len(result.endpoints) == 1
    assert result.malformed_record_count == 9
    assert "api.example.com" not in (result.message or "")


def test_records_without_valid_approved_endpoint_are_failure() -> None:
    provider, _ = _provider(
        _tool_result(
            ToolExecutionStatus.SUCCESS,
            stdout=_json(url="https://other.test") + "\nnot-json\n",
        )
    )

    result = provider.probe((_host(),))

    assert result.status is HttpProbeProviderStatus.FAILURE
    assert result.endpoints == ()
    assert result.out_of_scope_count == 1
    assert result.malformed_record_count == 1


def test_clean_empty_output_is_success() -> None:
    provider, _ = _provider(_tool_result(ToolExecutionStatus.SUCCESS))

    result = provider.probe((_host(),))

    assert result.status is HttpProbeProviderStatus.SUCCESS
    assert result.endpoints == result.responsive_hosts == ()


@pytest.mark.parametrize(
    ("status", "exit_code", "expected", "message"),
    (
        (
            ToolExecutionStatus.FAILURE,
            2,
            HttpProbeProviderStatus.FAILURE,
            "HTTPX returned a non-zero exit status.",
        ),
        (
            ToolExecutionStatus.TIMEOUT,
            None,
            HttpProbeProviderStatus.FAILURE,
            "HTTP probing timed out.",
        ),
        (
            ToolExecutionStatus.NOT_FOUND,
            None,
            HttpProbeProviderStatus.UNAVAILABLE,
            "HTTPX executable is unavailable.",
        ),
        (
            ToolExecutionStatus.ERROR,
            None,
            HttpProbeProviderStatus.ERROR,
            "HTTPX execution failed.",
        ),
    ),
)
def test_tool_status_mapping(
    status: ToolExecutionStatus,
    exit_code: int | None,
    expected: HttpProbeProviderStatus,
    message: str,
) -> None:
    provider, _ = _provider(_tool_result(status, exit_code=exit_code))

    result = provider.probe((_host(),))

    assert result.status is expected
    assert result.message == message


def test_timeout_preserves_only_complete_valid_records() -> None:
    provider, _ = _provider(
        _tool_result(
            ToolExecutionStatus.TIMEOUT,
            stdout=_json() + "\n" + _json(url="http://api.example.com"),
        )
    )

    result = provider.probe((_host(),))

    assert result.status is HttpProbeProviderStatus.PARTIAL
    assert tuple(endpoint.url for endpoint in result.endpoints) == (
        "https://api.example.com",
    )
    assert result.malformed_record_count == 1


def test_truncation_marks_valid_output_partial() -> None:
    provider, _ = _provider(
        _tool_result(
            ToolExecutionStatus.SUCCESS,
            stdout=_json() + "\n",
            truncated=True,
        )
    )

    result = provider.probe((_host(),))

    assert result.status is HttpProbeProviderStatus.PARTIAL
    assert result.truncated is True


def test_successful_final_json_does_not_require_newline() -> None:
    provider, _ = _provider(
        _tool_result(ToolExecutionStatus.SUCCESS, stdout=_json())
    )

    result = provider.probe((_host(),))

    assert result.status is HttpProbeProviderStatus.SUCCESS
    assert len(result.endpoints) == 1


def test_sensitive_stderr_and_outputs_never_leak_to_messages_or_repr() -> None:
    provider, _ = _provider(
        _tool_result(
            ToolExecutionStatus.FAILURE,
            exit_code=1,
            stdout="https://secret.example",
            stderr="Authorization: Bearer token C:\\private\\httpx",
        )
    )

    result = provider.probe((_host(),))
    rendered = repr(result)

    assert "secret.example" not in rendered
    assert "Bearer" not in rendered
    assert "private" not in rendered
