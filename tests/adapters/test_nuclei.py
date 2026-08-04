"""Offline tests for Nuclei invocation construction and JSONL parsing."""

import json

from redforge.adapters import (
    NUCLEI_TOOL,
    NUCLEI_TOOL_ID,
    NucleiConfig,
    NucleiVulnerabilityDetectionProvider,
    create_default_tool_registry,
)
from redforge.domain.http_probe import HttpProbeEndpoint
from redforge.sdk import (
    FindingSeverity,
    ToolExecutionResult,
    ToolExecutionStatus,
    VulnerabilityDetectionStatus,
)
from redforge.testing import FakeToolRunner


def _endpoint(url: str = "https://example.test/") -> HttpProbeEndpoint:
    return HttpProbeEndpoint(
        url=url,
        scheme="https",
        hostname="example.test",
        port=443,
        status_code=200,
        ip_address="192.0.2.1",
    )


def _record(
    *,
    template_id: str = "http-missing-header",
    host: str = "https://example.test/",
    title: str = "Missing Security Header",
    severity: str = "medium",
) -> str:
    return json.dumps(
        {
            "template-id": template_id,
            "info": {
                "name": title,
                "severity": severity,
                "classification": {"cvss-score": 9.9},
            },
            "type": "http",
            "host": host,
            "matched-at": f"{host}admin",
            "matcher-name": "header",
            "request": "Authorization: secret",
            "response": "private response",
            "template-path": "/private/nuclei-template.yaml",
        }
    )


def _result(
    stdout: str,
    *,
    status: ToolExecutionStatus = ToolExecutionStatus.SUCCESS,
    exit_code: int | None = 0,
    truncated: bool = False,
) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_id=NUCLEI_TOOL_ID,
        status=status,
        exit_code=exit_code,
        stdout=stdout,
        stderr="private stderr",
        duration_seconds=0,
        timed_out=status is ToolExecutionStatus.TIMEOUT,
        truncated=truncated,
    )


def _provider(
    result: ToolExecutionResult,
    *,
    config: NucleiConfig | None = None,
) -> tuple[NucleiVulnerabilityDetectionProvider, FakeToolRunner]:
    runner = FakeToolRunner()
    runner.add_result(NUCLEI_TOOL_ID, result)
    return (
        NucleiVulnerabilityDetectionProvider(runner=runner, config=config),
        runner,
    )


def test_tool_definition_and_default_registry() -> None:
    assert NUCLEI_TOOL.tool_id == NUCLEI_TOOL_ID
    assert NUCLEI_TOOL.executable_candidates == ("nuclei",)
    assert NUCLEI_TOOL.version_argument == ("-version",)
    assert create_default_tool_registry().require(NUCLEI_TOOL_ID) is NUCLEI_TOOL


def test_invocation_is_deterministic_stdin_fed_and_omits_raw_evidence() -> None:
    provider, _ = _provider(_result(""))

    invocation = provider.build_invocation((_endpoint(),))

    assert invocation.tool_id == NUCLEI_TOOL_ID
    assert invocation.stdin == "https://example.test/\n"
    assert invocation.arguments == (
        "-jsonl",
        "-silent",
        "-no-color",
        "-omit-raw",
        "-omit-template",
        "-disable-update-check",
        "-no-interactsh",
        "-no-httpx",
        "-retries",
        "0",
        "-timeout",
        "10",
        "-rate-limit",
        "50",
        "-concurrency",
        "10",
    )


def test_clean_multiple_findings_are_normalized_and_deduplicated() -> None:
    output = "\n".join(
        (_record(template_id="finding-b"), _record(template_id="finding-a"))
    )
    provider, runner = _provider(_result(f"{output}\n"))

    result = provider.detect((_endpoint(),))

    assert result.status is VulnerabilityDetectionStatus.SUCCESS
    assert len(result.findings) == 2
    assert tuple(
        item.template.template_id.value for item in result.findings
    ) == ("finding-a", "finding-b")
    assert all(
        item.severity is FindingSeverity.MEDIUM for item in result.findings
    )
    assert len(runner.invocations) == 1
    assert "secret" not in repr(result)
    assert "/private/" not in repr(result)

    duplicate_provider, _ = _provider(
        _result(f"{_record()}\n{_record()}\n")
    )
    duplicate_result = duplicate_provider.detect((_endpoint(),))
    assert len(duplicate_result.findings) == 1
    assert duplicate_result.duplicate_count == 1
    assert duplicate_result.status is VulnerabilityDetectionStatus.SUCCESS


def test_conflicting_duplicate_selection_is_deterministic_and_partial() -> None:
    first = _record(title="Z finding", severity="high")
    second = _record(title="A finding", severity="low")
    forward_provider, _ = _provider(_result(f"{first}\n{second}\n"))
    reverse_provider, _ = _provider(_result(f"{second}\n{first}\n"))

    forward = forward_provider.detect((_endpoint(),))
    reverse = reverse_provider.detect((_endpoint(),))

    assert forward == reverse
    assert forward.status is VulnerabilityDetectionStatus.PARTIAL
    assert forward.malformed_record_count == 1
    assert forward.duplicate_count == 1
    assert forward.findings.findings[0].title == "A finding"


def test_empty_malformed_mixed_and_unassociated_output_semantics() -> None:
    empty_provider, _ = _provider(_result(""))
    assert (
        empty_provider.detect((_endpoint(),)).status
        is VulnerabilityDetectionStatus.SUCCESS
    )

    malformed_provider, _ = _provider(_result("{broken}\n"))
    malformed = malformed_provider.detect((_endpoint(),))
    assert malformed.status is VulnerabilityDetectionStatus.FAILURE
    assert malformed.malformed_record_count == 1

    mixed_provider, _ = _provider(
        _result(f"{_record()}\n{{broken}}\n")
    )
    mixed = mixed_provider.detect((_endpoint(),))
    assert mixed.status is VulnerabilityDetectionStatus.PARTIAL
    assert len(mixed.findings) == 1

    other_provider, _ = _provider(
        _result(f"{_record(host='https://other.test/')}\n")
    )
    other = other_provider.detect((_endpoint(),))
    assert other.status is VulnerabilityDetectionStatus.FAILURE
    assert other.unassociated_record_count == 1


def test_endpoint_association_requires_exact_scheme_host_port_and_path() -> None:
    endpoint = HttpProbeEndpoint(
        url="http://example.test:8080/base",
        scheme="http",
        hostname="example.test",
        port=8080,
        status_code=200,
        ip_address="192.0.2.1",
    )
    valid_provider, _ = _provider(
        _result(f"{_record(host='http://example.test:8080/base')}\n")
    )
    wrong_port_provider, _ = _provider(
        _result(f"{_record(host='http://example.test/base')}\n")
    )
    wrong_path_provider, _ = _provider(
        _result(f"{_record(host='http://example.test:8080/other')}\n")
    )

    assert (
        valid_provider.detect((endpoint,)).status
        is VulnerabilityDetectionStatus.SUCCESS
    )
    for provider in (wrong_port_provider, wrong_path_provider):
        result = provider.detect((endpoint,))
        assert result.status is VulnerabilityDetectionStatus.FAILURE
        assert result.unassociated_record_count == 1


def test_timeout_failure_and_output_limits_fail_without_evidence() -> None:
    timeout_provider, _ = _provider(
        _result(
            "",
            status=ToolExecutionStatus.TIMEOUT,
            exit_code=None,
        )
    )
    assert (
        timeout_provider.detect((_endpoint(),)).status
        is VulnerabilityDetectionStatus.FAILURE
    )

    failed_provider, _ = _provider(
        _result(
            "",
            status=ToolExecutionStatus.FAILURE,
            exit_code=2,
        )
    )
    assert (
        failed_provider.detect((_endpoint(),)).status
        is VulnerabilityDetectionStatus.FAILURE
    )

    limited_provider, _ = _provider(
        _result(f"{_record()}\n"),
        config=NucleiConfig(max_output_bytes=8),
    )
    limited = limited_provider.detect((_endpoint(),))
    assert limited.status is VulnerabilityDetectionStatus.FAILURE
    assert limited.truncated is True


def test_missing_executable_maps_to_unavailable_without_output_leakage() -> None:
    provider, _ = _provider(
        _result(
            "",
            status=ToolExecutionStatus.NOT_FOUND,
            exit_code=None,
        )
    )

    result = provider.detect((_endpoint(),))

    assert result.status is VulnerabilityDetectionStatus.UNAVAILABLE
    assert len(result.findings) == 0
    assert result.message == "Nuclei executable is unavailable."
    assert "private stderr" not in repr(result)


def test_empty_endpoints_do_not_invoke_runner() -> None:
    runner = FakeToolRunner()
    provider = NucleiVulnerabilityDetectionProvider(runner=runner)

    result = provider.detect(())

    assert result.status is VulnerabilityDetectionStatus.SUCCESS
    assert len(result.findings) == 0
    assert runner.invocations == ()


def test_runner_exception_is_sanitized_error() -> None:
    provider = NucleiVulnerabilityDetectionProvider(runner=FakeToolRunner())

    result = provider.detect((_endpoint(),))

    assert result.status is VulnerabilityDetectionStatus.ERROR
    assert result.message == "Nuclei execution failed."
