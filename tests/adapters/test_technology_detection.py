"""Tests for the ToolRunner-backed WhatWeb provider."""

import json
import os
import stat
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters import (
    HTTPX_TOOL_ID,
    KATANA_TOOL_ID,
    SUBFINDER_TOOL_ID,
    WHATWEB_TOOL,
    WHATWEB_TOOL_ID,
    WhatWebConfig,
    WhatWebTechnologyDetectionProvider,
    create_default_tool_registry,
)
from redforge.domain.endpoint import Endpoint
from redforge.sdk import (
    TechnologyDetectionProviderStatus,
    ToolDefinition,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolId,
    ToolInvocation,
)
from redforge.testing import FakeToolRunner

FIXTURE_PATH = (
    Path(__file__).parents[1] / "fixtures" / "whatweb" / "multiple_targets.json"
)


def _result(
    *,
    stdout: str = "",
    status: ToolExecutionStatus = ToolExecutionStatus.SUCCESS,
    exit_code: int | None = 0,
    truncated: bool = False,
) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_id=WHATWEB_TOOL_ID,
        status=status,
        exit_code=exit_code,
        stdout=stdout,
        stderr="Authorization: secret C:\\private\\whatweb",
        duration_seconds=0,
        timed_out=status is ToolExecutionStatus.TIMEOUT,
        truncated=truncated,
    )


def _provider(
    result: ToolExecutionResult,
    *,
    config: WhatWebConfig | None = None,
) -> tuple[WhatWebTechnologyDetectionProvider, FakeToolRunner]:
    runner = FakeToolRunner()
    runner.add_result(WHATWEB_TOOL_ID, result)
    return (
        WhatWebTechnologyDetectionProvider(runner=runner, config=config),
        runner,
    )


def _endpoints() -> tuple[Endpoint, ...]:
    return (
        Endpoint("www.example.com", 443, "https", "/"),
        Endpoint("api.example.com", 443, "https", "/v1"),
    )


def _output_path(invocation: ToolInvocation) -> Path:
    return Path(invocation.arguments[0].removeprefix("--log-json="))


def test_tool_identity_definition_and_registry_coexistence() -> None:
    registry = create_default_tool_registry()

    assert ToolId("whatweb") == WHATWEB_TOOL_ID
    assert WHATWEB_TOOL.tool_id is WHATWEB_TOOL_ID
    assert WHATWEB_TOOL.executable == "whatweb"
    assert WHATWEB_TOOL.version_argument == ("--version",)
    assert WHATWEB_TOOL.default_timeout_seconds == 120
    assert WHATWEB_TOOL.tags == ("fingerprint", "technology", "web")
    assert registry.ids() == (
        HTTPX_TOOL_ID,
        KATANA_TOOL_ID,
        SUBFINDER_TOOL_ID,
        WHATWEB_TOOL_ID,
    )
    assert registry.require(WHATWEB_TOOL_ID) is WHATWEB_TOOL


def test_configuration_is_frozen_slotted_and_has_no_expansive_fields() -> None:
    config = WhatWebConfig()

    assert config == WhatWebConfig(
        timeout_seconds=None,
        open_timeout_seconds=10,
        read_timeout_seconds=15,
        max_threads=10,
        max_targets=256,
        max_input_bytes=65_536,
        max_output_bytes=1_048_576,
        max_records=10_000,
    )
    with pytest.raises(FrozenInstanceError):
        config.max_threads = 20  # type: ignore[misc]
    assert not hasattr(config, "__dict__")
    names = {field.name for field in fields(WhatWebConfig)}
    assert not names.intersection(
        {
            "extra_args",
            "headers",
            "cookies",
            "credentials",
            "proxy",
            "config_path",
            "output_path",
            "plugin_path",
        }
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_seconds", 0),
        ("timeout_seconds", float("inf")),
        ("open_timeout_seconds", 0),
        ("read_timeout_seconds", 601),
        ("max_threads", 0),
        ("max_targets", 0),
        ("max_input_bytes", 0),
        ("max_output_bytes", 0),
        ("max_records", 0),
    ],
)
def test_configuration_rejects_invalid_bounds(field: str, value: object) -> None:
    with pytest.raises(ValueError, match="WhatWeb"):
        WhatWebConfig(**{field: value})  # type: ignore[arg-type]


def test_exact_invocation_and_deterministic_target_arguments() -> None:
    provider, runner = _provider(_result(stdout="[]"))
    endpoints = (
        Endpoint("2001:0db8::10", 443, "https", "/nested?q=one"),
        Endpoint("bücher.example", 80, "http", "/"),
        Endpoint("bücher.example", 80, "http", "/"),
    )

    response = provider.detect(endpoints)
    invocation = runner.invocations[0]

    assert response.status is TechnologyDetectionProviderStatus.SUCCESS
    assert invocation.tool_id is WHATWEB_TOOL_ID
    assert invocation.timeout_seconds is None
    assert invocation.stdin is None
    assert invocation.arguments[0].startswith("--log-json=")
    output_path = _output_path(invocation)
    assert output_path.name.startswith("redforge-whatweb-")
    assert output_path.suffix == ".json"
    assert not output_path.exists()
    assert invocation.arguments[1:] == (
        "--quiet",
        "--colour=never",
        "--no-errors",
        "--no-cookies",
        "--aggression=1",
        "--follow-redirect=never",
        "--max-redirects=0",
        "--max-threads=10",
        "--open-timeout=10",
        "--read-timeout=15",
        "http://xn--bcher-kva.example/",
        "https://[2001:db8::10]/nested?q=one",
    )
    forbidden = (
        "--header",
        "--cookie",
        "--proxy",
        "--plugins",
        "--custom-plugin",
        "--update",
    )
    assert not any(
        argument.startswith(forbidden)
        for argument in invocation.arguments
    )


def test_ipv4_default_port_and_explicit_port_serialization() -> None:
    provider, runner = _provider(_result(stdout="[]"))

    response = provider.detect(
        (
            Endpoint("192.0.2.10", 80, "http", "/"),
            Endpoint("api.example.com", 8443, "https", "/admin"),
        )
    )

    assert response.status is TechnologyDetectionProviderStatus.SUCCESS
    assert runner.invocations[0].arguments[-2:] == (
        "http://192.0.2.10/",
        "https://api.example.com:8443/admin",
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        Endpoint("example.com", 443, "ftp", "/"),
        Endpoint("user@example.com", 443, "https", "/"),
        Endpoint("example.com", 443, "https", "relative"),
        Endpoint("example.com", 443, "https", "/path#fragment"),
        Endpoint("example.com ", 443, "https", "/"),
        Endpoint("example.com", 443, "https", "/bad path"),
    ],
)
def test_invalid_targets_fail_without_execution(endpoint: Endpoint) -> None:
    provider, runner = _provider(_result())

    response = provider.detect((endpoint,))

    assert response.status is TechnologyDetectionProviderStatus.ERROR
    assert runner.invocations == ()


def test_target_count_and_input_size_are_bounded() -> None:
    provider, runner = _provider(
        _result(),
        config=WhatWebConfig(max_targets=1, max_input_bytes=24),
    )

    response = provider.detect(
        (
            Endpoint("one.example", 443, "https", "/"),
            Endpoint("two.example", 443, "https", "/"),
        )
    )

    assert response.status is TechnologyDetectionProviderStatus.ERROR
    assert runner.invocations == ()


def test_realistic_json_normalizes_typed_evidence() -> None:
    provider, runner = _provider(
        _result(stdout=FIXTURE_PATH.read_text(encoding="utf-8"))
    )

    response = provider.detect(_endpoints())

    assert response.status is TechnologyDetectionProviderStatus.SUCCESS
    assert len(runner.invocations) == 1
    nginx = next(
        technology
        for technology in response.technologies
        if technology.name == "nginx"
        and technology.source == "https://www.example.com/"
    )
    assert nginx.version == "1.24.0"
    assert nginx.category == "web-server"
    assert nginx.confidence == 100
    assert nginx.evidence == ("string: nginx/1.24.0",)
    assert {
        technology.source
        for technology in response.technologies
        if technology.name == "nginx"
    } == {
        "https://www.example.com/",
        "https://api.example.com/v1",
    }
    assert not _output_path(runner.invocations[0]).exists()


class FileWritingRunner:
    """Write WhatWeb JSON to the adapter-created private result file."""

    def __init__(self, output: str) -> None:
        self.output = output
        self.output_path: Path | None = None
        self.private_permissions = False

    def run(
        self,
        definition: ToolDefinition,
        invocation: ToolInvocation,
    ) -> ToolExecutionResult:
        assert definition is WHATWEB_TOOL
        self.output_path = _output_path(invocation)
        assert self.output_path.is_file()
        assert not self.output_path.is_symlink()
        self.private_permissions = (
            True
            if os.name == "nt"
            else stat.S_IMODE(self.output_path.stat().st_mode) & 0o077 == 0
        )
        self.output_path.write_text(self.output, encoding="utf-8")
        return _result()

    def is_available(self, definition: ToolDefinition) -> bool:
        return definition is WHATWEB_TOOL


def test_private_json_file_is_read_and_cleaned_after_success() -> None:
    runner = FileWritingRunner(FIXTURE_PATH.read_text(encoding="utf-8"))
    provider = WhatWebTechnologyDetectionProvider(runner=runner)

    response = provider.detect(_endpoints())

    assert response.status is TechnologyDetectionProviderStatus.SUCCESS
    assert response.technologies
    assert runner.output_path is not None
    assert runner.private_permissions
    assert not runner.output_path.exists()


def test_oversized_private_json_file_is_rejected_and_cleaned() -> None:
    runner = FileWritingRunner(
        '[{"target":"https://www.example.com/","plugins":{}}]'
    )
    provider = WhatWebTechnologyDetectionProvider(
        runner=runner,
        config=WhatWebConfig(max_output_bytes=32),
    )

    response = provider.detect(
        (Endpoint("www.example.com", 443, "https", "/"),)
    )

    assert response.status is TechnologyDetectionProviderStatus.FAILURE
    assert response.truncated
    assert runner.output_path is not None
    assert not runner.output_path.exists()


def test_unknown_fields_are_ignored_and_duplicates_are_counted() -> None:
    record = {
        "target": "https://www.example.com/",
        "unknown": {"raw": "ignored"},
        "plugins": {"nginx": {"version": ["1.24", "1.24"]}},
    }
    provider, _ = _provider(_result(stdout=json.dumps([record, record])))

    response = provider.detect((Endpoint("www.example.com", 443, "https", "/"),))

    assert response.status is TechnologyDetectionProviderStatus.SUCCESS
    assert len(response.technologies) == 1
    assert response.duplicate_count == 1


@pytest.mark.parametrize(
    "target",
    [
        "https://notexample.com/",
        "https://www.example.com.attacker.test/",
        "https://attacker.test/",
        "https://www.example.com/other",
    ],
)
def test_exact_target_association_rejects_unknown_targets(target: str) -> None:
    output = json.dumps(
        [{"target": target, "plugins": {"nginx": {"version": ["1.24"]}}}]
    )
    provider, runner = _provider(_result(stdout=output))

    response = provider.detect(
        (Endpoint("www.example.com", 443, "https", "/"),)
    )

    assert response.status is TechnologyDetectionProviderStatus.FAILURE
    assert response.technologies == ()
    assert response.out_of_scope_count == 1
    assert not _output_path(runner.invocations[0]).exists()


@pytest.mark.parametrize(
    "output",
    [
        "{not-json",
        "{}",
        "[null]",
        '[{"plugins": {}}]',
        '[{"target": "https://www.example.com/", "plugins": []}]',
        (
            '[{"target":"https://www.example.com/",'
            '"plugins":{"nginx":{"certainty":101}}}]'
        ),
        (
            '[{"target":"https://www.example.com/",'
            '"plugins":{"nginx":{"version":42}}}]'
        ),
        (
            '[{"target":"https://www.example.com/",'
            '"plugins":{"":{"version":["1.0"]}}}]'
        ),
    ],
)
def test_malformed_or_unusable_output_is_failure(output: str) -> None:
    provider, runner = _provider(_result(stdout=output))

    response = provider.detect(
        (Endpoint("www.example.com", 443, "https", "/"),)
    )

    assert response.status is TechnologyDetectionProviderStatus.FAILURE
    assert response.technologies == ()
    assert response.malformed_record_count >= 1
    assert not _output_path(runner.invocations[0]).exists()


def test_clean_empty_output_is_success() -> None:
    provider, _ = _provider(_result(stdout="[]"))

    response = provider.detect(_endpoints())

    assert response.status is TechnologyDetectionProviderStatus.SUCCESS
    assert response.technologies == ()


def test_valid_plus_malformed_output_is_partial() -> None:
    output = json.dumps(
        [
            {
                "target": "https://www.example.com/",
                "plugins": {"nginx": {"version": ["1.24"]}},
            },
            None,
        ]
    )
    provider, _ = _provider(_result(stdout=output))

    response = provider.detect(
        (Endpoint("www.example.com", 443, "https", "/"),)
    )

    assert response.status is TechnologyDetectionProviderStatus.PARTIAL
    assert len(response.technologies) == 1
    assert response.malformed_record_count == 1


@pytest.mark.parametrize(
    ("status", "exit_code", "expected"),
    [
        (
            ToolExecutionStatus.FAILURE,
            2,
            TechnologyDetectionProviderStatus.FAILURE,
        ),
        (
            ToolExecutionStatus.NOT_FOUND,
            None,
            TechnologyDetectionProviderStatus.UNAVAILABLE,
        ),
        (
            ToolExecutionStatus.ERROR,
            None,
            TechnologyDetectionProviderStatus.ERROR,
        ),
    ],
)
def test_tool_status_mapping(
    status: ToolExecutionStatus,
    exit_code: int | None,
    expected: TechnologyDetectionProviderStatus,
) -> None:
    provider, runner = _provider(_result(status=status, exit_code=exit_code))

    response = provider.detect(_endpoints())

    assert response.status is expected
    assert "Authorization" not in repr(response)
    assert "private" not in repr(response)
    assert not _output_path(runner.invocations[0]).exists()


def test_timeout_with_complete_evidence_is_partial() -> None:
    output = json.dumps(
        [
            {
                "target": "https://www.example.com/",
                "plugins": {"nginx": {"version": ["1.24"]}},
            }
        ]
    )
    provider, runner = _provider(
        _result(
            stdout=output,
            status=ToolExecutionStatus.TIMEOUT,
            exit_code=None,
        )
    )

    response = provider.detect(
        (Endpoint("www.example.com", 443, "https", "/"),)
    )

    assert response.status is TechnologyDetectionProviderStatus.PARTIAL
    assert len(response.technologies) == 1
    assert not _output_path(runner.invocations[0]).exists()


def test_timeout_without_evidence_is_failure() -> None:
    provider, runner = _provider(
        _result(
            stdout="",
            status=ToolExecutionStatus.TIMEOUT,
            exit_code=None,
        )
    )

    response = provider.detect(_endpoints())

    assert response.status is TechnologyDetectionProviderStatus.FAILURE
    assert not _output_path(runner.invocations[0]).exists()


def test_truncated_complete_output_with_evidence_is_partial() -> None:
    output = json.dumps(
        [
            {
                "target": "https://www.example.com/",
                "plugins": {"nginx": {}},
            }
        ]
    )
    provider, _ = _provider(_result(stdout=output, truncated=True))

    response = provider.detect(
        (Endpoint("www.example.com", 443, "https", "/"),)
    )

    assert response.status is TechnologyDetectionProviderStatus.PARTIAL
    assert response.truncated


def test_truncated_incomplete_output_is_failure() -> None:
    provider, _ = _provider(
        _result(
            stdout='[{"target":"https://www.example.com/"',
            truncated=True,
        )
    )

    response = provider.detect(
        (Endpoint("www.example.com", 443, "https", "/"),)
    )

    assert response.status is TechnologyDetectionProviderStatus.FAILURE
    assert response.technologies == ()
    assert response.truncated


def test_empty_input_skips_tool_execution() -> None:
    provider, runner = _provider(_result())

    response = provider.detect(())

    assert response.status is TechnologyDetectionProviderStatus.SUCCESS
    assert response.technologies == ()
    assert runner.invocations == ()


class RaisingRunner:
    """Runner double whose sensitive exception must not escape."""

    def __init__(self) -> None:
        self.output_path: Path | None = None

    def run(
        self,
        definition: ToolDefinition,
        invocation: ToolInvocation,
    ) -> ToolExecutionResult:
        del definition
        self.output_path = _output_path(invocation)
        raise RuntimeError("Authorization secret C:\\private\\whatweb")

    def is_available(self, definition: ToolDefinition) -> bool:
        del definition
        return True


def test_runner_exception_is_sanitized() -> None:
    runner = RaisingRunner()
    provider = WhatWebTechnologyDetectionProvider(runner=runner)

    response = provider.detect(_endpoints())

    assert response.status is TechnologyDetectionProviderStatus.ERROR
    assert "Authorization" not in repr(response)
    assert "private" not in repr(response)
    assert runner.output_path is not None
    assert not runner.output_path.exists()
