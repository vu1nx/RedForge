"""Offline CLI dry-run contract tests."""

import json
from io import StringIO
from typing import NoReturn, cast

from redforge.application import (
    ReadinessStatus,
    ScanConfig,
    ScanInspection,
)
from redforge.cli import JSON_SCHEMA_VERSION, ExitCode, main
from redforge.composition import ApplicationComposition, CompositionProfile
from redforge.sdk import (
    ReadinessProbeResult,
    ReadinessReason,
    ToolDefinition,
    ToolExecutionResult,
    ToolId,
    ToolInvocation,
)


class NeverExecutingRunner:
    """Valid ToolRunner that fails the test if inspection touches execution."""

    def __init__(self) -> None:
        self.run_calls = 0
        self.availability_calls = 0

    def run(
        self,
        definition: ToolDefinition,
        invocation: ToolInvocation,
    ) -> ToolExecutionResult:
        del definition, invocation
        self.run_calls += 1
        raise AssertionError("dry run must not execute tools")

    def is_available(self, definition: ToolDefinition) -> bool:
        del definition
        self.availability_calls += 1
        raise AssertionError("injected readiness probe must own inspection")


class StaticToolProbe:
    def __init__(self, unavailable: tuple[ToolId, ...] = ()) -> None:
        self.unavailable = unavailable
        self.calls: list[ToolId] = []

    def check(self, definition: ToolDefinition) -> ReadinessProbeResult:
        self.calls.append(definition.tool_id)
        if definition.tool_id in self.unavailable:
            return ReadinessProbeResult(
                ReadinessStatus.UNAVAILABLE,
                ReadinessReason.EXECUTABLE_UNAVAILABLE,
            )
        return ReadinessProbeResult(ReadinessStatus.READY)


class CountingInspector:
    def __init__(self, probe: StaticToolProbe) -> None:
        self.runner = NeverExecutingRunner()
        self.delegate = ApplicationComposition(
            CompositionProfile.RECONNAISSANCE,
            tool_runner=self.runner,
            tool_readiness_probe=probe,
        ).create_inspector()
        self.configs: list[ScanConfig] = []

    def inspect(self, config: ScanConfig) -> ScanInspection:
        self.configs.append(config)
        return self.delegate.inspect(config)


def _must_not_orchestrate() -> NoReturn:
    raise AssertionError("dry run must not construct an orchestrator")


def _run_dry(
    argv: list[str],
    inspector: CountingInspector,
) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    code = main(
        argv,
        inspector_factory=lambda: inspector,
        orchestrator_factory=_must_not_orchestrate,
        stdout=stdout,
        stderr=stderr,
    )
    return code, stdout.getvalue(), stderr.getvalue()


def test_human_dry_run_is_deterministic_and_never_executes() -> None:
    probe = StaticToolProbe()
    inspector = CountingInspector(probe)

    first = _run_dry(
        ["scan", "AUTHORIZED.example.", "--dry-run"],
        inspector,
    )

    assert first[0] == ExitCode.ACCEPTED
    assert first[2] == ""
    assert first[1] == (
        "Dry run completed\n"
        "Target: authorized.example\n"
        "Preset: reconnaissance\n"
        "Composition profile: reconnaissance\n"
        "Ready: yes\n"
        "Planned capabilities:\n"
        "- subdomain_discovery\n"
        "- host_resolution\n"
        "- http_probe\n"
        "- web_crawl\n"
        "- technology_detection\n"
        "Required tools:\n"
        "- subfinder\n"
        "- httpx\n"
        "- katana\n"
        "- whatweb\n"
        "Required providers:\n"
        "- none\n"
    )
    assert len(inspector.configs) == 1
    assert inspector.runner.run_calls == 0
    assert inspector.runner.availability_calls == 0
    assert tuple(item.value for item in probe.calls) == (
        "subfinder",
        "httpx",
        "katana",
        "whatweb",
    )


def test_json_dry_run_is_one_sanitized_document() -> None:
    inspector = CountingInspector(StaticToolProbe())

    code, stdout, stderr = _run_dry(
        [
            "scan",
            "authorized.example",
            "--dry-run",
            "--output",
            "json",
        ],
        inspector,
    )

    payload = cast(dict[str, object], json.loads(stdout))
    assert code == ExitCode.ACCEPTED
    assert stderr == ""
    assert stdout.count("\n") == 1
    assert list(payload) == [
        "schema_version",
        "outcome",
        "exit_code",
        "target",
        "preset",
        "composition_profile",
        "capability_ids",
        "tool_ids",
        "provider_ids",
        "preflight",
    ]
    assert payload["schema_version"] == JSON_SCHEMA_VERSION
    assert payload["outcome"] == "dry_run"
    assert payload["target"] == "authorized.example"
    assert payload["capability_ids"] == [
        "subdomain_discovery",
        "host_resolution",
        "http_probe",
        "web_crawl",
        "technology_detection",
    ]
    assert payload["tool_ids"] == [
        "subfinder",
        "httpx",
        "katana",
        "whatweb",
    ]
    assert payload["provider_ids"] == []
    assert "command" not in stdout
    assert "executable" not in stdout
    assert "environment" not in stdout


def test_non_ready_dry_run_returns_three_without_runtime() -> None:
    inspector = CountingInspector(
        StaticToolProbe((ToolId("katana"),))
    )

    code, stdout, stderr = _run_dry(
        ["scan", "authorized.example", "--dry-run"],
        inspector,
    )

    assert code == ExitCode.NOT_READY
    assert stderr == ""
    assert "Ready: no" in stdout
    assert "katana (executable_unavailable)" in stdout
    assert inspector.runner.run_calls == 0
    assert inspector.runner.availability_calls == 0


def test_invalid_target_stops_before_dry_run_composition() -> None:
    inspector = CountingInspector(StaticToolProbe())

    code, stdout, stderr = _run_dry(
        ["scan", "https://authorized.example", "--dry-run"],
        inspector,
    )

    assert code == ExitCode.INVALID_INPUT
    assert stdout == ""
    assert stderr == "Invalid input: scan target or options are invalid\n"
    assert inspector.configs == []
