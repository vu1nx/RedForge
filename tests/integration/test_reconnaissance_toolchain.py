"""Golden offline reconnaissance through the real adapter boundaries."""

import json
from pathlib import Path

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters import (
    HTTPX_TOOL_ID,
    KATANA_TOOL_ID,
    SUBFINDER_TOOL_ID,
    WHATWEB_TOOL_ID,
    HttpxProbeProvider,
    KatanaWebCrawlProvider,
    SubfinderSubdomainProvider,
    WhatWebTechnologyDetectionProvider,
)
from redforge.application import ScanConfig
from redforge.composition import (
    ApplicationComposition,
    CompositionProfile,
    CompositionProviders,
)
from redforge.observability import DiagnosticEvent, DiagnosticEventType
from redforge.sdk import (
    PipelineStateKey,
    Status,
    ToolDefinition,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolId,
    ToolInvocation,
)
from redforge.testing import FakeToolRunner


class StaticResolver:
    """Offline host-resolution port with deterministic canonical addresses."""

    def resolve(self, hostname: str) -> tuple[str, ...]:
        return {
            "api.authorized.example": ("192.0.2.10",),
            "app.authorized.example": ("2001:db8::10",),
        }[hostname]


class RecordingSink:
    def __init__(self) -> None:
        self._events: list[DiagnosticEvent] = []

    def emit(self, event: DiagnosticEvent) -> None:
        self._events.append(event)

    @property
    def events(self) -> tuple[DiagnosticEvent, ...]:
        return tuple(self._events)


class FixtureToolRunner:
    """ToolRunner-compatible fixture harness that never starts a process."""

    def __init__(self, whatweb_output: str) -> None:
        self._fake = FakeToolRunner()
        self._whatweb_output = whatweb_output

    @property
    def invocations(self) -> tuple[ToolInvocation, ...]:
        return self._fake.invocations

    def add_result(
        self,
        tool_id: ToolId,
        result: ToolExecutionResult,
    ) -> None:
        self._fake.add_result(tool_id, result)

    def is_available(self, definition: ToolDefinition) -> bool:
        return self._fake.is_available(definition)

    def run(
        self,
        definition: ToolDefinition,
        invocation: ToolInvocation,
    ) -> ToolExecutionResult:
        result = self._fake.run(definition, invocation)
        if definition.tool_id == WHATWEB_TOOL_ID:
            output_argument = next(
                item
                for item in invocation.arguments
                if item.startswith("--log-json=")
            )
            Path(output_argument.removeprefix("--log-json=")).write_text(
                self._whatweb_output,
                encoding="utf-8",
            )
        return result


def _result(
    tool_id: ToolId,
    stdout: str = "",
    *,
    status: ToolExecutionStatus = ToolExecutionStatus.SUCCESS,
    exit_code: int | None = 0,
) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_id=tool_id,
        status=status,
        exit_code=exit_code,
        stdout=stdout,
        stderr="adversarial stderr must remain private",
        duration_seconds=0.0,
        timed_out=status is ToolExecutionStatus.TIMEOUT,
    )


def _runner() -> FixtureToolRunner:
    whatweb = json.dumps(
        [
            {
                "target": "https://api.authorized.example/v1",
                "plugins": {
                    "nginx": {
                        "version": ["1.25"],
                        "certainty": 100,
                    }
                },
            },
            {
                "target": "https://app.authorized.example/login",
                "plugins": {
                    "Django": {
                        "version": ["5.0"],
                        "certainty": 90,
                    }
                },
            },
        ]
    )
    runner = FixtureToolRunner(whatweb)
    runner.add_result(
        SUBFINDER_TOOL_ID,
        _result(
            SUBFINDER_TOOL_ID,
            '{"host":"app.authorized.example"}\n'
            '{"host":"api.authorized.example"}\n',
        ),
    )
    runner.add_result(
        HTTPX_TOOL_ID,
        _result(
            HTTPX_TOOL_ID,
            '{"url":"https://api.authorized.example","status_code":200}\n'
            '{"url":"https://app.authorized.example","status_code":200}\n',
        ),
    )
    runner.add_result(
        KATANA_TOOL_ID,
        _result(
            KATANA_TOOL_ID,
            '{"request":{"method":"GET","endpoint":'
            '"https://api.authorized.example/v1"}}\n'
            '{"request":{"method":"GET","endpoint":'
            '"https://app.authorized.example/login"}}\n',
        ),
    )
    runner.add_result(WHATWEB_TOOL_ID, _result(WHATWEB_TOOL_ID))
    return runner


def _composition(
    runner: FixtureToolRunner,
    sink: RecordingSink | None = None,
) -> ApplicationComposition:
    return ApplicationComposition(
        CompositionProfile.RECONNAISSANCE,
        providers=CompositionProviders(
            subdomain_provider=SubfinderSubdomainProvider(runner=runner),
            host_resolver=StaticResolver(),
            http_transport=HttpxProbeProvider(runner=runner),
            web_crawler=KatanaWebCrawlProvider(runner=runner),
            technology_detector=WhatWebTechnologyDetectionProvider(
                runner=runner
            ),
        ),
        diagnostic_sink=sink or RecordingSink(),
    )


def test_golden_reconnaissance_uses_real_parsers_without_process_or_network() -> None:
    runner = _runner()
    sink = RecordingSink()

    result = _composition(runner, sink).create_orchestrator().run(
        ScanConfig.for_reconnaissance("authorized.example")
    )

    assert result.runtime_status is Status.SUCCESS
    assert result.accepted
    assert result.pipeline_result.executed_capabilities == (
        "subdomain_discovery",
        "host_resolution",
        "http_probe",
        "web_crawl",
        "technology_detection",
    )
    assert tuple(invocation.tool_id for invocation in runner.invocations) == (
        SUBFINDER_TOOL_ID,
        HTTPX_TOOL_ID,
        KATANA_TOOL_ID,
        WHATWEB_TOOL_ID,
    )
    assert tuple(result.final_context.state) == (
        PipelineStateKey.SUBDOMAINS,
        PipelineStateKey.HOSTS,
        PipelineStateKey.ALIVE_HOSTS,
        PipelineStateKey.HTTP_ENDPOINTS,
        PipelineStateKey.ENDPOINTS,
        PipelineStateKey.TECHNOLOGIES,
    )
    technologies = result.final_context.state[
        PipelineStateKey.TECHNOLOGIES
    ]
    assert tuple(item.name for item in technologies) == ("nginx", "Django")
    assert sink.events[0].event_type is (
        DiagnosticEventType.SCAN_PREPARATION_STARTED
    )
    assert sink.events[-1].event_type is (
        DiagnosticEventType.SCAN_RESULT_CREATED
    )
    assert all(
        "adversarial stderr" not in repr(event) for event in sink.events
    )


@pytest.mark.parametrize(
    "status",
    (
        ToolExecutionStatus.NOT_FOUND,
        ToolExecutionStatus.FAILURE,
        ToolExecutionStatus.TIMEOUT,
        ToolExecutionStatus.ERROR,
    ),
)
def test_terminal_first_tool_failure_prevents_later_invocations(
    status: ToolExecutionStatus,
) -> None:
    runner = FixtureToolRunner("[]")
    runner.add_result(
        SUBFINDER_TOOL_ID,
        _result(
            SUBFINDER_TOOL_ID,
            status=status,
            exit_code=1 if status is ToolExecutionStatus.FAILURE else None,
        ),
    )

    result = _composition(runner).create_orchestrator().run(
        ScanConfig.for_reconnaissance("authorized.example")
    )

    assert not result.accepted
    assert result.runtime_status in {Status.FAILURE, Status.ERROR}
    assert tuple(invocation.tool_id for invocation in runner.invocations) == (
        SUBFINDER_TOOL_ID,
    )
