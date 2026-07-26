"""Planned execution through Subfinder, resolution, HTTPX, and downstream ports."""

from typing import cast

from redforge.adapters import HTTPX_TOOL_ID, SUBFINDER_TOOL_ID
from redforge.adapters.katana import WebCrawlAdapterResult
from redforge.adapters.technology_detection import TechnologyDetectionResult
from redforge.domain.endpoint import Endpoint
from redforge.domain.host import Host
from redforge.domain.http_probe import HttpProbeEndpoint
from redforge.domain.technology import Technology
from redforge.planning import (
    HOST_RESOLUTION,
    HTTP_PROBE,
    SUBDOMAIN_DISCOVERY,
    TECHNOLOGY_DETECTION,
    WEB_CRAWL,
    CapabilityDependencies,
    create_default_planned_execution,
)
from redforge.sdk import (
    Context,
    PipelineStateKey,
    Status,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from redforge.testing import FakeToolRunner


class RecordingResolver:
    """Resolve one deterministic address and retain invocation order."""

    def __init__(self) -> None:
        self.hostnames: list[str] = []

    def resolve(self, hostname: str) -> tuple[str, ...]:
        self.hostnames.append(hostname)
        return ("192.0.2.10",)


class RecordingCrawler:
    """Return one deterministic endpoint for responsive host URLs."""

    def __init__(self) -> None:
        self.inputs: list[tuple[Host, ...]] = []

    def crawl(self, hosts: tuple[Host, ...]) -> WebCrawlAdapterResult:
        self.inputs.append(hosts)
        return WebCrawlAdapterResult(
            endpoints=(
                Endpoint(
                    host="api.example.com",
                    port=443,
                    protocol="https",
                    path="/",
                ),
            )
        )


class RecordingDetector:
    """Return one technology while recording crawler endpoint input."""

    def __init__(self) -> None:
        self.inputs: list[tuple[Endpoint, ...]] = []

    def detect(
        self,
        endpoints: tuple[Endpoint, ...],
    ) -> TechnologyDetectionResult:
        self.inputs.append(endpoints)
        return TechnologyDetectionResult(
            technologies=(
                Technology(
                    name="nginx",
                    category="web-server",
                    source="https://api.example.com/",
                ),
            )
        )


def _runner(httpx_stdout: str) -> FakeToolRunner:
    runner = FakeToolRunner()
    runner.add_result(
        SUBFINDER_TOOL_ID,
        ToolExecutionResult(
            tool_id=SUBFINDER_TOOL_ID,
            status=ToolExecutionStatus.SUCCESS,
            exit_code=0,
            stdout='{"host":"api.example.com"}\n',
            stderr="",
            duration_seconds=0,
        ),
    )
    runner.add_result(
        HTTPX_TOOL_ID,
        ToolExecutionResult(
            tool_id=HTTPX_TOOL_ID,
            status=ToolExecutionStatus.SUCCESS,
            exit_code=0,
            stdout=httpx_stdout,
            stderr="",
            duration_seconds=0,
        ),
    )
    return runner


def test_planned_http_probe_uses_three_typed_capability_steps() -> None:
    runner = _runner(
        '{"url":"HTTPS://API.Example.COM","status_code":404,'
        '"host_ip":"192.0.2.10"}\n'
    )
    resolver = RecordingResolver()
    execution = create_default_planned_execution(
        dependencies=CapabilityDependencies(
            tool_runner=runner,
            host_resolver=resolver,
        )
    )
    context = Context(target_id="example.com")

    plan = execution.plan(
        goals=(PipelineStateKey.ALIVE_HOSTS,),
        context=context,
    )
    result = execution.execute(plan=plan, context=context)

    assert plan.required_capability_ids == (
        SUBDOMAIN_DISCOVERY,
        HOST_RESOLUTION,
        HTTP_PROBE,
    )
    assert result.status is Status.SUCCESS
    assert result.executed_capabilities == (
        "subdomain_discovery",
        "host_resolution",
        "http_probe",
    )
    assert tuple(item.tool_id for item in runner.invocations) == (
        SUBFINDER_TOOL_ID,
        HTTPX_TOOL_ID,
    )
    assert runner.invocations[1].stdin == "api.example.com\n"
    alive_hosts = result.context.get(PipelineStateKey.ALIVE_HOSTS)
    assert isinstance(alive_hosts, tuple)
    typed_alive_hosts = tuple(
        host
        for host in cast(tuple[object, ...], alive_hosts)
        if isinstance(host, Host)
    )
    assert tuple(host.hostname for host in typed_alive_hosts) == (
        "api.example.com",
    )
    assert result.context.get(PipelineStateKey.HTTP_ENDPOINTS) == (
        HttpProbeEndpoint(
            url="https://api.example.com",
            scheme="https",
            hostname="api.example.com",
            port=443,
            status_code=404,
            ip_address="192.0.2.10",
        ),
    )
    assert resolver.hostnames == ["api.example.com"]
    assert len(result.executions) == 3
    assert tuple(item.capability_id for item in result.executions) == (
        SUBDOMAIN_DISCOVERY,
        HOST_RESOLUTION,
        HTTP_PROBE,
    )


def test_downstream_crawl_and_technology_detection_remain_separate() -> None:
    runner = _runner(
        '{"url":"https://api.example.com","status_code":200}\n'
    )
    resolver = RecordingResolver()
    crawler = RecordingCrawler()
    detector = RecordingDetector()
    execution = create_default_planned_execution(
        dependencies=CapabilityDependencies(
            tool_runner=runner,
            host_resolver=resolver,
            web_crawler=crawler,
            technology_detector=detector,
        )
    )

    result = execution.run(
        goals=(PipelineStateKey.TECHNOLOGIES,),
        initial_context=Context(target_id="example.com"),
    )

    assert result.status is Status.SUCCESS
    assert tuple(item.capability_id for item in result.executions) == (
        SUBDOMAIN_DISCOVERY,
        HOST_RESOLUTION,
        HTTP_PROBE,
        WEB_CRAWL,
        TECHNOLOGY_DETECTION,
    )
    assert len(crawler.inputs) == 1
    assert tuple(host.hostname for host in crawler.inputs[0]) == (
        "api.example.com",
    )
    assert detector.inputs == [
        (Endpoint("api.example.com", 443, "https", "/"),)
    ]
    assert len(runner.invocations) == 2


def test_empty_successful_http_probe_flows_through_downstream_stages() -> None:
    runner = _runner("")
    crawler = RecordingCrawler()
    detector = RecordingDetector()
    execution = create_default_planned_execution(
        dependencies=CapabilityDependencies(
            tool_runner=runner,
            host_resolver=RecordingResolver(),
            web_crawler=crawler,
            technology_detector=detector,
        )
    )

    result = execution.run(
        goals=(PipelineStateKey.TECHNOLOGIES,),
        initial_context=Context(target_id="example.com"),
    )

    assert result.status is Status.SUCCESS
    assert result.context.get(PipelineStateKey.ALIVE_HOSTS) == ()
    assert result.context.get(PipelineStateKey.HTTP_ENDPOINTS) == ()
    assert result.context.get(PipelineStateKey.ENDPOINTS) == ()
    assert result.context.get(PipelineStateKey.TECHNOLOGIES) == ()
    assert crawler.inputs == []
    assert detector.inputs == []
