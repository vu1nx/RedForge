"""Planned execution through the ToolRunner-backed WhatWeb provider."""

from redforge.adapters import (
    HTTPX_TOOL_ID,
    KATANA_TOOL_ID,
    SUBFINDER_TOOL_ID,
    WHATWEB_TOOL_ID,
)
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
    ToolId,
)
from redforge.testing import FakeToolRunner


class FakeResolver:
    """Resolve one deterministic hostname without network access."""

    def resolve(self, hostname: str) -> tuple[str, ...]:  # noqa: ARG002
        return ("192.0.2.10",)


def _result(tool_id: ToolId, stdout: str) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_id=tool_id,
        status=ToolExecutionStatus.SUCCESS,
        exit_code=0,
        stdout=stdout,
        stderr="",
        duration_seconds=0,
    )


def test_planned_whatweb_execution_uses_one_invocation_and_history_entry() -> None:
    runner = FakeToolRunner()
    runner.add_result(
        SUBFINDER_TOOL_ID,
        _result(
            SUBFINDER_TOOL_ID,
            '{"host":"api.example.com"}\n',
        ),
    )
    runner.add_result(
        HTTPX_TOOL_ID,
        _result(
            HTTPX_TOOL_ID,
            '{"url":"https://api.example.com","status_code":200,'
            '"host_ip":"192.0.2.10"}\n',
        ),
    )
    runner.add_result(
        KATANA_TOOL_ID,
        _result(
            KATANA_TOOL_ID,
            '{"request":{"method":"GET",'
            '"endpoint":"https://api.example.com/users"}}\n',
        ),
    )
    runner.add_result(
        WHATWEB_TOOL_ID,
        _result(
            WHATWEB_TOOL_ID,
            '[{"target":"https://api.example.com/users",'
            '"plugins":{"nginx":{"version":["1.24.0"]}}}]',
        ),
    )
    execution = create_default_planned_execution(
        dependencies=CapabilityDependencies(
            tool_runner=runner,
            host_resolver=FakeResolver(),
        )
    )
    context = Context(target_id="example.com")

    plan = execution.plan(
        goals=(PipelineStateKey.TECHNOLOGIES,),
        context=context,
    )
    result = execution.execute(plan=plan, context=context)

    assert plan.required_capability_ids == (
        SUBDOMAIN_DISCOVERY,
        HOST_RESOLUTION,
        HTTP_PROBE,
        WEB_CRAWL,
        TECHNOLOGY_DETECTION,
    )
    assert result.status is Status.SUCCESS
    assert tuple(item.tool_id for item in runner.invocations) == (
        SUBFINDER_TOOL_ID,
        HTTPX_TOOL_ID,
        KATANA_TOOL_ID,
        WHATWEB_TOOL_ID,
    )
    technologies = result.context.get(PipelineStateKey.TECHNOLOGIES)
    assert technologies == (
        Technology(
            name="nginx",
            category="web-server",
            version="1.24.0",
            source="https://api.example.com/users",
            confidence=100,
        ),
    )
    assert all(
        result.context.has(key)
        for key in (
            PipelineStateKey.SUBDOMAINS,
            PipelineStateKey.HOSTS,
            PipelineStateKey.ALIVE_HOSTS,
            PipelineStateKey.HTTP_ENDPOINTS,
            PipelineStateKey.ENDPOINTS,
            PipelineStateKey.TECHNOLOGIES,
        )
    )
    assert len(result.executions) == 5
    assert tuple(item.capability_id for item in result.executions) == (
        SUBDOMAIN_DISCOVERY,
        HOST_RESOLUTION,
        HTTP_PROBE,
        WEB_CRAWL,
        TECHNOLOGY_DETECTION,
    )
