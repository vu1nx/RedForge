"""Tests for sequential pipeline execution."""

from dataclasses import FrozenInstanceError
from itertools import product
from typing import Any

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.host_resolver import HostResolverError
from redforge.adapters.subfinder import SubdomainDiscoveryResult
from redforge.capabilities.host_resolution import HostResolutionCapability
from redforge.capabilities.risk_intelligence import RiskIntelligenceCapability
from redforge.domain.asset import Asset
from redforge.domain.host import HostResolution
from redforge.domain.knowledge_graph import (
    KnowledgeGraph,
    KnowledgeGraphEdge,
    KnowledgeGraphNode,
    KnowledgeNodeKind,
    KnowledgeRelationKind,
)
from redforge.domain.risk_intelligence import RiskIntelligence
from redforge.domain.target import Target
from redforge.domain.technology import Technology
from redforge.runtime.pipeline import (
    CapabilityExecution,
    Pipeline,
    PipelineResult,
    combine_status,
)
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


class MockCapability(Capability):
    """Capability returning a configured object for runtime-boundary tests."""

    def __init__(self, name: str, returned: object) -> None:
        self._name = name
        self.returned = returned
        self.execute_calls: list[Context] = []

    def execute(self, context: Context) -> Result[Any]:
        self.execute_calls.append(context)
        return self.returned  # type: ignore[return-value]

    @property
    def name(self) -> str:
        return self._name


class RaisingCapability(Capability):
    """Capability that raises sensitive diagnostic text."""

    def __init__(self, name: str = "raising") -> None:
        self._name = name
        self.execute_calls = 0

    def execute(self, context: Context) -> Result[Any]:  # noqa: ARG002
        self.execute_calls += 1
        raise RuntimeError("secret-token C:\\private\\path")

    @property
    def name(self) -> str:
        return self._name


class PipelineResolver:
    """Deterministic resolver used by pipeline integration tests."""

    def __init__(self, responses: dict[str, tuple[str, ...] | Exception]) -> None:
        self.responses = responses

    def resolve(self, hostname: str) -> tuple[str, ...]:
        response = self.responses[hostname]
        if isinstance(response, Exception):
            raise response
        return response


def _result(
    status: Status,
    data: object = None,
    *,
    errors: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Result[Any]:
    return Result(
        status=status,
        data=data,
        errors=errors or [],
        metadata=metadata or {},
    )


def _run(*capabilities: Capability) -> PipelineResult:
    pipeline = Pipeline()
    for capability in capabilities:
        pipeline.add(capability)
    return pipeline.run("example.com")


_RANK = {
    Status.SUCCESS: 0,
    Status.PARTIAL: 1,
    Status.FAILURE: 2,
    Status.ERROR: 3,
}


@pytest.mark.parametrize(
    ("current", "observed"),
    list(product(Status, repeat=2)),
)
def test_combine_status_is_exhaustive_and_deterministic(
    current: Status, observed: Status
) -> None:
    expected = current if _RANK[current] >= _RANK[observed] else observed
    assert combine_status(current, observed) == expected


def test_empty_pipeline_has_immutable_empty_history() -> None:
    result = Pipeline().run(Target(identifier="example.com"))

    assert result.status == Status.SUCCESS
    assert result.executed_capabilities == ()
    assert result.execution_order == ()
    assert result.executions == ()
    assert result.last_result is None
    assert result.context.state == {}
    assert not hasattr(result, "__dict__")


def test_all_success_preserves_history_state_and_last_result() -> None:
    first_result = _result(
        Status.SUCCESS,
        {"hosts": ["www.example.com"]},
        metadata={"provider": "fixture"},
    )
    second_result = _result(Status.SUCCESS, ["www.example.com"])
    first = MockCapability("discover", first_result)
    second = MockCapability("probe", second_result)

    result = _run(first, second)

    assert result.status == Status.SUCCESS
    assert result.executed_capabilities == ("discover", "probe")
    assert result.execution_order == ("discover", "probe")
    assert result.executions == (
        CapabilityExecution("discover", first_result),
        CapabilityExecution("probe", second_result),
    )
    assert result.executions[0].result is first_result
    assert result.executions[0].result.metadata == {"provider": "fixture"}
    assert result.last_result is second_result
    assert result.context.state["discover"] == {"hosts": ["www.example.com"]}
    assert result.context.state["probe"] == ["www.example.com"]
    assert first.execute_calls[0] is second.execute_calls[0]
    with pytest.raises(FrozenInstanceError):
        result.executions = ()  # type: ignore[misc]


def test_partial_is_global_stored_and_does_not_stop_later_success() -> None:
    partial_result = _result(
        Status.PARTIAL,
        {"usable": True},
        errors=["one item skipped"],
        metadata={"skipped": 1},
    )
    final_result = _result(Status.SUCCESS, {"continued": True})
    partial = MockCapability("partial", partial_result)
    final = MockCapability("final", final_result)

    result = _run(partial, final)

    assert result.status == Status.PARTIAL
    assert result.context.state["partial"] == {"usable": True}
    assert result.context.state["final"] == {"continued": True}
    assert result.last_result is final_result
    assert result.executions[0].result is partial_result
    assert result.executions[0].result.errors == ["one item skipped"]
    assert result.executions[0].result.metadata == {"skipped": 1}


@pytest.mark.parametrize("status", [Status.FAILURE, Status.ERROR])
def test_failure_and_error_stop_without_publishing_data(
    status: Status,
) -> None:
    earlier_data = {"valid": True}
    stopping_data = {"diagnostic-only": True}
    first = MockCapability("first", _result(Status.SUCCESS, earlier_data))
    stopping_result = _result(status, stopping_data, errors=["stopped"])
    stopping = MockCapability("stopping", stopping_result)
    skipped = MockCapability("skipped", _result(Status.SUCCESS, {"bad": True}))

    result = _run(first, stopping, skipped)

    assert result.status == status
    assert result.executed_capabilities == ("first", "stopping")
    assert [entry.capability_name for entry in result.executions] == [
        "first",
        "stopping",
    ]
    assert result.last_result is stopping_result
    assert result.context.state["first"] is earlier_data
    assert "stopping" not in result.context.state
    assert "skipped" not in result.context.state
    assert skipped.execute_calls == []


def test_earlier_partial_combines_with_later_failure() -> None:
    result = _run(
        MockCapability("partial", _result(Status.PARTIAL, {"usable": True})),
        MockCapability("failure", _result(Status.FAILURE, {"invalid": True})),
    )

    assert result.status == Status.FAILURE
    assert result.context.state["partial"] == {"usable": True}
    assert "failure" not in result.context.state


def test_exception_is_sanitized_recorded_and_stops() -> None:
    raising = RaisingCapability()
    skipped = MockCapability("skipped", _result(Status.SUCCESS, "unused"))

    result = _run(raising, skipped)
    rendered = repr(result)

    assert result.status == Status.ERROR
    assert result.last_result is not None
    assert result.last_result.status == Status.ERROR
    assert result.executions[0].capability_name == "raising"
    assert result.executed_capabilities == ("raising",)
    assert result.context.state == {}
    assert skipped.execute_calls == []
    assert "secret-token" not in rendered
    assert "private" not in rendered
    assert "RuntimeError" not in rendered
    assert result.last_result.errors == [
        "Capability 'raising' failed with an unexpected execution error"
    ]


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        {},
        "invalid",
        Result(status="success", data="invalid status"),  # type: ignore[arg-type]
    ],
)
def test_invalid_capability_return_is_sanitized_error(invalid: object) -> None:
    skipped = MockCapability("skipped", _result(Status.SUCCESS, "unused"))

    result = _run(MockCapability("invalid", invalid), skipped)

    assert result.status == Status.ERROR
    last_result = result.last_result
    assert last_result is result.executions[0].result
    assert last_result is not None
    assert last_result.status == Status.ERROR
    assert last_result.data is None
    assert result.context.state == {}
    assert skipped.execute_calls == []
    assert last_result.errors == [
        "Capability 'invalid' returned an invalid result"
    ]


def test_duplicate_capability_names_are_rejected() -> None:
    pipeline = Pipeline()
    pipeline.add(MockCapability("duplicate", _result(Status.SUCCESS)))

    with pytest.raises(ValueError, match="duplicate capability name: 'duplicate'"):
        pipeline.add(MockCapability("duplicate", _result(Status.SUCCESS)))


def test_known_capability_output_mappings_continue_to_work() -> None:
    outputs: dict[str, tuple[str, object]] = {
        "subdomain_discovery": (
            PipelineStateKey.SUBDOMAINS,
            SubdomainDiscoveryResult(hostnames=("a.example.com",)),
        ),
        "host_resolution": (PipelineStateKey.HOSTS, HostResolution()),
        "http_probe": (PipelineStateKey.ALIVE_HOSTS, ["a.example.com"]),
        "technology_detection": (PipelineStateKey.TECHNOLOGIES, ["nginx"]),
        "asset_intelligence": (PipelineStateKey.ASSET_INTELLIGENCE, {"assets": []}),
        "vulnerability_intelligence": (
            PipelineStateKey.VULNERABILITY_INTELLIGENCE,
            {"vulnerabilities": []},
        ),
        "knowledge_graph": (PipelineStateKey.KNOWLEDGE_GRAPH, KnowledgeGraph()),
        "risk_intelligence": (
            PipelineStateKey.RISK_INTELLIGENCE,
            RiskIntelligence(),
        ),
    }
    capabilities = [
        MockCapability(name, _result(Status.SUCCESS, data))
        for name, (_, data) in outputs.items()
    ]

    result = _run(*capabilities)

    for name, (state_key, data) in outputs.items():
        assert result.context.state[state_key] is data, name


def test_host_resolution_success_is_stored_with_history() -> None:
    resolution = HostResolutionCapability(
        PipelineResolver({"example.com": ("192.0.2.1",)})
    )
    result = _run(
        MockCapability(
            "subdomain_discovery",
            _result(
                Status.SUCCESS,
                SubdomainDiscoveryResult(hostnames=("example.com",)),
            ),
        ),
        resolution,
    )

    assert result.status == Status.SUCCESS
    stored = result.context.state[PipelineStateKey.HOSTS]
    assert isinstance(stored, HostResolution)
    assert stored.hosts[0].hostname == "example.com"
    assert result.executions[-1].capability_name == "host_resolution"
    assert result.executions[-1].result is result.last_result


def test_host_resolution_partial_propagates_and_continues() -> None:
    resolution = HostResolutionCapability(
        PipelineResolver(
            {
                "good.example": ("192.0.2.1",),
                "missing.example": HostResolverError("not found"),
            }
        )
    )
    downstream = MockCapability("http_probe", _result(Status.SUCCESS, []))

    result = _run(
        MockCapability(
            "subdomain_discovery",
            _result(
                Status.SUCCESS,
                SubdomainDiscoveryResult(
                    hostnames=("good.example", "missing.example")
                ),
            ),
        ),
        resolution,
        downstream,
    )

    assert result.status == Status.PARTIAL
    assert downstream.execute_calls
    assert isinstance(result.context.state[PipelineStateKey.HOSTS], HostResolution)


@pytest.mark.parametrize(
    ("responses", "expected_status"),
    [
        (
            {"missing.example": HostResolverError("not found")},
            Status.FAILURE,
        ),
        (
            {"missing.example": RuntimeError("secret C:\\private\\resolver")},
            Status.ERROR,
        ),
    ],
)
def test_host_resolution_failure_or_error_stops_http_probe(
    responses: dict[str, tuple[str, ...] | Exception],
    expected_status: Status,
) -> None:
    downstream = MockCapability("http_probe", _result(Status.SUCCESS, []))
    result = _run(
        MockCapability(
            "subdomain_discovery",
            _result(
                Status.SUCCESS,
                SubdomainDiscoveryResult(hostnames=("missing.example",)),
            ),
        ),
        HostResolutionCapability(PipelineResolver(responses)),
        downstream,
    )

    assert result.status == expected_status
    assert result.last_result is not None
    assert result.last_result.status == expected_status
    assert downstream.execute_calls == []
    assert PipelineStateKey.HOSTS not in result.context.state
    assert "secret" not in repr(result)
    assert "private" not in repr(result)


def test_risk_intelligence_partial_becomes_pipeline_partial() -> None:
    asset = KnowledgeGraphNode(
        identifier="graph:asset:example.com",
        kind=KnowledgeNodeKind.ASSET,
        entity=Asset(identifier="asset:example.com", type="domain"),
    )
    technology = KnowledgeGraphNode(
        identifier="graph:technology:nginx",
        kind=KnowledgeNodeKind.TECHNOLOGY,
        entity=Technology(name="nginx", category="web-server"),
    )
    graph = KnowledgeGraph(
        nodes=(asset, technology),
        edges=(
            KnowledgeGraphEdge(
                source_id="graph:asset:missing",
                target_id=technology.identifier,
                kind=KnowledgeRelationKind.OBSERVED_TECHNOLOGY,
            ),
        ),
    )
    result = _run(
        MockCapability("knowledge_graph", _result(Status.SUCCESS, graph)),
        RiskIntelligenceCapability(),
    )

    assert result.status == Status.PARTIAL
    assert result.last_result is not None
    assert result.last_result.status == Status.PARTIAL
    assert result.context.state[PipelineStateKey.RISK_INTELLIGENCE] == RiskIntelligence()


def test_risk_intelligence_missing_graph_becomes_pipeline_failure() -> None:
    result = _run(RiskIntelligenceCapability())

    assert result.status == Status.FAILURE
    assert result.last_result is not None
    assert result.last_result.status == Status.FAILURE
    assert PipelineStateKey.RISK_INTELLIGENCE not in result.context.state


def test_risk_intelligence_wrong_graph_type_becomes_pipeline_error() -> None:
    result = _run(
        MockCapability(
            "knowledge_graph",
            _result(Status.SUCCESS, {"not": "a graph"}),
        ),
        RiskIntelligenceCapability(),
    )

    assert result.status == Status.ERROR
    assert result.last_result is not None
    assert result.last_result.status == Status.ERROR
    assert PipelineStateKey.RISK_INTELLIGENCE not in result.context.state
