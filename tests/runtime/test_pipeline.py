"""Tests for sequential pipeline execution."""

from dataclasses import FrozenInstanceError
from itertools import product
from typing import Any, cast

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.host_resolver import HostResolverError
from redforge.adapters.subfinder import SubdomainDiscoveryResult
from redforge.capabilities.host_resolution import HostResolutionCapability
from redforge.capabilities.risk_intelligence import RiskIntelligenceCapability
from redforge.domain.asset import Asset
from redforge.domain.asset_intelligence import AssetIntelligence
from redforge.domain.host import Host, HostResolution
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
from redforge.domain.vulnerability_intelligence import VulnerabilityIntelligence
from redforge.observability import (
    DiagnosticEvent,
    DiagnosticEventSink,
    DiagnosticEventType,
)
from redforge.runtime.pipeline import (
    CapabilityExecution,
    Pipeline,
    PipelineResult,
    combine_status,
)
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.capability import Capability
from redforge.sdk.capability_id import CapabilityId
from redforge.sdk.context import Context
from redforge.sdk.result import Result, StatePublication, Status
from redforge.sdk.technology_detection import TechnologyDetectionPartialReason


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


class PrerequisiteCapability(Capability):
    """Capability that records whether one published state key is present."""

    def __init__(
        self,
        name: str,
        required: PipelineStateKey,
        calls: list[str],
    ) -> None:
        self._name = name
        self._required = required
        self._calls = calls

    def execute(self, context: Context) -> Result[None]:
        self._calls.append(self.name)
        if not context.has(self._required):
            return Result(status=Status.FAILURE, data=None)
        return Result(status=Status.SUCCESS, data=None)

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


class RecordingDiagnosticSink:
    """Retain immutable diagnostic events for runtime-boundary assertions."""

    def __init__(self) -> None:
        self.events: list[DiagnosticEvent] = []

    def emit(self, event: DiagnosticEvent) -> None:
        self.events.append(event)


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
def test_combine_status_is_exhaustive_and_deterministic(current: Status, observed: Status) -> None:
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


@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        (
            {
                "partial_reasons": (
                    TechnologyDetectionPartialReason.MALFORMED_RECORDS_SKIPPED,
                )
            },
            (
                TechnologyDetectionPartialReason.MALFORMED_RECORDS_SKIPPED,
            ),
        ),
        (
            {
                "partial_reasons": (
                    TechnologyDetectionPartialReason.OUTPUT_TRUNCATED,
                    TechnologyDetectionPartialReason.EXECUTION_TIMEOUT,
                    TechnologyDetectionPartialReason.OUTPUT_TRUNCATED,
                )
            },
            (
                TechnologyDetectionPartialReason.EXECUTION_TIMEOUT,
                TechnologyDetectionPartialReason.OUTPUT_TRUNCATED,
            ),
        ),
        ({}, None),
        ({"partial_reasons": ("malformed_records_skipped",)}, None),
        (
            {
                "partial_reasons": (
                    (
                        TechnologyDetectionPartialReason.EXECUTION_TIMEOUT,
                    ),
                )
            },
            None,
        ),
        ({"partial_reasons": (object(),)}, None),
        (
            {
                "partial_reasons": (
                    TechnologyDetectionPartialReason.EXECUTION_TIMEOUT,
                )
                * 5
            },
            None,
        ),
        (
            {
                "partial_reasons": {"raw": "secret https://target.test"},
                "provider_payload": {
                    "stdout": "secret",
                    "target": "https://target.test",
                },
            },
            None,
        ),
    ],
)
def test_partial_diagnostics_allowlist_only_typed_bounded_reasons(
    metadata: dict[str, Any],
    expected: tuple[TechnologyDetectionPartialReason, ...] | None,
) -> None:
    sink = RecordingDiagnosticSink()
    pipeline = Pipeline()
    pipeline.add(
        MockCapability(
            "partial",
            _result(Status.PARTIAL, metadata=metadata),
        )
    )

    pipeline.run(
        "example.com",
        diagnostic_sink=cast(DiagnosticEventSink, sink),
    )

    terminal = sink.events[-1]
    assert terminal.event_type is DiagnosticEventType.CAPABILITY_PARTIAL
    assert terminal.fields.partial_reasons == expected
    rendered = repr(terminal)
    assert "target.test" not in rendered
    assert "stdout" not in rendered


@pytest.mark.parametrize(
    ("status", "event_type"),
    [
        (Status.SUCCESS, DiagnosticEventType.CAPABILITY_COMPLETED),
        (Status.FAILURE, DiagnosticEventType.CAPABILITY_FAILED),
        (Status.ERROR, DiagnosticEventType.CAPABILITY_ERROR),
    ],
)
def test_nonpartial_terminal_events_ignore_reason_metadata(
    status: Status,
    event_type: DiagnosticEventType,
) -> None:
    sink = RecordingDiagnosticSink()
    pipeline = Pipeline()
    pipeline.add(
        MockCapability(
            "terminal",
            _result(
                status,
                metadata={
                    "partial_reasons": (
                        TechnologyDetectionPartialReason.EXECUTION_TIMEOUT,
                    )
                },
            ),
        )
    )

    pipeline.run(
        "example.com",
        diagnostic_sink=cast(DiagnosticEventSink, sink),
    )

    terminal = sink.events[-1]
    assert terminal.event_type is event_type
    assert terminal.fields.partial_reasons is None


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
    assert last_result.errors == ["Capability 'invalid' returned an invalid result"]


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
        "technology_detection": (
            PipelineStateKey.TECHNOLOGIES,
            (Technology("nginx", "web-server"),),
        ),
        "asset_intelligence": (
            PipelineStateKey.ASSET_INTELLIGENCE,
            AssetIntelligence(),
        ),
        "vulnerability_intelligence": (
            PipelineStateKey.VULNERABILITY_INTELLIGENCE,
            VulnerabilityIntelligence(),
        ),
        "knowledge_graph": (PipelineStateKey.KNOWLEDGE_GRAPH, KnowledgeGraph()),
        "risk_intelligence": (
            PipelineStateKey.RISK_INTELLIGENCE,
            RiskIntelligence(),
        ),
    }
    capabilities = [
        MockCapability(name, _result(Status.SUCCESS, data)) for name, (_, data) in outputs.items()
    ]
    capabilities.append(
        MockCapability(
            "http_probe",
            Result(
                status=Status.SUCCESS,
                data=None,
                publications=(
                    StatePublication(PipelineStateKey.ALIVE_HOSTS, ()),
                    StatePublication(PipelineStateKey.HTTP_ENDPOINTS, ()),
                ),
            ),
        )
    )

    result = _run(*capabilities)

    for name, (state_key, data) in outputs.items():
        assert result.context.state[state_key] is data, name
    assert result.context.get(PipelineStateKey.ALIVE_HOSTS) == ()
    assert result.context.get(PipelineStateKey.HTTP_ENDPOINTS) == ()


def test_host_resolution_success_is_stored_with_history() -> None:
    resolution = HostResolutionCapability(PipelineResolver({"example.com": ("192.0.2.1",)}))
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
    downstream = MockCapability(
        "http_probe",
        Result(
            status=Status.SUCCESS,
            data=None,
            publications=(
                StatePublication(PipelineStateKey.ALIVE_HOSTS, ()),
                StatePublication(PipelineStateKey.HTTP_ENDPOINTS, ()),
            ),
        ),
    )

    result = _run(
        MockCapability(
            "subdomain_discovery",
            _result(
                Status.SUCCESS,
                SubdomainDiscoveryResult(hostnames=("good.example", "missing.example")),
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


@pytest.mark.parametrize("status", [Status.SUCCESS, Status.PARTIAL])
def test_explicit_multi_output_is_atomic_and_executes_downstream_once(
    status: Status,
) -> None:
    calls: list[str] = []
    multi_result = Result[None](
        status=status,
        data=None,
        publications=(
            StatePublication(
                PipelineStateKey.SUBDOMAINS,
                SubdomainDiscoveryResult(hostnames=("a.example",)),
            ),
            StatePublication(
                PipelineStateKey.HOSTS,
                HostResolution(hosts=(Host(hostname="host.example"),)),
            ),
        ),
    )
    pipeline = Pipeline(
        output_contracts={
            "multi": (
                PipelineStateKey.HOSTS,
                PipelineStateKey.SUBDOMAINS,
            )
        }
    )
    pipeline.add(MockCapability("multi", multi_result))
    pipeline.add(
        PrerequisiteCapability(
            "needs_subdomains",
            PipelineStateKey.SUBDOMAINS,
            calls,
        )
    )
    pipeline.add(PrerequisiteCapability("needs_hosts", PipelineStateKey.HOSTS, calls))

    result = pipeline.run("example.com")

    assert result.status == status
    assert result.context.get(PipelineStateKey.SUBDOMAINS) == (
        SubdomainDiscoveryResult(hostnames=("a.example",))
    )
    assert result.context.get(PipelineStateKey.HOSTS) == HostResolution(
        hosts=(Host(hostname="host.example"),)
    )
    assert calls == ["needs_subdomains", "needs_hosts"]
    assert result.executed_capabilities == (
        "multi",
        "needs_subdomains",
        "needs_hosts",
    )
    assert len(result.executions) == 3
    assert result.executions[0].result is multi_result
    assert result.last_result is result.executions[-1].result


def test_partial_explicit_subset_does_not_create_missing_state() -> None:
    pipeline = Pipeline(
        output_contracts={
            "multi": (
                PipelineStateKey.ALIVE_HOSTS,
                PipelineStateKey.HOSTS,
                PipelineStateKey.SUBDOMAINS,
            )
        }
    )
    pipeline.add(
        MockCapability(
            "multi",
            Result[None](
                status=Status.PARTIAL,
                data=None,
                publications=(
                    StatePublication(
                        PipelineStateKey.HOSTS, HostResolution()
                    ),
                    StatePublication(
                        PipelineStateKey.SUBDOMAINS,
                        SubdomainDiscoveryResult(),
                    ),
                ),
            ),
        )
    )

    result = pipeline.run("example.com")

    assert result.status == Status.PARTIAL
    assert result.context.has(PipelineStateKey.HOSTS)
    assert result.context.has(PipelineStateKey.SUBDOMAINS)
    assert not result.context.has(PipelineStateKey.ALIVE_HOSTS)


def test_downstream_missing_subset_prerequisite_uses_normal_failure_policy() -> None:
    calls: list[str] = []
    pipeline = Pipeline(
        output_contracts={
            "multi": (
                PipelineStateKey.ALIVE_HOSTS,
                PipelineStateKey.HOSTS,
            )
        }
    )
    pipeline.add(
        MockCapability(
            "multi",
            Result[None](
                status=Status.PARTIAL,
                data=None,
                publications=(
                    StatePublication(
                        PipelineStateKey.HOSTS,
                        HostResolution(
                            hosts=(Host(hostname="host.example"),)
                        ),
                    ),
                ),
            ),
        )
    )
    pipeline.add(
        PrerequisiteCapability(
            "needs_alive_hosts",
            PipelineStateKey.ALIVE_HOSTS,
            calls,
        )
    )

    result = pipeline.run("example.com")

    assert calls == ["needs_alive_hosts"]
    assert result.status == Status.FAILURE
    assert result.executed_capabilities == ("multi", "needs_alive_hosts")
    assert result.context.has(PipelineStateKey.HOSTS)
    assert not result.context.has(PipelineStateKey.ALIVE_HOSTS)


@pytest.mark.parametrize("status", [Status.FAILURE, Status.ERROR])
def test_stopping_result_with_explicit_publications_is_invalid(
    status: Status,
) -> None:
    invalid = Result[None](
        status=status,
        data=None,
        publications=(StatePublication(PipelineStateKey.HOSTS, ("secret-value",)),),
    )
    downstream = MockCapability("downstream", Result(status=Status.SUCCESS, data="unused"))
    pipeline = Pipeline(output_contracts={"invalid": (PipelineStateKey.HOSTS,)})
    pipeline.add(MockCapability("invalid", invalid))
    pipeline.add(downstream)

    result = pipeline.run(Context(target_id="example.com", state={"prior": "preserved"}))

    assert result.status == Status.ERROR
    assert result.last_result is not None
    assert result.last_result.status == Status.ERROR
    assert result.context.state == {"prior": "preserved"}
    assert downstream.execute_calls == []
    assert "secret-value" not in repr(result.last_result)


def test_duplicate_explicit_publications_are_rejected_atomically() -> None:
    invalid = Result[None](status=Status.SUCCESS, data=None)
    object.__setattr__(
        invalid,
        "publications",
        (
            StatePublication(PipelineStateKey.HOSTS, "first-secret"),
            StatePublication(PipelineStateKey.HOSTS, "second-secret"),
            StatePublication(PipelineStateKey.SUBDOMAINS, "third-secret"),
        ),
    )
    pipeline = Pipeline(
        output_contracts={
            "invalid": (
                PipelineStateKey.HOSTS,
                PipelineStateKey.SUBDOMAINS,
            )
        }
    )
    pipeline.add(MockCapability("invalid", invalid))
    context = Context(target_id="example.com", state={"prior": "preserved"})

    result = pipeline.run(context)

    assert result.status == Status.ERROR
    assert result.context.state == {"prior": "preserved"}
    assert len(result.executions) == 1
    assert "secret" not in repr(result.last_result)


def test_undeclared_explicit_publication_is_rejected_atomically() -> None:
    pipeline = Pipeline(output_contracts={"invalid": (PipelineStateKey.HOSTS,)})
    pipeline.add(
        MockCapability(
            "invalid",
            Result[None](
                status=Status.SUCCESS,
                data=None,
                publications=(
                    StatePublication(PipelineStateKey.HOSTS, "host-secret"),
                    StatePublication(PipelineStateKey.SUBDOMAINS, "subdomain-secret"),
                ),
            ),
        )
    )
    context = Context(target_id="example.com", state={"prior": "preserved"})

    result = pipeline.run(context)

    assert result.status == Status.ERROR
    assert result.context.state == {"prior": "preserved"}
    assert "secret" not in repr(result.last_result)


def test_invalid_typed_publication_is_rejected_atomically_and_recorded() -> None:
    pipeline = Pipeline(
        output_contracts={
            "invalid": (
                PipelineStateKey.ALIVE_HOSTS,
                PipelineStateKey.HTTP_ENDPOINTS,
            )
        }
    )
    pipeline.add(
        MockCapability(
            "invalid",
            Result[None](
                status=Status.SUCCESS,
                data=None,
                publications=(
                    StatePublication(PipelineStateKey.ALIVE_HOSTS, ()),
                    StatePublication(
                        PipelineStateKey.HTTP_ENDPOINTS,
                        ("sensitive-invalid-value",),
                    ),
                ),
            ),
        )
    )
    context = Context(target_id="example.com", state={"prior": "preserved"})

    result = pipeline.run(context)

    assert result.status is Status.ERROR
    assert result.context.state == {"prior": "preserved"}
    assert len(result.executions) == 1
    assert result.executions[0].result is result.last_result
    assert "sensitive-invalid-value" not in repr(result.last_result)


def test_legacy_data_for_multi_output_contract_fails_safely() -> None:
    pipeline = Pipeline(
        output_contracts={
            "legacy": (
                PipelineStateKey.HOSTS,
                PipelineStateKey.SUBDOMAINS,
            )
        }
    )
    pipeline.add(
        MockCapability(
            "legacy",
            Result(status=Status.SUCCESS, data="ambiguous-secret"),
        )
    )

    result = pipeline.run("example.com")

    assert result.status == Status.ERROR
    assert result.context.state == {}
    assert "ambiguous-secret" not in repr(result.last_result)


def test_legacy_output_keys_constructor_remains_supported() -> None:
    pipeline = Pipeline(output_keys={"legacy": PipelineStateKey.HOSTS})
    pipeline.add(
        MockCapability(
            "legacy",
            Result(status=Status.SUCCESS, data=HostResolution()),
        )
    )

    result = pipeline.run("example.com")

    assert result.status == Status.SUCCESS
    assert result.context.get(PipelineStateKey.HOSTS) == HostResolution()


def test_explicit_single_output_works_and_conflicting_data_fails() -> None:
    explicit = Pipeline(output_contracts={"explicit": (PipelineStateKey.HOSTS,)})
    explicit.add(
        MockCapability(
            "explicit",
            Result[None](
                status=Status.SUCCESS,
                data=None,
                publications=(
                    StatePublication(
                        PipelineStateKey.HOSTS,
                        HostResolution(),
                    ),
                ),
            ),
        )
    )
    assert (
        explicit.run("example.com").context.get(PipelineStateKey.HOSTS)
        == HostResolution()
    )

    conflict = Pipeline(output_contracts={"conflict": (PipelineStateKey.HOSTS,)})
    conflict.add(
        MockCapability(
            "conflict",
            Result(
                status=Status.SUCCESS,
                data="legacy-secret",
                publications=(StatePublication(PipelineStateKey.HOSTS, ("explicit",)),),
            ),
        )
    )
    result = conflict.run("example.com")
    assert result.status == Status.ERROR
    assert result.context.state == {}
    assert "secret" not in repr(result.last_result)


def test_explicit_typed_manual_contract_bypasses_name_fallback() -> None:
    identity = CapabilityId("manual_typed")
    pipeline = Pipeline()
    pipeline.add(
        MockCapability(
            identity.value,
            Result(status=Status.SUCCESS, data=HostResolution()),
        ),
        capability_id=identity,
        provides=(PipelineStateKey.HOSTS,),
    )

    result = pipeline.run("example.com")

    assert result.context.get(PipelineStateKey.HOSTS) == HostResolution()
    assert identity.value not in result.context.state
    assert result.executions[0].capability_id == identity


@pytest.mark.parametrize("invalid", ["", "UPPER", "with-dash", "with space"])
def test_explicit_manual_contract_rejects_malformed_legacy_ids(
    invalid: str,
) -> None:
    pipeline = Pipeline()

    with pytest.raises(ValueError):
        pipeline.add(
            MockCapability(
                invalid,
                Result(status=Status.SUCCESS, data=("host",)),
            ),
            capability_id=invalid,
            provides=(PipelineStateKey.HOSTS,),
        )
