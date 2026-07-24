"""Tests for deterministic Risk Intelligence construction."""

from redforge.capabilities.risk_intelligence import RiskIntelligenceCapability
from redforge.domain.asset import Asset
from redforge.domain.endpoint import Endpoint
from redforge.domain.knowledge_graph import (
    KnowledgeGraph,
    KnowledgeGraphEdge,
    KnowledgeGraphNode,
    KnowledgeNodeKind,
    KnowledgeRelationKind,
)
from redforge.domain.risk_intelligence import RiskFactorKind, RiskIntelligence, RiskLevel
from redforge.domain.technology import Technology
from redforge.domain.vulnerability import Vulnerability, VulnerabilitySeverity
from redforge.domain.vulnerability_association import VulnerabilityMatchConfidence
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


def _asset(*, endpoint: bool = True, identifier: str = "graph:asset:a") -> KnowledgeGraphNode:
    endpoints = (Endpoint(host="example.com", port=443, protocol="https"),) if endpoint else ()
    return KnowledgeGraphNode(
        identifier=identifier,
        kind=KnowledgeNodeKind.ASSET,
        entity=Asset(identifier=identifier, type="domain", endpoints=endpoints),
    )


def _technology(
    *, confidence: int | None = 100, identifier: str = "graph:technology:t"
) -> KnowledgeGraphNode:
    return KnowledgeGraphNode(
        identifier=identifier,
        kind=KnowledgeNodeKind.TECHNOLOGY,
        entity=Technology(name="nginx", category="server", confidence=confidence),
    )


def _vulnerability(
    *,
    cvss: float | None = 8.0,
    severity: VulnerabilitySeverity = VulnerabilitySeverity.HIGH,
    identifier: str = "graph:vulnerability:v",
) -> KnowledgeGraphNode:
    return KnowledgeGraphNode(
        identifier=identifier,
        kind=KnowledgeNodeKind.VULNERABILITY,
        entity=Vulnerability(
            identifier=identifier, source="NVD", cvss_score=cvss, severity=severity
        ),
    )


def _graph(
    *,
    asset: KnowledgeGraphNode | None = None,
    technology: KnowledgeGraphNode | None = None,
    vulnerability: KnowledgeGraphNode | None = None,
    match_confidence: VulnerabilityMatchConfidence | None = VulnerabilityMatchConfidence.HIGH,
    extra_edges: tuple[KnowledgeGraphEdge, ...] = (),
) -> KnowledgeGraph:
    asset = asset or _asset()
    technology = technology or _technology()
    vulnerability = vulnerability or _vulnerability()
    return KnowledgeGraph(
        nodes=(asset, technology, vulnerability),
        edges=(
            KnowledgeGraphEdge(
                source_id=asset.identifier,
                target_id=technology.identifier,
                kind=KnowledgeRelationKind.OBSERVED_TECHNOLOGY,
            ),
            KnowledgeGraphEdge(
                source_id=technology.identifier,
                target_id=vulnerability.identifier,
                kind=KnowledgeRelationKind.MATCHES_VULNERABILITY,
                confidence=match_confidence,
            ),
            *extra_edges,
        ),
    )


def _execute(value: object = ...) -> Result[RiskIntelligence]:
    state: dict[str, object] = {}
    if value is not ...:
        state[PipelineStateKey.KNOWLEDGE_GRAPH] = value
    return RiskIntelligenceCapability().execute(Context(target_id="target", state=state))


def _contribution(value: object, kind: RiskFactorKind) -> int:
    assessment = _execute(value).data.assessments[0]
    return next(f.contribution for f in assessment.factors if f.kind == kind)


def test_missing_wrong_and_empty_graph_inputs_are_distinct() -> None:
    missing = _execute()
    wrong = _execute({"nodes": []})
    empty = _execute(KnowledgeGraph())

    assert missing.status == Status.FAILURE
    assert missing.data == RiskIntelligence()
    assert missing.metadata["missing_prerequisite"] == PipelineStateKey.KNOWLEDGE_GRAPH
    assert wrong.status == Status.ERROR
    assert wrong.data == RiskIntelligence()
    assert wrong.metadata["invalid_input"] == PipelineStateKey.KNOWLEDGE_GRAPH
    assert empty.status == Status.SUCCESS
    assert empty.data == RiskIntelligence()


def test_valid_cvss_is_only_positive_priority_contribution() -> None:
    graph = _graph(vulnerability=_vulnerability(cvss=8.0, severity=VulnerabilitySeverity.CRITICAL))
    assessment = _execute(graph).data.assessments[0]

    assert assessment.priority_score == 56
    assert _contribution(graph, RiskFactorKind.CVSS_BASE) == 56
    assert _contribution(graph, RiskFactorKind.VULNERABILITY_SEVERITY) == 0
    assert sum(f.contribution > 0 for f in assessment.factors) == 1


def test_severity_is_fallback_when_cvss_is_absent_or_invalid() -> None:
    absent = _graph(vulnerability=_vulnerability(cvss=None, severity=VulnerabilitySeverity.HIGH))
    invalid = _graph(vulnerability=_vulnerability(cvss=11.0, severity=VulnerabilitySeverity.MEDIUM))

    assert _execute(absent).data.assessments[0].priority_score == 55
    assert _contribution(absent, RiskFactorKind.VULNERABILITY_SEVERITY) == 55
    assert _contribution(absent, RiskFactorKind.DATA_QUALITY) == 0
    assert _execute(invalid).data.assessments[0].priority_score == 35
    assert _contribution(invalid, RiskFactorKind.CVSS_BASE) == 0


def test_cvss_severity_disagreement_is_not_double_counted() -> None:
    low_cvss_critical = _graph(
        vulnerability=_vulnerability(cvss=1.0, severity=VulnerabilitySeverity.CRITICAL)
    )
    assert _execute(low_cvss_critical).data.assessments[0].priority_score == 7
    assert _execute(low_cvss_critical).data.assessments[0].level == RiskLevel.LOW


def test_missing_magnitude_is_visible_uncertain_and_not_penalized() -> None:
    graph = _graph(
        vulnerability=_vulnerability(cvss=None, severity=VulnerabilitySeverity.UNKNOWN)
    )
    assessment = _execute(graph).data.assessments[0]

    assert assessment.priority_score == 0
    assert assessment.level == RiskLevel.UNKNOWN
    assert assessment.data_completeness == 75
    assert _contribution(graph, RiskFactorKind.DATA_QUALITY) == 0


def test_confidence_changes_confidence_only_not_priority_or_level() -> None:
    high = _graph()
    low = _graph(
        technology=_technology(confidence=20),
        match_confidence=VulnerabilityMatchConfidence.MEDIUM,
    )
    high_assessment = _execute(high).data.assessments[0]
    low_assessment = _execute(low).data.assessments[0]

    assert high_assessment.priority_score == low_assessment.priority_score == 56
    assert high_assessment.level == low_assessment.level
    assert high_assessment.confidence_score == 100
    assert low_assessment.confidence_score == 40
    assert _contribution(low, RiskFactorKind.IDENTITY_MATCH_CONFIDENCE) == 0
    assert _contribution(low, RiskFactorKind.TECHNOLOGY_DETECTION_CONFIDENCE) == 0


def test_one_or_no_confidence_components_are_deterministic() -> None:
    identity_only = _graph(technology=_technology(confidence=None))
    neither = _graph(
        technology=_technology(confidence=None), match_confidence=None
    )

    assert _execute(identity_only).data.assessments[0].confidence_score == 100
    assert _execute(identity_only).data.assessments[0].data_completeness == 75
    assert _execute(neither).data.assessments[0].confidence_score == 0
    assert _execute(neither).data.assessments[0].data_completeness == 50
    assert _execute(neither).data.assessments[0].priority_score == 56


def test_endpoint_presence_is_context_only() -> None:
    present = _graph(asset=_asset(endpoint=True))
    absent = _graph(asset=_asset(endpoint=False))
    present_assessment = _execute(present).data.assessments[0]
    absent_assessment = _execute(absent).data.assessments[0]

    assert _contribution(present, RiskFactorKind.OBSERVED_ENDPOINT_PRESENCE) == 0
    assert _contribution(absent, RiskFactorKind.OBSERVED_ENDPOINT_PRESENCE) == 0
    assert present_assessment.priority_score == absent_assessment.priority_score
    assert present_assessment.level == absent_assessment.level
    assert any("does not establish" in f.explanation for f in present_assessment.factors)


def test_duplicate_dangling_reversed_and_unrelated_edges() -> None:
    graph = _graph()
    duplicate = KnowledgeGraph(nodes=graph.nodes, edges=(*graph.edges, *graph.edges))
    assert len(_execute(duplicate).data.assessments) == 1

    dangling = KnowledgeGraphEdge(
        source_id="missing",
        target_id=graph.nodes[1].identifier,
        kind=KnowledgeRelationKind.OBSERVED_TECHNOLOGY,
    )
    partial = _execute(_graph(extra_edges=(dangling,)))
    assert partial.status == Status.PARTIAL
    assert len(partial.data.assessments) == 1

    reversed_graph = KnowledgeGraph(
        nodes=graph.nodes,
        edges=(
            KnowledgeGraphEdge(
                source_id=graph.nodes[1].identifier,
                target_id=graph.nodes[0].identifier,
                kind=KnowledgeRelationKind.OBSERVED_TECHNOLOGY,
            ),
            graph.edges[1],
        ),
    )
    assert _execute(reversed_graph).status == Status.PARTIAL
    assert _execute(reversed_graph).data == RiskIntelligence()

    unrelated = KnowledgeGraph(nodes=graph.nodes[1:], edges=(graph.edges[1],))
    assert _execute(unrelated).status == Status.SUCCESS
    assert _execute(unrelated).data == RiskIntelligence()


def test_output_order_is_priority_then_stable_graph_identifiers() -> None:
    asset = _asset()
    technology = _technology()
    high = _vulnerability(cvss=9.0, identifier="graph:vulnerability:z")
    low = _vulnerability(cvss=2.0, identifier="graph:vulnerability:a")
    graph = KnowledgeGraph(
        nodes=(asset, technology, low, high),
        edges=(
            KnowledgeGraphEdge(asset.identifier, technology.identifier, KnowledgeRelationKind.OBSERVED_TECHNOLOGY),
            KnowledgeGraphEdge(technology.identifier, low.identifier, KnowledgeRelationKind.MATCHES_VULNERABILITY),
            KnowledgeGraphEdge(technology.identifier, high.identifier, KnowledgeRelationKind.MATCHES_VULNERABILITY),
        ),
    )
    result = _execute(graph)
    assert [a.priority_score for a in result.data.assessments] == [63, 14]


def test_name() -> None:
    assert RiskIntelligenceCapability().name == "risk_intelligence"
