"""Risk Intelligence capability for explicit Security Knowledge Graph paths."""

from collections import defaultdict
from typing import Any, TypeGuard

from redforge.domain.asset import Asset
from redforge.domain.knowledge_graph import (
    KnowledgeGraph,
    KnowledgeGraphEdge,
    KnowledgeGraphNode,
    KnowledgeNodeKind,
    KnowledgeRelationKind,
)
from redforge.domain.risk_intelligence import (
    RiskAssessment,
    RiskFactor,
    RiskFactorKind,
    RiskIntelligence,
)
from redforge.domain.technology import Technology
from redforge.domain.vulnerability import Vulnerability, VulnerabilitySeverity
from redforge.domain.vulnerability_association import VulnerabilityMatchConfidence
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


def _is_cvss_score(value: object) -> TypeGuard[int | float]:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and 0.0 <= value <= 10.0
    )


def _is_confidence_percentage(value: object) -> TypeGuard[int]:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 100
    )


class RiskIntelligenceCapability(Capability):
    """Prioritize only explicit Asset-Technology-Vulnerability graph paths."""

    _SEVERITY_CONTRIBUTIONS: dict[VulnerabilitySeverity, int] = {
        VulnerabilitySeverity.UNKNOWN: 0,
        VulnerabilitySeverity.LOW: 15,
        VulnerabilitySeverity.MEDIUM: 35,
        VulnerabilitySeverity.HIGH: 55,
        VulnerabilitySeverity.CRITICAL: 70,
    }
    _IDENTITY_CONFIDENCE: dict[VulnerabilityMatchConfidence, int] = {
        VulnerabilityMatchConfidence.MEDIUM: 60,
        VulnerabilityMatchConfidence.HIGH: 100,
    }

    def execute(self, context: Context) -> Result[RiskIntelligence]:
        """Build deterministic investigation priorities from valid graph paths."""
        if PipelineStateKey.KNOWLEDGE_GRAPH not in context.state:
            return Result(
                status=Status.FAILURE,
                data=RiskIntelligence(),
                errors=["Required Knowledge Graph input is missing"],
                metadata={
                    "missing_prerequisite": PipelineStateKey.KNOWLEDGE_GRAPH,
                    "assessment_count": 0,
                },
            )
        graph = context.state[PipelineStateKey.KNOWLEDGE_GRAPH]
        if not isinstance(graph, KnowledgeGraph):
            return Result(
                status=Status.ERROR,
                data=RiskIntelligence(),
                errors=["Knowledge Graph input has an invalid type"],
                metadata={
                    "invalid_input": PipelineStateKey.KNOWLEDGE_GRAPH,
                    "expected_type": "KnowledgeGraph",
                    "assessment_count": 0,
                },
            )

        nodes = self._node_index(graph.nodes)
        asset_technology: dict[str, set[str]] = defaultdict(set)
        technology_vulnerabilities: dict[
            str, dict[str, list[KnowledgeGraphEdge]]
        ] = defaultdict(lambda: defaultdict(list))
        errors: list[str] = []
        skipped_relationship_count = 0

        for edge in sorted(set(graph.edges), key=self._edge_sort_key):
            source = nodes.get(edge.source_id)
            target = nodes.get(edge.target_id)
            if (
                source is None
                or target is None
                or not self._valid_edge(edge, source, target)
            ):
                skipped_relationship_count += 1
                errors.append(
                    "Skipped invalid graph relationship "
                    f"'{edge.source_id}' -> '{edge.target_id}' "
                    f"({edge.kind.value})"
                )
                continue
            if edge.kind == KnowledgeRelationKind.OBSERVED_TECHNOLOGY:
                asset_technology[target.identifier].add(source.identifier)
            else:
                technology_vulnerabilities[source.identifier][
                    target.identifier
                ].append(edge)

        assessments: dict[str, RiskAssessment] = {}
        for technology_node_id in sorted(asset_technology):
            vulnerability_edges = technology_vulnerabilities.get(technology_node_id)
            if not vulnerability_edges:
                continue
            technology_node = nodes[technology_node_id]
            technology = technology_node.entity
            if not isinstance(technology, Technology):
                continue

            for asset_node_id in sorted(asset_technology[technology_node_id]):
                asset_node = nodes[asset_node_id]
                asset = asset_node.entity
                if not isinstance(asset, Asset):
                    continue
                for vulnerability_node_id in sorted(vulnerability_edges):
                    vulnerability_node = nodes[vulnerability_node_id]
                    vulnerability = vulnerability_node.entity
                    if not isinstance(vulnerability, Vulnerability):
                        continue
                    match_edge = min(
                        vulnerability_edges[vulnerability_node_id],
                        key=self._match_edge_preference_key,
                    )
                    assessment = self._assessment(
                        asset_node,
                        technology_node,
                        vulnerability_node,
                        asset,
                        technology,
                        vulnerability,
                        match_edge,
                    )
                    assessments.setdefault(assessment.identifier, assessment)

        ordered_assessments = tuple(
            sorted(
                assessments.values(),
                key=lambda item: (
                    -item.priority_score,
                    item.asset_node_id,
                    item.technology_node_id,
                    item.vulnerability_node_id,
                    item.identifier,
                ),
            )
        )
        status = (
            Status.PARTIAL if skipped_relationship_count > 0 else Status.SUCCESS
        )
        return Result(
            status=status,
            data=RiskIntelligence(assessments=ordered_assessments),
            errors=errors,
            metadata={
                "assessment_count": len(ordered_assessments),
                "skipped_relationship_count": skipped_relationship_count,
                "input_node_count": len(graph.nodes),
                "input_edge_count": len(graph.edges),
            },
        )

    def _node_index(
        self, nodes: tuple[KnowledgeGraphNode, ...]
    ) -> dict[str, KnowledgeGraphNode]:
        index: dict[str, KnowledgeGraphNode] = {}
        for node in sorted(nodes, key=lambda item: item.identifier):
            index.setdefault(node.identifier, node)
        return index

    def _valid_edge(
        self,
        edge: KnowledgeGraphEdge,
        source: KnowledgeGraphNode | None,
        target: KnowledgeGraphNode | None,
    ) -> bool:
        if source is None or target is None:
            return False
        if edge.kind == KnowledgeRelationKind.OBSERVED_TECHNOLOGY:
            return (
                source.kind == KnowledgeNodeKind.ASSET
                and isinstance(source.entity, Asset)
                and target.kind == KnowledgeNodeKind.TECHNOLOGY
                and isinstance(target.entity, Technology)
            )
        if edge.kind == KnowledgeRelationKind.MATCHES_VULNERABILITY:
            return (
                source.kind == KnowledgeNodeKind.TECHNOLOGY
                and isinstance(source.entity, Technology)
                and target.kind == KnowledgeNodeKind.VULNERABILITY
                and isinstance(target.entity, Vulnerability)
            )
        return False

    def _assessment(
        self,
        asset_node: KnowledgeGraphNode,
        technology_node: KnowledgeGraphNode,
        vulnerability_node: KnowledgeGraphNode,
        asset: Asset,
        technology: Technology,
        vulnerability: Vulnerability,
        match_edge: KnowledgeGraphEdge,
    ) -> RiskAssessment:
        factors: list[RiskFactor] = []
        missing: list[str] = []

        valid_cvss = _is_cvss_score(vulnerability.cvss_score)
        known_severity = vulnerability.severity != VulnerabilitySeverity.UNKNOWN
        if not valid_cvss:
            missing.append("valid CVSS base score")
        if not known_severity:
            missing.append("known vulnerability severity")
        factors.append(
            self._severity_factor(vulnerability, use_fallback=not valid_cvss)
        )
        factors.append(self._cvss_factor(vulnerability))
        factors.append(self._identity_factor(match_edge, missing))
        factors.append(self._technology_confidence_factor(technology, missing))
        factors.append(self._endpoint_presence_factor(asset))
        if missing:
            factors.append(
                RiskFactor(
                    kind=RiskFactorKind.DATA_QUALITY,
                    contribution=0,
                    explanation=(
                        "Explicit assessment information is absent: "
                        + ", ".join(missing)
                    ),
                    evidence=tuple(f"missing:{item}" for item in missing),
                )
            )

        priority_score = next(
            factor.contribution
            for factor in factors
            if factor.kind == (
                RiskFactorKind.CVSS_BASE
                if valid_cvss
                else RiskFactorKind.VULNERABILITY_SEVERITY
            )
        )
        confidence_components: list[int] = []
        if match_edge.confidence is not None:
            confidence_components.append(
                self._IDENTITY_CONFIDENCE[match_edge.confidence]
            )
        if _is_confidence_percentage(technology.confidence):
            confidence_components.append(technology.confidence)
        confidence_score = (
            sum(confidence_components) // len(confidence_components)
            if confidence_components
            else 0
        )
        completeness_components = (
            valid_cvss or known_severity,
            match_edge.confidence is not None,
            _is_confidence_percentage(technology.confidence),
            True,
        )
        evidence = {
            f"asset-node:{asset_node.identifier}",
            f"technology-node:{technology_node.identifier}",
            f"vulnerability-node:{vulnerability_node.identifier}",
            f"vulnerability:{vulnerability.identifier}",
        }
        evidence.update(f"technology-evidence:{item}" for item in technology.evidence)
        evidence.update(f"match-evidence:{item}" for item in match_edge.evidence)
        evidence.update(
            "endpoint:"
            f"{endpoint.protocol}://{endpoint.host}:{endpoint.port}"
            f"{endpoint.path or ''}"
            for endpoint in asset.endpoints
        )
        return RiskAssessment(
            asset_node_id=asset_node.identifier,
            technology_node_id=technology_node.identifier,
            vulnerability_node_id=vulnerability_node.identifier,
            priority_score=priority_score,
            confidence_score=confidence_score,
            data_completeness=25 * sum(completeness_components),
            priority_known=valid_cvss or known_severity,
            factors=tuple(factors),
            evidence=tuple(sorted(evidence)),
        )

    def _severity_factor(
        self, vulnerability: Vulnerability, *, use_fallback: bool
    ) -> RiskFactor:
        severity = vulnerability.severity
        contribution = (
            self._SEVERITY_CONTRIBUTIONS[severity] if use_fallback else 0
        )
        if not use_fallback:
            explanation = (
                f"Provider vulnerability severity is {severity.value}; it is "
                "evidence only because a valid CVSS base score is available"
            )
        elif severity == VulnerabilitySeverity.UNKNOWN:
            explanation = (
                "No known provider qualitative severity is available for fallback"
            )
        else:
            explanation = (
                f"Provider vulnerability severity {severity.value} contributes "
                f"{contribution} fallback priority points because CVSS is unavailable"
            )
        return RiskFactor(
            kind=RiskFactorKind.VULNERABILITY_SEVERITY,
            contribution=contribution,
            explanation=explanation,
            evidence=(f"severity:{severity.value}",),
        )

    def _cvss_factor(
        self, vulnerability: Vulnerability
    ) -> RiskFactor:
        score = vulnerability.cvss_score
        if not _is_cvss_score(score):
            return RiskFactor(
                kind=RiskFactorKind.CVSS_BASE,
                contribution=0,
                explanation="No valid provider CVSS base score is available",
                evidence=("cvss:missing",),
            )
        contribution = int(float(score) * 7 + 0.5)
        return RiskFactor(
            kind=RiskFactorKind.CVSS_BASE,
            contribution=contribution,
            explanation=(
                f"Provider CVSS base score {score:g} contributes "
                f"{contribution} priority points"
            ),
            evidence=(f"cvss:{score:g}",),
        )

    def _identity_factor(
        self, edge: KnowledgeGraphEdge, missing: list[str]
    ) -> RiskFactor:
        confidence = edge.confidence
        if confidence is None:
            missing.append("identity match confidence")
            return RiskFactor(
                kind=RiskFactorKind.IDENTITY_MATCH_CONFIDENCE,
                contribution=0,
                explanation=(
                    "Technology-to-Vulnerability identity confidence is missing; "
                    "this leaves assessment confidence incomplete but does not "
                    "reduce investigation priority"
                ),
                evidence=("identity-match-confidence:missing",),
            )
        return RiskFactor(
            kind=RiskFactorKind.IDENTITY_MATCH_CONFIDENCE,
            contribution=0,
            explanation=(
                f"Explicit Technology-to-Vulnerability identity match has "
                f"{confidence.value} confidence; this influences assessment "
                "confidence, not investigation priority"
            ),
            evidence=(f"identity-match-confidence:{confidence.value}",),
        )

    def _technology_confidence_factor(
        self, technology: Technology, missing: list[str]
    ) -> RiskFactor:
        confidence = technology.confidence
        if not _is_confidence_percentage(confidence):
            missing.append("technology detection confidence")
            return RiskFactor(
                kind=RiskFactorKind.TECHNOLOGY_DETECTION_CONFIDENCE,
                contribution=0,
                explanation=(
                    "Technology detection confidence is missing; this leaves "
                    "assessment confidence incomplete but does not reduce "
                    "investigation priority"
                ),
                evidence=("technology-detection-confidence:missing",),
            )
        return RiskFactor(
            kind=RiskFactorKind.TECHNOLOGY_DETECTION_CONFIDENCE,
            contribution=0,
            explanation=(
                f"Technology detection confidence is {confidence}%; this influences "
                "assessment confidence, not investigation priority"
            ),
            evidence=(f"technology-detection-confidence:{confidence}",),
        )

    def _endpoint_presence_factor(self, asset: Asset) -> RiskFactor:
        endpoints = tuple(
            sorted(
                (
                    f"{endpoint.protocol}://{endpoint.host}:{endpoint.port}"
                    f"{endpoint.path or ''}"
                )
                for endpoint in asset.endpoints
            )
        )
        if not endpoints:
            return RiskFactor(
                kind=RiskFactorKind.OBSERVED_ENDPOINT_PRESENCE,
                contribution=0,
                explanation=(
                    "No Endpoint is present on the Asset snapshot; endpoint absence "
                    "does not establish reachability or exposure"
                ),
                evidence=("observed-endpoint:none",),
            )
        return RiskFactor(
            kind=RiskFactorKind.OBSERVED_ENDPOINT_PRESENCE,
            contribution=0,
            explanation=(
                "The Asset snapshot contains one or more Endpoints; presence does "
                "not establish reachability, public availability, or network exposure"
            ),
            evidence=endpoints,
        )

    def _match_edge_preference_key(
        self, edge: KnowledgeGraphEdge
    ) -> tuple[Any, ...]:
        confidence = (
            self._IDENTITY_CONFIDENCE.get(edge.confidence, 0)
            if edge.confidence is not None
            else 0
        )
        return (-confidence, self._edge_sort_key(edge))

    def _edge_sort_key(self, edge: KnowledgeGraphEdge) -> tuple[Any, ...]:
        return (
            edge.source_id,
            edge.target_id,
            edge.kind.value,
            edge.product_identifier.scheme if edge.product_identifier else "",
            edge.product_identifier.value if edge.product_identifier else "",
            edge.match_method.value if edge.match_method else "",
            edge.confidence.value if edge.confidence else "",
            edge.evidence,
        )

    @property
    def name(self) -> str:
        """Return the stable pipeline capability name."""
        return "risk_intelligence"
