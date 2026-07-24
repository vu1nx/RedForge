"""Security Knowledge Graph construction capability."""

import hashlib
import json
from typing import Any

from redforge.domain.asset import Asset
from redforge.domain.asset_intelligence import AssetIntelligence
from redforge.domain.knowledge_graph import (
    KnowledgeGraph,
    KnowledgeGraphEdge,
    KnowledgeGraphNode,
    KnowledgeNodeKind,
    KnowledgeRelationKind,
)
from redforge.domain.technology import Technology
from redforge.domain.vulnerability import Vulnerability
from redforge.domain.vulnerability_association import VulnerabilityAssociation
from redforge.domain.vulnerability_intelligence import VulnerabilityIntelligence
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


class KnowledgeGraphCapability(Capability):
    """Build a graph snapshot from explicit intelligence relationships."""

    def execute(self, context: Context) -> Result[KnowledgeGraph]:
        """Construct graph nodes and edges without inferring ownership."""
        asset_intelligence = context.state.get(PipelineStateKey.ASSET_INTELLIGENCE)
        if not isinstance(asset_intelligence, AssetIntelligence):
            asset_intelligence = AssetIntelligence()

        vulnerability_intelligence = context.state.get(
            PipelineStateKey.VULNERABILITY_INTELLIGENCE
        )
        if not isinstance(vulnerability_intelligence, VulnerabilityIntelligence):
            vulnerability_intelligence = VulnerabilityIntelligence()

        nodes: dict[str, KnowledgeGraphNode] = {}
        edges: set[KnowledgeGraphEdge] = set()
        errors: list[str] = []
        skipped_relationship_count = 0

        asset_nodes = self._asset_nodes(asset_intelligence.assets)
        nodes.update(
            (node.identifier, node) for node in asset_nodes.values()
        )
        vulnerability_nodes = self._vulnerability_nodes(
            vulnerability_intelligence.vulnerabilities
        )
        nodes.update(
            (node.identifier, node) for node in vulnerability_nodes.values()
        )

        for association in sorted(
            asset_intelligence.technology_associations,
            key=lambda item: (
                item.asset_id,
                self._technology_sort_key(item.knowledge),
            ),
        ):
            asset_node = asset_nodes.get(association.asset_id)
            if asset_node is None:
                skipped_relationship_count += 1
                errors.append(
                    "Skipped asset-to-technology relationship with unknown asset "
                    f"'{association.asset_id}'"
                )
                continue
            technology_node = self._technology_node(association.knowledge)
            nodes.setdefault(technology_node.identifier, technology_node)
            edges.add(
                KnowledgeGraphEdge(
                    source_id=asset_node.identifier,
                    target_id=technology_node.identifier,
                    kind=KnowledgeRelationKind.OBSERVED_TECHNOLOGY,
                )
            )

        for association in sorted(
            vulnerability_intelligence.associations,
            key=self._vulnerability_association_sort_key,
        ):
            vulnerability_node = vulnerability_nodes.get(association.vulnerability_id)
            if vulnerability_node is None:
                skipped_relationship_count += 1
                errors.append(
                    "Skipped technology-to-vulnerability relationship with unknown "
                    f"vulnerability '{association.vulnerability_id}'"
                )
                continue
            if (
                not association.product_identifier.scheme.strip()
                or not association.product_identifier.value.strip()
            ):
                skipped_relationship_count += 1
                errors.append(
                    "Skipped technology-to-vulnerability relationship with invalid "
                    f"product identity for '{association.vulnerability_id}'"
                )
                continue
            technology_node = self._technology_node(association.technology)
            nodes.setdefault(technology_node.identifier, technology_node)
            edges.add(
                KnowledgeGraphEdge(
                    source_id=technology_node.identifier,
                    target_id=vulnerability_node.identifier,
                    kind=KnowledgeRelationKind.MATCHES_VULNERABILITY,
                    product_identifier=association.product_identifier,
                    match_method=association.match_method,
                    confidence=association.confidence,
                    evidence=association.evidence,
                )
            )

        ordered_nodes = tuple(sorted(nodes.values(), key=lambda item: item.identifier))
        ordered_edges = tuple(sorted(edges, key=self._edge_sort_key))
        graph = KnowledgeGraph(nodes=ordered_nodes, edges=ordered_edges)
        status = (
            Status.PARTIAL if skipped_relationship_count > 0 else Status.SUCCESS
        )
        return Result(
            status=status,
            data=graph,
            errors=errors,
            metadata={
                "asset_node_count": sum(
                    node.kind == KnowledgeNodeKind.ASSET for node in ordered_nodes
                ),
                "technology_node_count": sum(
                    node.kind == KnowledgeNodeKind.TECHNOLOGY for node in ordered_nodes
                ),
                "vulnerability_node_count": sum(
                    node.kind == KnowledgeNodeKind.VULNERABILITY
                    for node in ordered_nodes
                ),
                "asset_technology_edge_count": sum(
                    edge.kind == KnowledgeRelationKind.OBSERVED_TECHNOLOGY
                    for edge in ordered_edges
                ),
                "technology_vulnerability_edge_count": sum(
                    edge.kind == KnowledgeRelationKind.MATCHES_VULNERABILITY
                    for edge in ordered_edges
                ),
                "skipped_relationship_count": skipped_relationship_count,
                "node_count": len(ordered_nodes),
                "edge_count": len(ordered_edges),
            },
        )

    def _asset_nodes(
        self, assets: tuple[Asset, ...]
    ) -> dict[str, KnowledgeGraphNode]:
        nodes: dict[str, KnowledgeGraphNode] = {}
        for asset in sorted(assets, key=self._asset_sort_key):
            if not asset.identifier.strip():
                continue
            nodes.setdefault(
                asset.identifier,
                KnowledgeGraphNode(
                    identifier=f"graph:{asset.identifier}",
                    kind=KnowledgeNodeKind.ASSET,
                    entity=asset,
                ),
            )
        return nodes

    def _vulnerability_nodes(
        self, vulnerabilities: tuple[Vulnerability, ...]
    ) -> dict[str, KnowledgeGraphNode]:
        nodes: dict[str, KnowledgeGraphNode] = {}
        for vulnerability in sorted(
            vulnerabilities,
            key=self._vulnerability_sort_key,
        ):
            identifier = vulnerability.identifier.strip()
            if not identifier:
                continue
            nodes.setdefault(
                identifier,
                KnowledgeGraphNode(
                    identifier=f"graph:vulnerability:{identifier}",
                    kind=KnowledgeNodeKind.VULNERABILITY,
                    entity=vulnerability,
                ),
            )
        return nodes

    def _technology_node(self, technology: Technology) -> KnowledgeGraphNode:
        payload = json.dumps(
            {
                "category": technology.category,
                "confidence": technology.confidence,
                "description": technology.description,
                "evidence": technology.evidence,
                "name": technology.name,
                "source": technology.source,
                "vendor": technology.vendor,
                "version": technology.version,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return KnowledgeGraphNode(
            identifier=f"graph:technology-observation:{digest}",
            kind=KnowledgeNodeKind.TECHNOLOGY,
            entity=technology,
        )

    def _asset_sort_key(self, asset: Asset) -> tuple[Any, ...]:
        return (
            asset.identifier,
            asset.type,
            asset.name or "",
            asset.description or "",
            asset.aliases,
            tuple(
                sorted(
                    (
                        tuple(
                            (address.version.value, address.value)
                            for address in host.addresses
                        ),
                        host.hostname or "",
                        host.operating_system or "",
                        host.description or "",
                    )
                    for host in asset.hosts
                )
            ),
            tuple(
                sorted(
                    (
                        endpoint.host,
                        endpoint.port,
                        endpoint.protocol,
                        endpoint.path or "",
                        endpoint.description or "",
                    )
                    for endpoint in asset.endpoints
                )
            ),
        )

    def _technology_sort_key(self, technology: Technology) -> tuple[Any, ...]:
        return (
            technology.name,
            technology.category,
            technology.version or "",
            technology.vendor or "",
            technology.description or "",
            technology.source or "",
            technology.evidence,
            technology.confidence if technology.confidence is not None else -1,
        )

    def _vulnerability_sort_key(
        self, vulnerability: Vulnerability
    ) -> tuple[Any, ...]:
        return (
            vulnerability.identifier,
            vulnerability.source,
            vulnerability.aliases,
            vulnerability.summary or "",
            vulnerability.description or "",
            vulnerability.severity.value,
            vulnerability.cvss_score
            if vulnerability.cvss_score is not None
            else -1.0,
            vulnerability.cvss_vector or "",
            vulnerability.cvss_version or "",
            vulnerability.cwe_ids,
            vulnerability.references,
            vulnerability.published_at.isoformat()
            if vulnerability.published_at is not None
            else "",
            vulnerability.modified_at.isoformat()
            if vulnerability.modified_at is not None
            else "",
            vulnerability.status or "",
        )

    def _vulnerability_association_sort_key(
        self, association: VulnerabilityAssociation
    ) -> tuple[Any, ...]:
        return (
            association.vulnerability_id,
            self._technology_sort_key(association.technology),
            association.product_identifier.scheme,
            association.product_identifier.value,
            association.match_method.value,
            association.confidence.value,
            association.evidence,
        )

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
        return "knowledge_graph"
