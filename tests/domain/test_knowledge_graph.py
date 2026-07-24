"""Tests for Security Knowledge Graph domain models."""

from dataclasses import FrozenInstanceError

import pytest  # type: ignore[reportMissingImports]

from redforge.domain.asset import Asset
from redforge.domain.knowledge_graph import (
    KnowledgeGraph,
    KnowledgeGraphEdge,
    KnowledgeGraphNode,
    KnowledgeNodeKind,
    KnowledgeRelationKind,
)
from redforge.domain.product_identifier import ProductIdentifier
from redforge.domain.technology import Technology
from redforge.domain.vulnerability_association import (
    VulnerabilityMatchConfidence,
    VulnerabilityMatchMethod,
)


def test_node_preserves_independent_domain_entity() -> None:
    asset = Asset(identifier="asset:example.com", type="domain")
    node = KnowledgeGraphNode(
        identifier="graph:asset:example.com",
        kind=KnowledgeNodeKind.ASSET,
        entity=asset,
    )

    assert node.entity is asset
    assert not hasattr(node, "__dict__")
    with pytest.raises(FrozenInstanceError):
        node.identifier = "changed"  # type: ignore[misc]


def test_edge_preserves_vulnerability_relationship_provenance() -> None:
    product_identifier = ProductIdentifier(
        scheme="cpe23",
        value="cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
    )
    edge = KnowledgeGraphEdge(
        source_id="graph:technology-observation:abc",
        target_id="graph:vulnerability:CVE-2026-0001",
        kind=KnowledgeRelationKind.MATCHES_VULNERABILITY,
        product_identifier=product_identifier,
        match_method=VulnerabilityMatchMethod.CPE_EXACT,
        confidence=VulnerabilityMatchConfidence.HIGH,
        evidence=("exact CPE match",),
    )

    assert edge.product_identifier is product_identifier
    assert edge.evidence == ("exact CPE match",)
    assert not hasattr(edge, "__dict__")


def test_knowledge_graph_is_immutable_tuple_read_model() -> None:
    technology = Technology(name="nginx", category="web-server")
    node = KnowledgeGraphNode(
        identifier="graph:technology-observation:abc",
        kind=KnowledgeNodeKind.TECHNOLOGY,
        entity=technology,
    )
    graph = KnowledgeGraph(nodes=(node,))

    assert graph.nodes == (node,)
    assert graph.edges == ()
    assert not hasattr(graph, "__dict__")
    with pytest.raises(FrozenInstanceError):
        graph.nodes = ()  # type: ignore[misc]
