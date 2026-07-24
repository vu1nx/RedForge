"""Tests for Security Knowledge Graph construction."""

from redforge.capabilities.knowledge_graph import KnowledgeGraphCapability
from redforge.domain.asset import Asset
from redforge.domain.asset_association import AssetAssociation
from redforge.domain.asset_intelligence import AssetIntelligence
from redforge.domain.knowledge_graph import (
    KnowledgeGraph,
    KnowledgeNodeKind,
    KnowledgeRelationKind,
)
from redforge.domain.product_identifier import ProductIdentifier
from redforge.domain.technology import Technology
from redforge.domain.vulnerability import Vulnerability, VulnerabilitySeverity
from redforge.domain.vulnerability_association import (
    VulnerabilityAssociation,
    VulnerabilityMatchConfidence,
    VulnerabilityMatchMethod,
)
from redforge.domain.vulnerability_intelligence import VulnerabilityIntelligence
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.context import Context
from redforge.sdk.result import Status


def _asset(identifier: str = "asset:example.com") -> Asset:
    return Asset(identifier=identifier, type="domain", name="example.com")


def _technology(
    *,
    source: str = "https://example.com/",
    evidence: tuple[str, ...] = ("nginx/1.24.0",),
) -> Technology:
    return Technology(
        name="nginx",
        category="web-server",
        version="1.24.0",
        vendor="nginx",
        source=source,
        evidence=evidence,
        confidence=100,
    )


def _vulnerability(identifier: str = "CVE-2026-0001") -> Vulnerability:
    return Vulnerability(
        identifier=identifier,
        source="NVD",
        severity=VulnerabilitySeverity.HIGH,
        cvss_score=8.1,
    )


def _vulnerability_association(
    technology: Technology,
    *,
    vulnerability_id: str = "CVE-2026-0001",
    product_identifier: ProductIdentifier | None = None,
) -> VulnerabilityAssociation:
    return VulnerabilityAssociation(
        technology=technology,
        vulnerability_id=vulnerability_id,
        product_identifier=product_identifier
        or ProductIdentifier(
            scheme="cpe23",
            value="cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
        ),
        match_method=VulnerabilityMatchMethod.CPE_EXACT,
        confidence=VulnerabilityMatchConfidence.HIGH,
        evidence=("exact product identity",),
    )


def _context(
    asset_intelligence: object | None = None,
    vulnerability_intelligence: object | None = None,
) -> Context:
    state: dict[str, object] = {}
    if asset_intelligence is not None:
        state[PipelineStateKey.ASSET_INTELLIGENCE] = asset_intelligence
    if vulnerability_intelligence is not None:
        state[PipelineStateKey.VULNERABILITY_INTELLIGENCE] = (
            vulnerability_intelligence
        )
    return Context(target_id="example.com", state=state)


def test_empty_or_missing_intelligence_returns_empty_success() -> None:
    for context in (
        _context(),
        _context(AssetIntelligence(), VulnerabilityIntelligence()),
        _context(object(), object()),
    ):
        result = KnowledgeGraphCapability().execute(context)

        assert result.status == Status.SUCCESS
        assert result.data == KnowledgeGraph()
        assert result.metadata["node_count"] == 0
        assert result.metadata["edge_count"] == 0


def test_builds_explicit_asset_technology_vulnerability_path() -> None:
    asset = _asset()
    technology = _technology()
    vulnerability = _vulnerability()
    asset_intelligence = AssetIntelligence(
        assets=(asset,),
        technology_associations=(
            AssetAssociation(asset_id=asset.identifier, knowledge=technology),
        ),
    )
    vulnerability_intelligence = VulnerabilityIntelligence(
        vulnerabilities=(vulnerability,),
        associations=(_vulnerability_association(technology),),
    )

    result = KnowledgeGraphCapability().execute(
        _context(asset_intelligence, vulnerability_intelligence)
    )

    assert result.status == Status.SUCCESS
    assert [node.kind for node in result.data.nodes] == [
        KnowledgeNodeKind.ASSET,
        KnowledgeNodeKind.TECHNOLOGY,
        KnowledgeNodeKind.VULNERABILITY,
    ]
    assert {node.entity for node in result.data.nodes} == {
        asset,
        technology,
        vulnerability,
    }
    assert [edge.kind for edge in result.data.edges] == [
        KnowledgeRelationKind.OBSERVED_TECHNOLOGY,
        KnowledgeRelationKind.MATCHES_VULNERABILITY,
    ]

    vulnerability_edge = next(
        edge
        for edge in result.data.edges
        if edge.kind == KnowledgeRelationKind.MATCHES_VULNERABILITY
    )
    assert vulnerability_edge.product_identifier is not None
    assert vulnerability_edge.product_identifier.scheme == "cpe23"
    assert vulnerability_edge.match_method == VulnerabilityMatchMethod.CPE_EXACT
    assert vulnerability_edge.confidence == VulnerabilityMatchConfidence.HIGH
    assert vulnerability_edge.evidence == ("exact product identity",)


def test_separate_technology_observations_receive_separate_graph_nodes() -> None:
    asset = _asset()
    first = _technology(source="https://a.example.com/")
    second = _technology(source="https://b.example.com/")
    intelligence = AssetIntelligence(
        assets=(asset,),
        technology_associations=(
            AssetAssociation(asset_id=asset.identifier, knowledge=first),
            AssetAssociation(asset_id=asset.identifier, knowledge=second),
        ),
    )

    result = KnowledgeGraphCapability().execute(_context(intelligence))

    technology_nodes = [
        node
        for node in result.data.nodes
        if node.kind == KnowledgeNodeKind.TECHNOLOGY
    ]
    assert len(technology_nodes) == 2
    assert len({node.identifier for node in technology_nodes}) == 2


def test_technology_identifier_includes_observation_evidence() -> None:
    asset = _asset()
    first = _technology(evidence=("first",))
    second = _technology(evidence=("second",))
    intelligence = AssetIntelligence(
        assets=(asset,),
        technology_associations=(
            AssetAssociation(asset_id=asset.identifier, knowledge=first),
            AssetAssociation(asset_id=asset.identifier, knowledge=second),
        ),
    )

    result = KnowledgeGraphCapability().execute(_context(intelligence))

    identifiers = {
        node.identifier
        for node in result.data.nodes
        if node.kind == KnowledgeNodeKind.TECHNOLOGY
    }
    assert len(identifiers) == 2
    assert all(
        identifier.startswith("graph:technology-observation:")
        for identifier in identifiers
    )


def test_duplicate_relationships_are_deduplicated() -> None:
    asset = _asset()
    technology = _technology()
    vulnerability = _vulnerability()
    asset_association = AssetAssociation(
        asset_id=asset.identifier,
        knowledge=technology,
    )
    vulnerability_association = _vulnerability_association(technology)

    result = KnowledgeGraphCapability().execute(
        _context(
            AssetIntelligence(
                assets=(asset, asset),
                technology_associations=(asset_association, asset_association),
            ),
            VulnerabilityIntelligence(
                vulnerabilities=(vulnerability, vulnerability),
                associations=(
                    vulnerability_association,
                    vulnerability_association,
                ),
            ),
        )
    )

    assert result.status == Status.SUCCESS
    assert len(result.data.nodes) == 3
    assert len(result.data.edges) == 2


def test_unknown_asset_relationship_is_skipped_without_inference() -> None:
    technology = _technology()
    intelligence = AssetIntelligence(
        technology_associations=(
            AssetAssociation(asset_id="asset:missing", knowledge=technology),
        )
    )

    result = KnowledgeGraphCapability().execute(_context(intelligence))

    assert result.status == Status.PARTIAL
    assert result.data == KnowledgeGraph()
    assert result.metadata["skipped_relationship_count"] == 1
    assert "unknown asset" in result.errors[0]


def test_unknown_vulnerability_relationship_is_skipped() -> None:
    technology = _technology()
    intelligence = VulnerabilityIntelligence(
        associations=(
            _vulnerability_association(
                technology,
                vulnerability_id="CVE-2026-MISSING",
            ),
        )
    )

    result = KnowledgeGraphCapability().execute(
        _context(vulnerability_intelligence=intelligence)
    )

    assert result.status == Status.PARTIAL
    assert result.data == KnowledgeGraph()
    assert result.metadata["skipped_relationship_count"] == 1
    assert "unknown vulnerability" in result.errors[0]


def test_vulnerability_relationship_does_not_infer_asset_ownership() -> None:
    technology = _technology()
    vulnerability = _vulnerability()
    intelligence = VulnerabilityIntelligence(
        vulnerabilities=(vulnerability,),
        associations=(_vulnerability_association(technology),),
    )

    result = KnowledgeGraphCapability().execute(
        _context(vulnerability_intelligence=intelligence)
    )

    assert result.status == Status.SUCCESS
    assert {node.kind for node in result.data.nodes} == {
        KnowledgeNodeKind.TECHNOLOGY,
        KnowledgeNodeKind.VULNERABILITY,
    }
    assert [edge.kind for edge in result.data.edges] == [
        KnowledgeRelationKind.MATCHES_VULNERABILITY
    ]


def test_invalid_product_identity_relationship_is_skipped() -> None:
    technology = _technology()
    vulnerability = _vulnerability()
    intelligence = VulnerabilityIntelligence(
        vulnerabilities=(vulnerability,),
        associations=(
            _vulnerability_association(
                technology,
                product_identifier=ProductIdentifier(scheme="", value=""),
            ),
        ),
    )

    result = KnowledgeGraphCapability().execute(
        _context(vulnerability_intelligence=intelligence)
    )

    assert result.status == Status.PARTIAL
    assert len(result.data.nodes) == 1
    assert result.data.edges == ()
    assert "invalid product identity" in result.errors[0]


def test_output_is_deterministic_across_input_ordering() -> None:
    first_asset = _asset("asset:a.example.com")
    second_asset = _asset("asset:b.example.com")
    first_technology = _technology(source="https://a.example.com/")
    second_technology = _technology(source="https://b.example.com/")
    first_vulnerability = _vulnerability("CVE-2026-0001")
    second_vulnerability = _vulnerability("CVE-2026-0002")
    asset_associations = (
        AssetAssociation(
            asset_id=first_asset.identifier,
            knowledge=first_technology,
        ),
        AssetAssociation(
            asset_id=second_asset.identifier,
            knowledge=second_technology,
        ),
    )
    vulnerability_associations = (
        _vulnerability_association(
            first_technology,
            vulnerability_id=first_vulnerability.identifier,
        ),
        _vulnerability_association(
            second_technology,
            vulnerability_id=second_vulnerability.identifier,
        ),
    )

    def execute(*, reverse: bool) -> KnowledgeGraph:
        assets = (first_asset, second_asset)
        vulnerabilities = (first_vulnerability, second_vulnerability)
        if reverse:
            assets = tuple(reversed(assets))
            vulnerabilities = tuple(reversed(vulnerabilities))
        return KnowledgeGraphCapability().execute(
            _context(
                AssetIntelligence(
                    assets=assets,
                    technology_associations=tuple(
                        reversed(asset_associations)
                        if reverse
                        else asset_associations
                    ),
                ),
                VulnerabilityIntelligence(
                    vulnerabilities=vulnerabilities,
                    associations=tuple(
                        reversed(vulnerability_associations)
                        if reverse
                        else vulnerability_associations
                    ),
                ),
            )
        ).data

    assert execute(reverse=False) == execute(reverse=True)


def test_metadata_counts_graph_contents() -> None:
    asset = _asset()
    technology = _technology()
    vulnerability = _vulnerability()
    result = KnowledgeGraphCapability().execute(
        _context(
            AssetIntelligence(
                assets=(asset,),
                technology_associations=(
                    AssetAssociation(
                        asset_id=asset.identifier,
                        knowledge=technology,
                    ),
                ),
            ),
            VulnerabilityIntelligence(
                vulnerabilities=(vulnerability,),
                associations=(_vulnerability_association(technology),),
            ),
        )
    )

    assert result.metadata == {
        "asset_node_count": 1,
        "technology_node_count": 1,
        "vulnerability_node_count": 1,
        "asset_technology_edge_count": 1,
        "technology_vulnerability_edge_count": 1,
        "skipped_relationship_count": 0,
        "node_count": 3,
        "edge_count": 2,
    }


def test_name() -> None:
    assert KnowledgeGraphCapability().name == "knowledge_graph"
