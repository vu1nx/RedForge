"""Security Knowledge Graph read model."""

from dataclasses import dataclass
from enum import StrEnum

from redforge.domain.asset import Asset
from redforge.domain.product_identifier import ProductIdentifier
from redforge.domain.technology import Technology
from redforge.domain.vulnerability import Vulnerability
from redforge.domain.vulnerability_association import (
    VulnerabilityMatchConfidence,
    VulnerabilityMatchMethod,
)

type KnowledgeGraphEntity = Asset | Technology | Vulnerability


class KnowledgeNodeKind(StrEnum):
    """Entity kinds currently represented in the security knowledge graph."""

    ASSET = "asset"
    TECHNOLOGY = "technology"
    VULNERABILITY = "vulnerability"


class KnowledgeRelationKind(StrEnum):
    """Explicit relationship kinds supported by the current intelligence models."""

    OBSERVED_TECHNOLOGY = "observed_technology"
    MATCHES_VULNERABILITY = "matches_vulnerability"


@dataclass(frozen=True, slots=True)
class KnowledgeGraphNode:
    """Graph-local identity for an existing immutable domain entity."""

    identifier: str
    """Deterministic identifier within one knowledge graph snapshot."""

    kind: KnowledgeNodeKind
    """Kind of the represented domain entity."""

    entity: KnowledgeGraphEntity
    """Original immutable domain entity; the graph does not take ownership."""


@dataclass(frozen=True, slots=True)
class KnowledgeGraphEdge:
    """Directed, explicit relationship between two graph nodes."""

    source_id: str
    """Identifier of the source node."""

    target_id: str
    """Identifier of the target node."""

    kind: KnowledgeRelationKind
    """Semantics of the directed relationship."""

    product_identifier: ProductIdentifier | None = None
    """Product identity that established a vulnerability relationship."""

    match_method: VulnerabilityMatchMethod | None = None
    """Method used to establish a vulnerability relationship."""

    confidence: VulnerabilityMatchConfidence | None = None
    """Identity-match confidence, not exploitability or risk."""

    evidence: tuple[str, ...] = ()
    """Immutable relationship evidence."""


@dataclass(frozen=True, slots=True)
class KnowledgeGraph:
    """Deterministic graph snapshot built from explicit intelligence relationships."""

    nodes: tuple[KnowledgeGraphNode, ...] = ()
    """Graph nodes ordered by graph-local identifier."""

    edges: tuple[KnowledgeGraphEdge, ...] = ()
    """Directed relationships ordered deterministically."""
