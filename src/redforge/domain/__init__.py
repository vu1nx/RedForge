"""RedForge Domain Layer.

This package contains immutable domain models representing core entities.
"""

from redforge.domain.asset import Asset
from redforge.domain.asset_association import AssetAssociation
from redforge.domain.asset_intelligence import AssetIntelligence
from redforge.domain.endpoint import Endpoint
from redforge.domain.evidence import Evidence
from redforge.domain.finding import Finding
from redforge.domain.host import Host, HostAddress, HostResolution, IPVersion
from redforge.domain.http_probe import HttpProbeEndpoint
from redforge.domain.knowledge_graph import (
    KnowledgeGraph,
    KnowledgeGraphEdge,
    KnowledgeGraphEntity,
    KnowledgeGraphNode,
    KnowledgeNodeKind,
    KnowledgeRelationKind,
)
from redforge.domain.product_identifier import ProductIdentifier
from redforge.domain.risk_intelligence import (
    RiskAssessment,
    RiskFactor,
    RiskFactorKind,
    RiskIntelligence,
    RiskLevel,
    risk_assessment_identifier,
    risk_level_for_score,
)
from redforge.domain.scan_scope import ScanScope, ScanTarget
from redforge.domain.service import Service
from redforge.domain.target import Target
from redforge.domain.technology import Technology
from redforge.domain.vulnerability import Vulnerability, VulnerabilitySeverity
from redforge.domain.vulnerability_association import (
    VulnerabilityAssociation,
    VulnerabilityMatchConfidence,
    VulnerabilityMatchMethod,
)
from redforge.domain.vulnerability_intelligence import VulnerabilityIntelligence

__all__ = [
    "Asset",
    "AssetAssociation",
    "AssetIntelligence",
    "Evidence",
    "Finding",
    "Host",
    "HostAddress",
    "HostResolution",
    "HttpProbeEndpoint",
    "IPVersion",
    "KnowledgeGraph",
    "KnowledgeGraphEdge",
    "KnowledgeGraphEntity",
    "KnowledgeGraphNode",
    "KnowledgeNodeKind",
    "KnowledgeRelationKind",
    "Endpoint",
    "ProductIdentifier",
    "RiskAssessment",
    "RiskFactor",
    "RiskFactorKind",
    "RiskIntelligence",
    "RiskLevel",
    "ScanScope",
    "ScanTarget",
    "Service",
    "Target",
    "Technology",
    "Vulnerability",
    "VulnerabilityAssociation",
    "VulnerabilityIntelligence",
    "VulnerabilityMatchConfidence",
    "VulnerabilityMatchMethod",
    "VulnerabilitySeverity",
    "risk_assessment_identifier",
    "risk_level_for_score",
]
