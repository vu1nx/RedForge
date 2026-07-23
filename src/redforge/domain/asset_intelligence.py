"""Asset Intelligence read model."""

from dataclasses import dataclass

from redforge.domain.asset import Asset
from redforge.domain.asset_association import AssetAssociation
from redforge.domain.evidence import Evidence
from redforge.domain.finding import Finding
from redforge.domain.service import Service
from redforge.domain.technology import Technology


@dataclass(frozen=True, slots=True)
class AssetIntelligence:
    """Correlated asset identities and their explicit knowledge relationships."""

    assets: tuple[Asset, ...] = ()
    """Stable asset identities discovered during reconnaissance."""

    technology_associations: tuple[AssetAssociation[Technology], ...] = ()
    """Technology observations linked to assets through source provenance."""

    service_associations: tuple[AssetAssociation[Service], ...] = ()
    """Service observations with explicit asset ownership."""

    finding_associations: tuple[AssetAssociation[Finding], ...] = ()
    """Findings that explicitly target an asset identifier."""

    evidence_associations: tuple[AssetAssociation[Evidence], ...] = ()
    """Evidence related transitively through an asset-associated finding."""
