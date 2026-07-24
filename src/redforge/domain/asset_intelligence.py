"""Asset Intelligence read model."""

from dataclasses import dataclass

from redforge.domain.asset import Asset
from redforge.domain.asset_association import AssetAssociation
from redforge.domain.technology import Technology


@dataclass(frozen=True, slots=True)
class AssetIntelligence:
    """Correlated asset identities and their explicit knowledge relationships."""

    assets: tuple[Asset, ...] = ()
    """Deterministic snapshot-local asset identities."""

    technology_associations: tuple[AssetAssociation[Technology], ...] = ()
    """Technology observations linked to assets through source provenance."""
