"""Explicit relationships between assets and independent security knowledge."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AssetAssociation[T]:
    """Associates independent domain knowledge with a stable asset identity."""

    asset_id: str
    """Identifier of the related asset."""

    knowledge: T
    """Independent domain object related to the asset."""
