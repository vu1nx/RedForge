"""Asset domain model."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Asset:
    """Represents an asset within a target environment.

    An asset is a resource that has value and may be subject to security assessment.
    """

    identifier: str
    """Unique identifier for the asset."""

    type: str
    """Type or category of the asset."""

    name: str | None = None
    """Human-readable name for the asset."""

    description: str | None = None
    """Additional description or context about the asset."""
