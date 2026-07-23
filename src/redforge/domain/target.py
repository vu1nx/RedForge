"""Target domain model."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Target:
    """Represents a target for assessment or scanning.

    A target is the primary entity that is being evaluated or scanned.
    It can represent a domain, IP address, or network range.
    """

    identifier: str
    """Unique identifier for the target."""

    name: str | None = None
    """Human-readable name for the target."""

    description: str | None = None
    """Additional description or context about the target."""
