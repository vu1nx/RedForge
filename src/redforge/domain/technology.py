"""Technology domain model."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Technology:
    """Represents a technology or software component.

    A technology is a specific software, framework, library, or platform
    that is used within the target environment.
    """

    name: str
    """Name of the technology."""

    category: str
    """Category of the technology (e.g., framework, database, library)."""

    version: str | None = None
    """Version of the technology."""

    vendor: str | None = None
    """Vendor or creator of the technology."""

    description: str | None = None
    """Additional description or context about the technology."""

    source: str | None = None
    """Endpoint or asset where the technology was detected."""

    evidence: tuple[str, ...] = ()
    """Immutable detection evidence reported by the source tool."""

    confidence: int | None = None
    """Detection confidence as a percentage from 0 to 100."""
