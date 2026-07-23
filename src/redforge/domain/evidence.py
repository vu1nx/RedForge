"""Evidence domain model."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class Evidence:
    """Represents evidence supporting a finding.

    Evidence is the data or artifacts that substantiate a security finding.
    """

    identifier: str
    """Unique identifier for the evidence."""

    finding_id: str
    """Identifier of the finding this evidence supports."""

    type: str
    """Type of evidence (e.g., screenshot, log, network_capture)."""

    content: str
    """Content or data of the evidence."""

    timestamp: datetime
    """Timestamp when the evidence was collected."""

    description: str | None = None
    """Additional description or context about the evidence."""

    source: str | None = None
    """Source or method used to collect the evidence."""
