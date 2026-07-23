"""Finding domain model."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class Severity(StrEnum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True, slots=True)
class Finding:
    """Represents a security finding or issue.

    A finding is a discovered security issue, vulnerability, or observation
    identified during assessment or scanning.
    """

    identifier: str
    """Unique identifier for the finding."""

    title: str
    """Title or summary of the finding."""

    severity: Severity
    """Severity level of the finding."""

    description: str
    """Detailed description of the finding."""

    target_id: str
    """Identifier of the target where the finding was discovered."""

    timestamp: datetime
    """Timestamp when the finding was discovered."""

    remediation: str | None = None
    """Recommended remediation steps."""

    references: list[str] | None = None
    """External references or documentation links."""
