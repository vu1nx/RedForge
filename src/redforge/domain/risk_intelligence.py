"""Risk Intelligence domain models."""

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class RiskLevel(StrEnum):
    """Qualitative investigation-priority level."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskFactorKind(StrEnum):
    """Kinds of explicit evidence that can influence investigation priority."""

    VULNERABILITY_SEVERITY = "vulnerability_severity"
    CVSS_BASE = "cvss_base"
    IDENTITY_MATCH_CONFIDENCE = "identity_match_confidence"
    TECHNOLOGY_DETECTION_CONFIDENCE = "technology_detection_confidence"
    OBSERVED_ENDPOINT_PRESENCE = "observed_endpoint_presence"
    DATA_QUALITY = "data_quality"


def risk_level_for_score(
    score: int, *, priority_known: bool = True
) -> RiskLevel:
    """Map a bounded investigation-priority score to its qualitative level."""
    if not _is_integer(score):
        raise TypeError("priority score must be an integer")
    if not 0 <= score <= 100:
        raise ValueError("priority score must be an integer from 0 to 100")
    if not priority_known:
        return RiskLevel.UNKNOWN
    if score < 20:
        return RiskLevel.LOW
    if score < 40:
        return RiskLevel.MEDIUM
    if score < 60:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def risk_assessment_identifier(
    asset_node_id: str,
    technology_node_id: str,
    vulnerability_node_id: str,
) -> str:
    """Return the deterministic identity of one explicit graph path."""
    payload = json.dumps(
        [asset_node_id, technology_node_id, vulnerability_node_id],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"risk-assessment:{digest}"


@dataclass(frozen=True, slots=True)
class RiskFactor:
    """One explainable score contribution based on explicit graph evidence."""

    kind: RiskFactorKind
    """Kind of evidence represented by the factor."""

    contribution: int
    """Signed integer contribution to investigation priority."""

    explanation: str
    """Human-readable explanation of the contribution."""

    evidence: tuple[str, ...] = ()
    """Immutable evidence supporting the contribution."""

    def __post_init__(self) -> None:
        if not _is_integer(self.contribution):
            raise TypeError("risk factor contribution must be an integer")


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Investigation priority for one explicit Asset-Technology-Vulnerability path."""

    identifier: str = field(init=False)
    """Deterministic identity derived only from the three graph node identifiers."""

    asset_node_id: str
    """Graph identifier of the explicitly related Asset."""

    technology_node_id: str
    """Graph identifier of the explicitly observed Technology."""

    vulnerability_node_id: str
    """Graph identifier of the explicitly matched Vulnerability."""

    priority_score: int
    """Bounded RedForge investigation priority from 0 to 100."""

    confidence_score: int
    """Evidence confidence from explicit correlation confidence values."""

    data_completeness: int
    """Percentage of explicitly available assessment evidence components."""

    priority_known: bool = True
    """Whether usable vulnerability-magnitude evidence is available."""

    level: RiskLevel = field(init=False)
    """Qualitative level derived deterministically from ``priority_score``."""

    factors: tuple[RiskFactor, ...] = ()
    """Ordered, explainable score contributions."""

    evidence: tuple[str, ...] = ()
    """Immutable evidence describing the assessed graph path."""

    def __post_init__(self) -> None:
        if not _is_integer(self.priority_score):
            raise TypeError("priority score must be an integer")
        if not 0 <= self.priority_score <= 100:
            raise ValueError("priority score must be an integer from 0 to 100")
        for name, value in (
            ("confidence score", self.confidence_score),
            ("data completeness", self.data_completeness),
        ):
            if not _is_integer(value):
                raise TypeError(f"{name} must be an integer")
            if not 0 <= value <= 100:
                raise ValueError(f"{name} must be an integer from 0 to 100")
        level = risk_level_for_score(
            self.priority_score, priority_known=self.priority_known
        )
        identifier = risk_assessment_identifier(
            self.asset_node_id,
            self.technology_node_id,
            self.vulnerability_node_id,
        )
        object.__setattr__(self, "identifier", identifier)
        object.__setattr__(self, "level", level)


@dataclass(frozen=True, slots=True)
class RiskIntelligence:
    """Deterministic investigation priorities derived from explicit graph paths."""

    assessments: tuple[RiskAssessment, ...] = ()
    """Deduplicated assessments in deterministic priority order."""
