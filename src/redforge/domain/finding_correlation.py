"""Pure deterministic correlation and aggregation for normalized findings."""

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from itertools import combinations
from typing import cast

from redforge.domain.finding_intelligence import (
    AffectedAsset,
    AffectedEndpoint,
    AffectedTechnology,
    DetectionMethod,
    EvidenceConfidence,
    EvidenceQuality,
    EvidenceSource,
    EvidenceSummary,
    FindingFingerprint,
    FindingRecord,
    FindingRecordCollection,
    FindingReference,
    FindingReferenceKind,
    FindingSeverity,
)

_CONCRETE_REFERENCE_KINDS = frozenset(
    {
        FindingReferenceKind.CVE,
        FindingReferenceKind.GHSA,
        FindingReferenceKind.OSV,
    }
)
_WEAKNESS_REFERENCE_KINDS = frozenset({FindingReferenceKind.CWE})
_MAX_CLASSIFICATION_ID = 256
_MAX_NORMALIZED_TITLE = 512
_MAX_CORRELATION_RECORDS = 512
_MAX_AGGREGATE_ITEMS = 4096
_MAX_UNMERGED_DECISIONS = 131_000


class CorrelationMatchStrength(StrEnum):
    """Conservative categorical result of comparing two source findings."""

    EXACT = "exact"
    STRONG = "strong"
    POSSIBLE = "possible"
    NO_MATCH = "no_match"


class FindingCorrelationReason(StrEnum):
    """Bounded reasons used by the deterministic correlation policy."""

    SAME_FINGERPRINT = "same_fingerprint"
    SAME_CONCRETE_REFERENCE = "same_concrete_reference"
    SAME_CLASSIFICATION = "same_classification"
    SAME_ASSET = "same_asset"
    SAME_ENDPOINT = "same_endpoint"
    ENDPOINT_MISSING_ON_ONE_SIDE = "endpoint_missing_on_one_side"
    SAME_TECHNOLOGY = "same_technology"
    TECHNOLOGY_MISSING_ON_ONE_SIDE = "technology_missing_on_one_side"
    CWE_ONLY_CLASSIFICATION = "cwe_only_classification"
    TITLE_ONLY_SIMILARITY = "title_only_similarity"
    CONFLICTING_CONCRETE_REFERENCE = "conflicting_concrete_reference"
    CONFLICTING_CLASSIFICATION = "conflicting_classification"
    CONFLICTING_ENDPOINT = "conflicting_endpoint"
    CONFLICTING_TECHNOLOGY = "conflicting_technology"
    ASSET_MISMATCH = "asset_mismatch"
    INSUFFICIENT_IDENTITY = "insufficient_identity"


class FindingConflictKind(StrEnum):
    """Normal typed disagreements observed during correlation."""

    ASSET_MISMATCH = "asset_mismatch"
    CONCRETE_REFERENCE = "concrete_reference"
    CLASSIFICATION = "classification"
    ENDPOINT = "endpoint"
    TECHNOLOGY = "technology"


class CanonicalAnchorKind(StrEnum):
    """Provider-neutral source of one stable canonical finding identity."""

    CONCRETE_REFERENCE = "concrete_reference"
    CLASSIFICATION_SUBJECT = "classification_subject"


@dataclass(frozen=True, slots=True, repr=False)
class FindingCorrelationKey:
    """Provider-neutral comparison key distinct from exact finding identity."""

    classification_id: str
    normalized_title: str
    asset: AffectedAsset
    endpoint: AffectedEndpoint | None
    technology: AffectedTechnology | None
    concrete_references: tuple[FindingReference, ...]
    weakness_references: tuple[FindingReference, ...]

    def __post_init__(self) -> None:
        _validate_classification_id(self.classification_id)
        _validate_normalized_title(self.normalized_title)
        if not isinstance(cast(object, self.asset), AffectedAsset):
            raise TypeError("correlation asset is invalid")
        if self.endpoint is not None and not isinstance(
            cast(object, self.endpoint), AffectedEndpoint
        ):
            raise TypeError("correlation endpoint is invalid")
        if self.technology is not None and not isinstance(
            cast(object, self.technology), AffectedTechnology
        ):
            raise TypeError("correlation technology is invalid")
        _validate_reference_tuple(
            self.concrete_references,
            allowed=_CONCRETE_REFERENCE_KINDS,
            label="concrete references",
        )
        _validate_reference_tuple(
            self.weakness_references,
            allowed=_WEAKNESS_REFERENCE_KINDS,
            label="weakness references",
        )

    @classmethod
    def from_record(cls, record: FindingRecord) -> "FindingCorrelationKey":
        if not isinstance(cast(object, record), FindingRecord):
            raise TypeError("correlation key requires a FindingRecord")
        references = record.metadata.references
        return cls(
            classification_id=record.classification.identifier,
            normalized_title=" ".join(record.classification.title.casefold().split()),
            asset=record.context.asset,
            endpoint=record.context.endpoint,
            technology=record.context.technology,
            concrete_references=tuple(
                reference
                for reference in references
                if reference.kind in _CONCRETE_REFERENCE_KINDS
            ),
            weakness_references=tuple(
                reference
                for reference in references
                if reference.kind in _WEAKNESS_REFERENCE_KINDS
            ),
        )

    def __repr__(self) -> str:
        return (
            "FindingCorrelationKey("
            f"classification_id={self.classification_id!r}, "
            f"asset_kind={self.asset.kind!r}, "
            f"has_endpoint={self.endpoint is not None!r}, "
            f"has_technology={self.technology is not None!r}, "
            f"concrete_reference_count={len(self.concrete_references)!r}, "
            f"weakness_reference_count={len(self.weakness_references)!r})"
        )


def _validate_reference_tuple(
    value: object,
    *,
    allowed: frozenset[FindingReferenceKind],
    label: str,
) -> None:
    if not isinstance(value, tuple) or not all(
        isinstance(item, FindingReference) and item.kind in allowed
        for item in cast(tuple[object, ...], value)
    ):
        raise TypeError(f"correlation {label} are invalid")
    typed = cast(tuple[FindingReference, ...], value)
    if len(typed) > _MAX_AGGREGATE_ITEMS:
        raise ValueError(f"too many correlation {label}")
    if tuple(sorted(set(typed))) != typed:
        raise ValueError(f"correlation {label} must be canonical")


def _validate_classification_id(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) > _MAX_CLASSIFICATION_ID
        or re.fullmatch(r"[a-z0-9]+(?:_[a-z0-9]+)*", value) is None
    ):
        raise ValueError("correlation classification is invalid")


def _validate_normalized_title(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > _MAX_NORMALIZED_TITLE
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("correlation title is invalid")


@dataclass(frozen=True, slots=True, order=True, repr=False)
class FindingConflict:
    """Typed disagreement retained without exposing conflicting values."""

    kind: FindingConflictKind
    blocking: bool

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.kind), FindingConflictKind):
            raise TypeError("finding conflict kind is invalid")
        if not isinstance(cast(object, self.blocking), bool):
            raise TypeError("finding conflict blocking flag is invalid")

    def __repr__(self) -> str:
        return f"FindingConflict(kind={self.kind!r}, blocking={self.blocking!r})"


@dataclass(frozen=True, slots=True, repr=False)
class FindingCorrelationDecision:
    """Immutable pairwise decision with safe record references and reasons."""

    left_fingerprint: FindingFingerprint
    right_fingerprint: FindingFingerprint
    strength: CorrelationMatchStrength
    reasons: tuple[FindingCorrelationReason, ...]
    conflicts: tuple[FindingConflict, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.left_fingerprint), FindingFingerprint):
            raise TypeError("left correlation fingerprint is invalid")
        if not isinstance(cast(object, self.right_fingerprint), FindingFingerprint):
            raise TypeError("right correlation fingerprint is invalid")
        if self.right_fingerprint < self.left_fingerprint:
            left = self.left_fingerprint
            object.__setattr__(self, "left_fingerprint", self.right_fingerprint)
            object.__setattr__(self, "right_fingerprint", left)
        if not isinstance(cast(object, self.strength), CorrelationMatchStrength):
            raise TypeError("correlation strength is invalid")
        object.__setattr__(self, "reasons", _enum_tuple(self.reasons, FindingCorrelationReason))
        if not self.reasons:
            raise ValueError("correlation decision requires reasons")
        object.__setattr__(self, "conflicts", _conflict_tuple(self.conflicts))

    @property
    def automatic_merge(self) -> bool:
        return self.strength in {
            CorrelationMatchStrength.EXACT,
            CorrelationMatchStrength.STRONG,
        } and not any(conflict.blocking for conflict in self.conflicts)

    def __repr__(self) -> str:
        return (
            "FindingCorrelationDecision("
            f"strength={self.strength!r}, reason_count={len(self.reasons)!r}, "
            f"conflict_count={len(self.conflicts)!r})"
        )


def _enum_tuple[T: StrEnum](value: object, item_type: type[T]) -> tuple[T, ...]:
    if not isinstance(value, tuple) or not all(
        isinstance(item, item_type) for item in cast(tuple[object, ...], value)
    ):
        raise TypeError("correlation reasons are invalid")
    return tuple(sorted(set(cast(tuple[T, ...], value)), key=lambda item: item.value))


def _conflict_tuple(value: object) -> tuple[FindingConflict, ...]:
    if not isinstance(value, tuple) or not all(
        isinstance(item, FindingConflict) for item in cast(tuple[object, ...], value)
    ):
        raise TypeError("correlation conflicts are invalid")
    return tuple(
        sorted(
            set(cast(tuple[FindingConflict, ...], value)),
            key=lambda item: (item.kind.value, item.blocking),
        )
    )


@dataclass(frozen=True, slots=True, repr=False)
class CanonicalFindingAnchor:
    """Stable provider-neutral material used to derive a canonical ID."""

    kind: CanonicalAnchorKind
    asset: AffectedAsset
    reference: FindingReference | None = None
    classification_id: str | None = None
    endpoint: AffectedEndpoint | None = None
    technology: AffectedTechnology | None = None

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.kind), CanonicalAnchorKind):
            raise TypeError("canonical anchor kind is invalid")
        if not isinstance(cast(object, self.asset), AffectedAsset):
            raise TypeError("canonical anchor asset is invalid")
        if self.kind is CanonicalAnchorKind.CONCRETE_REFERENCE:
            reference = self.reference
            if (
                not isinstance(reference, FindingReference)
                or reference.kind not in _CONCRETE_REFERENCE_KINDS
                or self.classification_id is not None
            ):
                raise ValueError("concrete canonical anchor is invalid")
        elif (
            self.reference is not None
        ):
            raise ValueError("classification canonical anchor is invalid")
        else:
            _validate_classification_id(self.classification_id)
        if self.endpoint is not None and not isinstance(
            cast(object, self.endpoint), AffectedEndpoint
        ):
            raise TypeError("canonical anchor endpoint is invalid")
        if self.technology is not None and not isinstance(
            cast(object, self.technology), AffectedTechnology
        ):
            raise TypeError("canonical anchor technology is invalid")

    def __repr__(self) -> str:
        return (
            "CanonicalFindingAnchor("
            f"kind={self.kind!r}, asset_kind={self.asset.kind!r}, "
            f"has_endpoint={self.endpoint is not None!r}, "
            f"has_technology={self.technology is not None!r})"
        )


@dataclass(frozen=True, slots=True, order=True, repr=False)
class CanonicalFindingId:
    """SHA-256 identity derived only from a canonical correlation anchor."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.value), str) or re.fullmatch(
            r"finding_[0-9a-f]{64}", self.value
        ) is None:
            raise ValueError("canonical finding ID is invalid")

    @classmethod
    def from_anchor(cls, anchor: CanonicalFindingAnchor) -> "CanonicalFindingId":
        if not isinstance(cast(object, anchor), CanonicalFindingAnchor):
            raise TypeError("canonical finding ID requires an anchor")
        reference = anchor.reference
        endpoint = anchor.endpoint
        technology = anchor.technology
        payload = (
            anchor.kind.value,
            reference.kind.value if reference is not None else "",
            reference.value if reference is not None else "",
            anchor.classification_id or "",
            anchor.asset.kind.value,
            anchor.asset.value,
            endpoint.scheme if endpoint is not None else "",
            endpoint.hostname if endpoint is not None else "",
            str(endpoint.port) if endpoint is not None else "",
            endpoint.path if endpoint is not None else "",
            technology.name if technology is not None else "",
            technology.version if technology is not None and technology.version else "",
        )
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return cls(f"finding_{hashlib.sha256(encoded).hexdigest()}")

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return "CanonicalFindingId(value=<sha256>)"


@dataclass(frozen=True, slots=True, repr=False)
class CanonicalFinding:
    """Immutable deterministic aggregate retaining normalized source records."""

    canonical_id: CanonicalFindingId
    anchor: CanonicalFindingAnchor
    source_records: tuple[FindingRecord, ...]
    references: tuple[FindingReference, ...]
    evidence_summaries: tuple[EvidenceSummary, ...]
    detection_methods: tuple[DetectionMethod, ...]
    provenance_sources: tuple[EvidenceSource, ...]
    observed_severities: tuple[FindingSeverity, ...]
    strongest_confidence: EvidenceConfidence
    strongest_evidence_quality: EvidenceQuality
    conflicts: tuple[FindingConflict, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.canonical_id), CanonicalFindingId):
            raise TypeError("canonical finding identity is invalid")
        if not isinstance(cast(object, self.anchor), CanonicalFindingAnchor):
            raise TypeError("canonical finding anchor is invalid")
        if self.canonical_id != CanonicalFindingId.from_anchor(self.anchor):
            raise ValueError("canonical finding identity does not match anchor")
        object.__setattr__(self, "source_records", _record_tuple(self.source_records))
        if not self.source_records:
            raise ValueError("canonical finding requires source records")
        object.__setattr__(self, "references", _value_tuple(self.references, FindingReference))
        object.__setattr__(
            self,
            "evidence_summaries",
            _value_tuple(self.evidence_summaries, EvidenceSummary),
        )
        object.__setattr__(
            self,
            "detection_methods",
            _enum_tuple(self.detection_methods, DetectionMethod),
        )
        object.__setattr__(
            self,
            "provenance_sources",
            _value_tuple(self.provenance_sources, EvidenceSource),
        )
        object.__setattr__(
            self,
            "observed_severities",
            _enum_tuple(self.observed_severities, FindingSeverity),
        )
        if not isinstance(cast(object, self.strongest_confidence), EvidenceConfidence):
            raise TypeError("canonical confidence is invalid")
        if not isinstance(
            cast(object, self.strongest_evidence_quality), EvidenceQuality
        ):
            raise TypeError("canonical evidence quality is invalid")
        object.__setattr__(self, "conflicts", _conflict_tuple(self.conflicts))

    def __repr__(self) -> str:
        return (
            "CanonicalFinding("
            f"canonical_id={self.canonical_id!r}, "
            f"source_count={len(self.source_records)!r}, "
            f"conflict_count={len(self.conflicts)!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CanonicalFindingCollection:
    """Canonical findings plus deterministic unmerged pairwise decisions."""

    findings: tuple[CanonicalFinding, ...] = ()
    unmerged_decisions: tuple[FindingCorrelationDecision, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.findings), tuple) or not all(
            isinstance(item, CanonicalFinding)
            for item in cast(tuple[object, ...], self.findings)
        ):
            raise TypeError("canonical findings must be an immutable tuple")
        if len(self.findings) > _MAX_CORRELATION_RECORDS:
            raise ValueError("too many canonical findings")
        by_id: dict[CanonicalFindingId, CanonicalFinding] = {}
        for finding in self.findings:
            existing = by_id.get(finding.canonical_id)
            if existing is not None and existing != finding:
                raise ValueError("canonical finding identities conflict")
            by_id.setdefault(finding.canonical_id, finding)
        object.__setattr__(
            self,
            "findings",
            tuple(by_id[key] for key in sorted(by_id)),
        )
        if not isinstance(cast(object, self.unmerged_decisions), tuple) or not all(
            isinstance(item, FindingCorrelationDecision)
            and not item.automatic_merge
            for item in cast(tuple[object, ...], self.unmerged_decisions)
        ):
            raise TypeError("unmerged correlation decisions are invalid")
        object.__setattr__(
            self,
            "unmerged_decisions",
            tuple(sorted(set(self.unmerged_decisions), key=_decision_sort_key)),
        )
        if len(self.unmerged_decisions) > _MAX_UNMERGED_DECISIONS:
            raise ValueError("too many unmerged correlation decisions")

    def __len__(self) -> int:
        return len(self.findings)

    def __iter__(self):
        return iter(self.findings)

    def __repr__(self) -> str:
        return (
            "CanonicalFindingCollection("
            f"finding_count={len(self.findings)!r}, "
            f"unmerged_decision_count={len(self.unmerged_decisions)!r})"
        )


def _value_tuple[T](value: object, item_type: type[T]) -> tuple[T, ...]:
    if not isinstance(value, tuple) or not all(
        isinstance(item, item_type) for item in cast(tuple[object, ...], value)
    ):
        raise TypeError("canonical aggregate collection is invalid")
    typed = cast(tuple[T, ...], value)
    if len(typed) > _MAX_AGGREGATE_ITEMS:
        raise ValueError("canonical aggregate collection is too large")
    return tuple(sorted(set(typed), key=_aggregate_value_key))


def _aggregate_value_key(value: object) -> tuple[str, ...]:
    if isinstance(value, FindingReference):
        return ("reference", value.kind.value, value.value)
    if isinstance(value, EvidenceSummary):
        return ("summary", value.value)
    if isinstance(value, EvidenceSource):
        return ("source", value.kind.value, value.name)
    raise TypeError("canonical aggregate item is invalid")


def _record_sort_key(record: FindingRecord) -> tuple[object, ...]:
    endpoint = record.context.endpoint
    technology = record.context.technology
    concrete = tuple(
        (reference.kind.value, reference.value)
        for reference in record.metadata.references
        if reference.kind in _CONCRETE_REFERENCE_KINDS
    )
    return (
        concrete,
        record.context.asset.kind.value,
        record.context.asset.value,
        endpoint is None,
        endpoint.canonical_url if endpoint is not None else "",
        technology is None,
        technology.name if technology is not None else "",
        technology.version if technology is not None and technology.version else "",
        record.fingerprint.value,
        record.metadata.source.kind.value,
        record.metadata.source.name,
        record.metadata.source_record_id or "",
        record.classification.severity.value,
        tuple(
            (
                evidence.kind.value,
                evidence.method.value,
                evidence.confidence.value,
                evidence.quality.value,
                evidence.source.kind.value,
                evidence.source.name,
                evidence.summary.value,
            )
            for evidence in record.evidence
        ),
    )


def _record_tuple(value: object) -> tuple[FindingRecord, ...]:
    if not isinstance(value, tuple) or not all(
        isinstance(item, FindingRecord) for item in cast(tuple[object, ...], value)
    ):
        raise TypeError("canonical source records are invalid")
    typed = cast(tuple[FindingRecord, ...], value)
    if len(typed) > _MAX_CORRELATION_RECORDS:
        raise ValueError("too many source records for correlation")
    return tuple(sorted(set(typed), key=_record_sort_key))


def _decision_sort_key(decision: FindingCorrelationDecision) -> tuple[object, ...]:
    return (
        decision.left_fingerprint.value,
        decision.right_fingerprint.value,
        decision.strength.value,
        tuple(reason.value for reason in decision.reasons),
        tuple((conflict.kind.value, conflict.blocking) for conflict in decision.conflicts),
    )


_CONFIDENCE_RANK = {
    EvidenceConfidence.UNKNOWN: 0,
    EvidenceConfidence.LOW: 1,
    EvidenceConfidence.MEDIUM: 2,
    EvidenceConfidence.HIGH: 3,
    EvidenceConfidence.CERTAIN: 4,
}
_QUALITY_RANK = {
    EvidenceQuality.UNKNOWN: 0,
    EvidenceQuality.WEAK: 1,
    EvidenceQuality.NORMAL: 2,
    EvidenceQuality.STRONG: 3,
    EvidenceQuality.VERIFIED: 4,
}


class FindingCorrelator:
    """Pure pairwise comparison, deterministic grouping, and aggregation service."""

    @staticmethod
    def compare(
        left: FindingRecord,
        right: FindingRecord,
    ) -> FindingCorrelationDecision:
        if not isinstance(cast(object, left), FindingRecord) or not isinstance(
            cast(object, right), FindingRecord
        ):
            raise TypeError("finding correlation requires FindingRecord values")
        left_key = FindingCorrelationKey.from_record(left)
        right_key = FindingCorrelationKey.from_record(right)
        reasons: list[FindingCorrelationReason] = []
        conflicts: list[FindingConflict] = []

        if left_key.asset != right_key.asset:
            return _decision(
                left,
                right,
                CorrelationMatchStrength.NO_MATCH,
                (FindingCorrelationReason.ASSET_MISMATCH,),
                (FindingConflict(FindingConflictKind.ASSET_MISMATCH, True),),
            )
        reasons.append(FindingCorrelationReason.SAME_ASSET)

        left_concrete = set(left_key.concrete_references)
        right_concrete = set(right_key.concrete_references)
        shared_concrete = left_concrete & right_concrete
        if _concrete_references_conflict(left_concrete, right_concrete):
            reasons.append(FindingCorrelationReason.CONFLICTING_CONCRETE_REFERENCE)
            conflicts.append(FindingConflict(FindingConflictKind.CONCRETE_REFERENCE, True))
            return _decision(
                left,
                right,
                CorrelationMatchStrength.NO_MATCH,
                tuple(reasons),
                tuple(conflicts),
            )
        if shared_concrete:
            reasons.append(FindingCorrelationReason.SAME_CONCRETE_REFERENCE)
        same_concrete_anchor = (
            bool(shared_concrete)
            and _selected_concrete_anchor(left_concrete)
            == _selected_concrete_anchor(right_concrete)
        )

        if left_key.endpoint is not None and right_key.endpoint is not None:
            if left_key.endpoint != right_key.endpoint:
                reasons.append(FindingCorrelationReason.CONFLICTING_ENDPOINT)
                conflicts.append(FindingConflict(FindingConflictKind.ENDPOINT, True))
                return _decision(
                    left,
                    right,
                    CorrelationMatchStrength.NO_MATCH,
                    tuple(reasons),
                    tuple(conflicts),
                )
            reasons.append(FindingCorrelationReason.SAME_ENDPOINT)
        elif (left_key.endpoint is None) != (right_key.endpoint is None):
            reasons.append(FindingCorrelationReason.ENDPOINT_MISSING_ON_ONE_SIDE)

        if left_key.technology is not None and right_key.technology is not None:
            if left_key.technology != right_key.technology:
                reasons.append(FindingCorrelationReason.CONFLICTING_TECHNOLOGY)
                conflicts.append(FindingConflict(FindingConflictKind.TECHNOLOGY, True))
                return _decision(
                    left,
                    right,
                    CorrelationMatchStrength.NO_MATCH,
                    tuple(reasons),
                    tuple(conflicts),
                )
            reasons.append(FindingCorrelationReason.SAME_TECHNOLOGY)
        elif (left_key.technology is None) != (right_key.technology is None):
            reasons.append(FindingCorrelationReason.TECHNOLOGY_MISSING_ON_ONE_SIDE)

        same_classification = (
            left_key.classification_id == right_key.classification_id
        )
        if same_classification:
            reasons.append(FindingCorrelationReason.SAME_CLASSIFICATION)
        else:
            reasons.append(FindingCorrelationReason.CONFLICTING_CLASSIFICATION)
            conflicts.append(
                FindingConflict(
                    FindingConflictKind.CLASSIFICATION,
                    not bool(shared_concrete),
                )
            )

        if left.fingerprint == right.fingerprint:
            reasons.append(FindingCorrelationReason.SAME_FINGERPRINT)
            return _decision(
                left,
                right,
                CorrelationMatchStrength.EXACT,
                tuple(reasons),
                tuple(conflicts),
            )

        if same_concrete_anchor:
            complete_endpoint = (
                left_key.endpoint is not None
                and right_key.endpoint is not None
                and left_key.endpoint == right_key.endpoint
            )
            complete_technology = (
                (left_key.technology is None and right_key.technology is None)
                or (
                    left_key.technology is not None
                    and left_key.technology == right_key.technology
                )
            )
            strength = (
                CorrelationMatchStrength.EXACT
                if complete_endpoint and complete_technology
                else CorrelationMatchStrength.STRONG
            )
            return _decision(
                left,
                right,
                strength,
                tuple(reasons),
                tuple(conflicts),
            )

        if shared_concrete:
            reasons.append(FindingCorrelationReason.INSUFFICIENT_IDENTITY)
            return _decision(
                left,
                right,
                CorrelationMatchStrength.POSSIBLE,
                tuple(reasons),
                tuple(conflicts),
            )

        common_weakness = set(left_key.weakness_references) & set(
            right_key.weakness_references
        )
        if common_weakness:
            reasons.append(FindingCorrelationReason.CWE_ONLY_CLASSIFICATION)
        if not same_classification:
            if left_key.normalized_title == right_key.normalized_title:
                reasons.append(FindingCorrelationReason.TITLE_ONLY_SIMILARITY)
            return _decision(
                left,
                right,
                CorrelationMatchStrength.NO_MATCH,
                tuple(reasons),
                tuple(conflicts),
            )
        reasons.append(FindingCorrelationReason.INSUFFICIENT_IDENTITY)
        return _decision(
            left,
            right,
            CorrelationMatchStrength.POSSIBLE,
            tuple(reasons),
            tuple(conflicts),
        )

    @staticmethod
    def correlate(
        collection: FindingRecordCollection,
    ) -> CanonicalFindingCollection:
        if not isinstance(cast(object, collection), FindingRecordCollection):
            raise TypeError("correlation requires a FindingRecordCollection")
        return FindingCorrelator.group(collection.records)

    @staticmethod
    def group(records: tuple[FindingRecord, ...]) -> CanonicalFindingCollection:
        ordered = _record_tuple(records)
        groups: list[list[FindingRecord]] = []
        for record in ordered:
            candidates = [
                index
                for index, group in enumerate(groups)
                if all(
                    FindingCorrelator.compare(existing, record).automatic_merge
                    for existing in group
                )
            ]
            if len(candidates) == 1:
                groups[candidates[0]].append(record)
            else:
                groups.append([record])

        findings = tuple(
            _aggregate(tuple(group))
            for group in groups
        )
        unmerged = tuple(
            decision
            for left, right in combinations(ordered, 2)
            if not (decision := FindingCorrelator.compare(left, right)).automatic_merge
        )
        return CanonicalFindingCollection(findings, unmerged)


def _decision(
    left: FindingRecord,
    right: FindingRecord,
    strength: CorrelationMatchStrength,
    reasons: tuple[FindingCorrelationReason, ...],
    conflicts: tuple[FindingConflict, ...],
) -> FindingCorrelationDecision:
    return FindingCorrelationDecision(
        left.fingerprint,
        right.fingerprint,
        strength,
        reasons,
        conflicts,
    )


def _concrete_references_conflict(
    left: set[FindingReference],
    right: set[FindingReference],
) -> bool:
    if not left or not right:
        return False
    if not left & right:
        return True
    for kind in _CONCRETE_REFERENCE_KINDS:
        left_of_kind = {reference for reference in left if reference.kind is kind}
        right_of_kind = {reference for reference in right if reference.kind is kind}
        if left_of_kind and right_of_kind and not left_of_kind & right_of_kind:
            return True
    return False


def _selected_concrete_anchor(
    references: set[FindingReference],
) -> FindingReference | None:
    return min(references, key=_reference_anchor_key) if references else None


def _aggregate(records: tuple[FindingRecord, ...]) -> CanonicalFinding:
    ordered = _record_tuple(records)
    anchor = _anchor_for(ordered)
    evidence = tuple(item for record in ordered for item in record.evidence)
    conflicts = tuple(
        conflict
        for left, right in combinations(ordered, 2)
        for conflict in FindingCorrelator.compare(left, right).conflicts
        if not conflict.blocking
    )
    return CanonicalFinding(
        canonical_id=CanonicalFindingId.from_anchor(anchor),
        anchor=anchor,
        source_records=ordered,
        references=tuple(
            reference
            for record in ordered
            for reference in record.metadata.references
        ),
        evidence_summaries=tuple(item.summary for item in evidence),
        detection_methods=tuple(item.method for item in evidence),
        provenance_sources=tuple(
            record.metadata.source for record in ordered
        )
        + tuple(
            item.source for item in evidence
        ),
        observed_severities=tuple(
            record.classification.severity for record in ordered
        ),
        strongest_confidence=max(
            (item.confidence for item in evidence),
            key=_CONFIDENCE_RANK.__getitem__,
        ),
        strongest_evidence_quality=max(
            (item.quality for item in evidence),
            key=_QUALITY_RANK.__getitem__,
        ),
        conflicts=conflicts,
    )


def _anchor_for(records: tuple[FindingRecord, ...]) -> CanonicalFindingAnchor:
    keys = tuple(FindingCorrelationKey.from_record(record) for record in records)
    common_concrete = set(keys[0].concrete_references)
    for key in keys[1:]:
        common_concrete &= set(key.concrete_references)
    endpoints = {key.endpoint for key in keys if key.endpoint is not None}
    technologies = {key.technology for key in keys if key.technology is not None}
    endpoint = next(iter(endpoints)) if len(endpoints) == 1 else None
    technology = next(iter(technologies)) if len(technologies) == 1 else None
    if common_concrete:
        selected_anchors = {
            _selected_concrete_anchor(set(key.concrete_references)) for key in keys
        }
        if len(selected_anchors) != 1 or None in selected_anchors:
            raise ValueError("correlated records do not share a stable concrete anchor")
        reference = cast(FindingReference, next(iter(selected_anchors)))
        return CanonicalFindingAnchor(
            kind=CanonicalAnchorKind.CONCRETE_REFERENCE,
            asset=keys[0].asset,
            reference=reference,
            endpoint=endpoint,
            technology=technology,
        )
    identity = records[0].identity
    return CanonicalFindingAnchor(
        kind=CanonicalAnchorKind.CLASSIFICATION_SUBJECT,
        asset=identity.asset,
        classification_id=identity.classification_id,
        endpoint=identity.endpoint,
        technology=identity.technology,
    )


def _reference_anchor_key(reference: FindingReference) -> tuple[int, str]:
    priority = {
        FindingReferenceKind.CVE: 0,
        FindingReferenceKind.GHSA: 1,
        FindingReferenceKind.OSV: 2,
    }
    return priority[reference.kind], reference.value


__all__ = [
    "CanonicalAnchorKind",
    "CanonicalFinding",
    "CanonicalFindingAnchor",
    "CanonicalFindingCollection",
    "CanonicalFindingId",
    "CorrelationMatchStrength",
    "FindingConflict",
    "FindingConflictKind",
    "FindingCorrelationDecision",
    "FindingCorrelationKey",
    "FindingCorrelationReason",
    "FindingCorrelator",
]
