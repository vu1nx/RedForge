"""Offline tests for conservative canonical finding correlation."""

from dataclasses import FrozenInstanceError
from itertools import permutations

import pytest  # type: ignore[reportMissingImports]

from redforge.domain import (
    AffectedAsset,
    AffectedEndpoint,
    AffectedTechnology,
    AssetIdentityKind,
    CanonicalFinding,
    CanonicalFindingCollection,
    CanonicalFindingId,
    CorrelationMatchStrength,
    DetectionMethod,
    EvidenceConfidence,
    EvidenceKind,
    EvidenceQuality,
    EvidenceSource,
    EvidenceSourceKind,
    EvidenceSummary,
    FindingClassification,
    FindingConflictKind,
    FindingContext,
    FindingCorrelationKey,
    FindingCorrelationReason,
    FindingCorrelator,
    FindingEvidence,
    FindingIdentity,
    FindingMetadata,
    FindingRecord,
    FindingRecordCollection,
    FindingReference,
    FindingReferenceKind,
    FindingSeverity,
    FindingTag,
    finding_fingerprint,
)


def _reference(kind: FindingReferenceKind, value: str) -> FindingReference:
    return FindingReference(kind, value)


CVE = _reference(FindingReferenceKind.CVE, "CVE-2026-12345")
OTHER_CVE = _reference(FindingReferenceKind.CVE, "CVE-2026-54321")
GHSA = _reference(FindingReferenceKind.GHSA, "GHSA-2345-6789-cfgh")
OSV = _reference(FindingReferenceKind.OSV, "OSV-2026-EXAMPLE")
CWE = _reference(FindingReferenceKind.CWE, "CWE-79")


def _record(
    *,
    classification_id: str = "reflected_xss",
    title: str = "Reflected XSS",
    asset: str = "app.example.test",
    endpoint: str | None = "https://app.example.test/login",
    technology: tuple[str, str | None] | None = ("Example Server", "1.0"),
    references: tuple[FindingReference, ...] = (),
    source: str = "scanner_a",
    source_record_id: str | None = "record-a",
    severity: FindingSeverity = FindingSeverity.MEDIUM,
    confidence: EvidenceConfidence = EvidenceConfidence.HIGH,
    quality: EvidenceQuality = EvidenceQuality.STRONG,
    method: DetectionMethod = DetectionMethod.ACTIVE,
    summary: str = "Sanitized condition was observed.",
) -> FindingRecord:
    affected_asset = AffectedAsset(AssetIdentityKind.HOSTNAME, asset)
    affected_endpoint = AffectedEndpoint.from_url(endpoint) if endpoint else None
    affected_technology = (
        AffectedTechnology(*technology) if technology is not None else None
    )
    classification = FindingClassification(
        classification_id,
        title,
        severity,
    )
    identity = FindingIdentity(
        classification.identifier,
        affected_asset,
        affected_endpoint,
        affected_technology,
    )
    evidence_source = EvidenceSource(EvidenceSourceKind.TOOL, source)
    return FindingRecord(
        identity=identity,
        fingerprint=finding_fingerprint(identity),
        classification=classification,
        context=FindingContext(
            affected_asset,
            affected_endpoint,
            affected_technology,
        ),
        evidence=(
            FindingEvidence(
                EvidenceKind.HTTP,
                method,
                confidence,
                quality,
                evidence_source,
                EvidenceSummary(summary),
            ),
        ),
        metadata=FindingMetadata(
            evidence_source,
            source_record_id,
            tags=(FindingTag("web"),),
            references=references,
        ),
    )


def test_identical_fingerprint_is_exact_and_order_independent() -> None:
    left = _record(source="scanner_a")
    right = _record(source="scanner_b")

    forward = FindingCorrelator.compare(left, right)
    reverse = FindingCorrelator.compare(right, left)

    assert forward == reverse
    assert forward.strength is CorrelationMatchStrength.EXACT
    assert forward.automatic_merge
    assert FindingCorrelationReason.SAME_FINGERPRINT in forward.reasons


@pytest.mark.parametrize("reference", (CVE, GHSA, OSV))
def test_same_concrete_reference_and_subject_is_exact(
    reference: FindingReference,
) -> None:
    left = _record(references=(reference,), classification_id="provider_a")
    right = _record(
        references=(reference,),
        classification_id="provider_b",
        title="Different provider label",
        source="scanner_b",
    )

    decision = FindingCorrelator.compare(left, right)

    assert decision.strength is CorrelationMatchStrength.EXACT
    assert decision.automatic_merge
    assert FindingCorrelationReason.SAME_CONCRETE_REFERENCE in decision.reasons
    assert FindingCorrelationReason.CONFLICTING_CLASSIFICATION in decision.reasons
    assert decision.conflicts[0].kind is FindingConflictKind.CLASSIFICATION
    assert not decision.conflicts[0].blocking


def test_conflicting_concrete_references_are_no_match() -> None:
    decision = FindingCorrelator.compare(
        _record(references=(CVE,)),
        _record(references=(OTHER_CVE,), source="scanner_b"),
    )

    assert decision.strength is CorrelationMatchStrength.NO_MATCH
    assert not decision.automatic_merge
    assert FindingCorrelationReason.CONFLICTING_CONCRETE_REFERENCE in decision.reasons
    assert decision.conflicts[0].blocking

    conflicting_alias = _reference(
        FindingReferenceKind.GHSA,
        "GHSA-3456-789C-FGHJ",
    )
    partial_overlap = FindingCorrelator.compare(
        _record(references=(CVE, GHSA)),
        _record(
            references=(CVE, conflicting_alias),
            source="scanner_b",
        ),
    )
    assert partial_overlap.strength is CorrelationMatchStrength.NO_MATCH
    assert partial_overlap.conflicts[0].kind is FindingConflictKind.CONCRETE_REFERENCE


def test_shared_secondary_reference_does_not_change_canonical_anchor() -> None:
    multi_reference = _record(references=(CVE, GHSA))
    ghsa_only = _record(
        references=(GHSA,),
        source="scanner_b",
        classification_id="provider_b",
        title="Provider B label",
    )

    decision = FindingCorrelator.compare(multi_reference, ghsa_only)
    collection = FindingCorrelator.group((multi_reference, ghsa_only))

    assert decision.strength is CorrelationMatchStrength.POSSIBLE
    assert not decision.automatic_merge
    assert len(collection.findings) == 2
    assert (
        FindingCorrelator.group((multi_reference,)).findings[0].canonical_id
        in {finding.canonical_id for finding in collection.findings}
    )


def test_cross_scheme_and_arbitrary_advisory_aliases_are_not_inferred() -> None:
    cross_scheme = FindingCorrelator.compare(
        _record(references=(CVE,)),
        _record(references=(GHSA,), source="scanner_b"),
    )
    advisory = _reference(
        FindingReferenceKind.VENDOR_ADVISORY,
        "https://security.example.test/advisory-1",
    )
    same_advisory = FindingCorrelator.compare(
        _record(
            references=(advisory,),
            endpoint=None,
        ),
        _record(
            references=(advisory,),
            endpoint=None,
            technology=None,
            source="scanner_b",
        ),
    )

    assert cross_scheme.strength is CorrelationMatchStrength.NO_MATCH
    assert FindingCorrelationReason.CONFLICTING_CONCRETE_REFERENCE in (
        cross_scheme.reasons
    )
    assert same_advisory.strength is CorrelationMatchStrength.POSSIBLE
    assert not same_advisory.automatic_merge


def test_cwe_is_never_a_concrete_anchor_or_unsafe_merge_signal() -> None:
    different_endpoints = FindingCorrelator.compare(
        _record(references=(CWE,), endpoint="https://app.example.test/a"),
        _record(
            references=(CWE,),
            endpoint="https://app.example.test/b",
            source="scanner_b",
        ),
    )
    missing_endpoint = FindingCorrelator.compare(
        _record(references=(CWE,)),
        _record(references=(CWE,), endpoint=None, source="scanner_b"),
    )
    conflicting_technology = FindingCorrelator.compare(
        _record(references=(CWE,), technology=("Server A", "1")),
        _record(
            references=(CWE,),
            technology=("Server B", "1"),
            source="scanner_b",
        ),
    )

    assert different_endpoints.strength is CorrelationMatchStrength.NO_MATCH
    assert missing_endpoint.strength is CorrelationMatchStrength.POSSIBLE
    assert not missing_endpoint.automatic_merge
    assert FindingCorrelationReason.CWE_ONLY_CLASSIFICATION in missing_endpoint.reasons
    assert conflicting_technology.strength is CorrelationMatchStrength.NO_MATCH


def test_missing_context_widens_only_with_shared_concrete_reference() -> None:
    concrete_endpoint = FindingCorrelator.compare(
        _record(references=(CVE,)),
        _record(references=(CVE,), endpoint=None, source="scanner_b"),
    )
    generic_endpoint = FindingCorrelator.compare(
        _record(),
        _record(endpoint=None, source="scanner_b"),
    )
    concrete_technology = FindingCorrelator.compare(
        _record(references=(CVE,)),
        _record(references=(CVE,), technology=None, source="scanner_b"),
    )
    generic_technology = FindingCorrelator.compare(
        _record(),
        _record(technology=None, source="scanner_b"),
    )

    assert concrete_endpoint.strength is CorrelationMatchStrength.STRONG
    assert concrete_endpoint.automatic_merge
    assert generic_endpoint.strength is CorrelationMatchStrength.POSSIBLE
    assert not generic_endpoint.automatic_merge
    assert concrete_technology.strength is CorrelationMatchStrength.STRONG
    assert generic_technology.strength is CorrelationMatchStrength.POSSIBLE


def test_explicit_subject_conflicts_block_even_shared_concrete_references() -> None:
    endpoint_conflict = FindingCorrelator.compare(
        _record(references=(CVE,), endpoint="https://app.example.test/a"),
        _record(
            references=(CVE,),
            endpoint="https://app.example.test/b",
            source="scanner_b",
        ),
    )
    technology_conflict = FindingCorrelator.compare(
        _record(references=(CVE,), technology=("Server A", "1")),
        _record(
            references=(CVE,),
            technology=("Server B", "1"),
            source="scanner_b",
        ),
    )
    asset_conflict = FindingCorrelator.compare(
        _record(references=(CVE,)),
        _record(
            references=(CVE,),
            asset="other.example.test",
            source="scanner_b",
        ),
    )

    assert endpoint_conflict.strength is CorrelationMatchStrength.NO_MATCH
    assert technology_conflict.strength is CorrelationMatchStrength.NO_MATCH
    assert asset_conflict.strength is CorrelationMatchStrength.NO_MATCH
    assert all(
        decision.conflicts[0].blocking
        for decision in (endpoint_conflict, technology_conflict, asset_conflict)
    )


def test_title_similarity_alone_never_merges() -> None:
    exact_title = FindingCorrelator.compare(
        _record(classification_id="provider_a", title="Shared title"),
        _record(
            classification_id="provider_b",
            title="Shared title",
            source="scanner_b",
        ),
    )
    normalized_title = FindingCorrelator.compare(
        _record(classification_id="provider_a", title="Shared   Title"),
        _record(
            classification_id="provider_b",
            title="shared title",
            source="scanner_b",
        ),
    )

    for decision in (exact_title, normalized_title):
        assert decision.strength is CorrelationMatchStrength.NO_MATCH
        assert not decision.automatic_merge
        assert FindingCorrelationReason.TITLE_ONLY_SIMILARITY in decision.reasons


def test_correlation_key_is_distinct_from_identity_and_classifies_references() -> None:
    record = _record(references=(CVE, CWE))

    key = FindingCorrelationKey.from_record(record)

    assert key != record.identity
    assert key.concrete_references == (CVE,)
    assert key.weakness_references == (CWE,)
    assert "CVE-2026-12345" not in repr(key)


def test_canonical_id_is_stable_for_permutations_and_source_additions() -> None:
    records = (
        _record(references=(CVE,), source="scanner_a", source_record_id="a"),
        _record(
            references=(CVE,),
            source="scanner_b",
            source_record_id="b",
            classification_id="provider_b",
            title="Provider B label",
        ),
        _record(
            references=(CVE,),
            source="scanner_c",
            source_record_id="c",
            severity=FindingSeverity.HIGH,
            confidence=EvidenceConfidence.CERTAIN,
            quality=EvidenceQuality.VERIFIED,
            summary="Different sanitized evidence summary.",
        ),
    )

    outputs = tuple(FindingCorrelator.group(order) for order in permutations(records))
    canonical_ids = {output.findings[0].canonical_id for output in outputs}

    assert len(canonical_ids) == 1
    assert all(output == outputs[0] for output in outputs)
    single_id = FindingCorrelator.group((records[0],)).findings[0].canonical_id
    pair_id = FindingCorrelator.group(records[:2]).findings[0].canonical_id
    assert single_id == pair_id == outputs[0].findings[0].canonical_id


def test_canonical_id_ignores_provider_evidence_and_source_record_metadata() -> None:
    baseline = _record(references=(CVE,))
    variants = (
        _record(references=(CVE,), source="other_provider"),
        _record(references=(CVE,), source_record_id="different-record"),
        _record(references=(CVE,), severity=FindingSeverity.CRITICAL),
        _record(references=(CVE,), confidence=EvidenceConfidence.LOW),
        _record(references=(CVE,), quality=EvidenceQuality.WEAK),
        _record(references=(CVE,), summary="Alternative sanitized evidence."),
    )
    expected = FindingCorrelator.group((baseline,)).findings[0].canonical_id

    assert all(
        FindingCorrelator.group((variant,)).findings[0].canonical_id == expected
        for variant in variants
    )


def test_exact_duplicate_collapses_without_changing_canonical_id() -> None:
    record = _record(references=(CVE,))

    single = FindingCorrelator.group((record,))
    duplicated = FindingCorrelator.group((record, record, record))

    assert single == duplicated
    assert len(duplicated.findings[0].source_records) == 1


def test_aggregation_retains_sources_evidence_references_and_conflicts() -> None:
    first = _record(
        references=(CVE, CWE),
        source="scanner_a",
        classification_id="provider_a",
        severity=FindingSeverity.MEDIUM,
        confidence=EvidenceConfidence.MEDIUM,
        quality=EvidenceQuality.NORMAL,
        method=DetectionMethod.PASSIVE,
        summary="First sanitized summary.",
    )
    second = _record(
        references=(CVE, GHSA),
        source="scanner_b",
        source_record_id="record-b",
        classification_id="provider_b",
        title="Provider B label",
        severity=FindingSeverity.HIGH,
        confidence=EvidenceConfidence.CERTAIN,
        quality=EvidenceQuality.VERIFIED,
        method=DetectionMethod.ACTIVE,
        summary="Second sanitized summary.",
    )

    canonical = FindingCorrelator.group((second, first)).findings[0]

    assert len(canonical.source_records) == 2
    assert canonical.references == tuple(sorted({CVE, CWE, GHSA}))
    assert {item.value for item in canonical.evidence_summaries} == {
        "First sanitized summary.",
        "Second sanitized summary.",
    }
    assert set(canonical.detection_methods) == {
        DetectionMethod.ACTIVE,
        DetectionMethod.PASSIVE,
    }
    assert {source.name for source in canonical.provenance_sources} == {
        "scanner_a",
        "scanner_b",
    }
    assert set(canonical.observed_severities) == {
        FindingSeverity.MEDIUM,
        FindingSeverity.HIGH,
    }
    assert canonical.strongest_confidence is EvidenceConfidence.CERTAIN
    assert canonical.strongest_evidence_quality is EvidenceQuality.VERIFIED
    assert len(canonical.conflicts) == 1
    assert canonical.conflicts[0].kind is FindingConflictKind.CLASSIFICATION
    assert not canonical.conflicts[0].blocking


def test_blocking_conflicts_and_possible_matches_remain_visible_unmerged() -> None:
    first = _record(references=(CVE,), endpoint="https://app.example.test/a")
    conflicting = _record(
        references=(CVE,),
        endpoint="https://app.example.test/b",
        source="scanner_b",
    )
    possible = _record(endpoint=None, source="scanner_c")

    collection = FindingCorrelator.group((first, conflicting, possible))

    assert len(collection.findings) == 3
    assert any(
        decision.strength is CorrelationMatchStrength.NO_MATCH
        and decision.conflicts
        and decision.conflicts[0].blocking
        for decision in collection.unmerged_decisions
    )
    assert any(
        decision.strength is CorrelationMatchStrength.POSSIBLE
        for decision in collection.unmerged_decisions
    )


def test_missing_context_cannot_bridge_two_conflicting_explicit_groups() -> None:
    endpoint_a = _record(references=(CVE,), endpoint="https://app.example.test/a")
    endpoint_b = _record(
        references=(CVE,),
        endpoint="https://app.example.test/b",
        source="scanner_b",
    )
    bridge = _record(
        references=(CVE,),
        endpoint=None,
        source="scanner_c",
    )

    outputs = tuple(
        FindingCorrelator.group(order)
        for order in permutations((bridge, endpoint_b, endpoint_a))
    )

    assert all(output == outputs[0] for output in outputs)
    assert len(outputs[0].findings) == 3


def test_collection_api_accepts_task_0060_record_collection() -> None:
    record = _record()

    result = FindingCorrelator.correlate(FindingRecordCollection((record,)))

    assert isinstance(result, CanonicalFindingCollection)
    assert len(result) == 1


def test_correlation_models_are_frozen_slotted_bounded_and_safely_represented() -> None:
    record = _record(references=(CVE,))
    decision = FindingCorrelator.compare(record, record)
    canonical = FindingCorrelator.group((record,)).findings[0]

    with pytest.raises(FrozenInstanceError):
        decision.strength = CorrelationMatchStrength.NO_MATCH  # type: ignore[misc]
    assert not hasattr(decision, "__dict__")
    assert not hasattr(canonical, "__dict__")
    assert "app.example.test" not in repr(decision)
    assert "app.example.test" not in repr(canonical)
    assert "CVE-2026-12345" not in repr(canonical)
    assert canonical.canonical_id == CanonicalFindingId.from_anchor(canonical.anchor)
    with pytest.raises(ValueError):
        CanonicalFindingId("unstable-id")
    with pytest.raises(ValueError):
        FindingCorrelationKey(
            classification_id="valid_id",
            normalized_title="x" * 513,
            asset=record.context.asset,
            endpoint=None,
            technology=None,
            concrete_references=(),
            weakness_references=(),
        )
    with pytest.raises(ValueError):
        FindingCorrelator.group((record,) * 513)


def test_public_types_are_immutable_tuple_based() -> None:
    record = _record(references=(CVE,))
    result = FindingCorrelator.group((record,))

    assert isinstance(result, CanonicalFindingCollection)
    assert isinstance(result.findings, tuple)
    assert isinstance(result.unmerged_decisions, tuple)
    assert isinstance(result.findings[0], CanonicalFinding)
    assert isinstance(result.findings[0].source_records, tuple)
