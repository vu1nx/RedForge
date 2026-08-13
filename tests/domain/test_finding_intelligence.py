"""Tests for the provider-neutral finding intelligence domain."""

import json
from dataclasses import FrozenInstanceError

import pytest  # type: ignore[reportMissingImports]

from redforge.domain import (
    AffectedAsset,
    AffectedEndpoint,
    AffectedTechnology,
    AssetIdentityKind,
    DetectionMethod,
    EvidenceConfidence,
    EvidenceKind,
    EvidenceQuality,
    EvidenceSource,
    EvidenceSourceKind,
    EvidenceSummary,
    FindingClassification,
    FindingContext,
    FindingEvidence,
    FindingFingerprint,
    FindingIdentity,
    FindingMetadata,
    FindingRecord,
    FindingRecordCollection,
    FindingReference,
    FindingReferenceKind,
    FindingSeverity,
    FindingTag,
    finding_fingerprint,
    serialize_finding_record,
)


def _record(
    *,
    source: str = "scanner_a",
    title: str = "Missing Security Header",
) -> FindingRecord:
    asset = AffectedAsset(AssetIdentityKind.HOSTNAME, "APP.Example.test.")
    endpoint = AffectedEndpoint.from_url("https://app.example.test:8443/login")
    technology = AffectedTechnology("Example Server", "1.0")
    classification = FindingClassification.from_title(
        title,
        severity=FindingSeverity.MEDIUM,
    )
    identity = FindingIdentity(
        classification.identifier,
        asset,
        endpoint,
        technology,
    )
    evidence_source = EvidenceSource(EvidenceSourceKind.TOOL, source)
    return FindingRecord(
        identity=identity,
        fingerprint=finding_fingerprint(identity),
        classification=classification,
        context=FindingContext(asset, endpoint, technology),
        evidence=(
            FindingEvidence(
                EvidenceKind.HEADER,
                DetectionMethod.ACTIVE,
                EvidenceConfidence.HIGH,
                EvidenceQuality.STRONG,
                evidence_source,
                EvidenceSummary("Sanitized header condition was observed."),
            ),
        ),
        metadata=FindingMetadata(
            source=evidence_source,
            source_record_id="provider-record-1",
            tags=(FindingTag("Web Security"),),
            references=(
                FindingReference(FindingReferenceKind.CWE, "CWE-693"),
            ),
        ),
    )


def test_identity_and_fingerprint_are_provider_neutral_and_deterministic() -> None:
    first = _record(source="scanner_a")
    second = _record(source="scanner_b")

    assert first.identity == second.identity
    assert first.fingerprint == second.fingerprint
    assert first.fingerprint == FindingFingerprint.from_identity(first.identity)
    assert first.metadata.source != second.metadata.source
    assert "scanner" not in first.fingerprint.value

    normalized = AffectedTechnology("EXAMPLE   SERVER", "1.0")
    assert normalized == AffectedTechnology("example server", "1.0")


def test_models_are_frozen_slotted_bounded_and_have_safe_repr() -> None:
    record = _record()

    with pytest.raises(FrozenInstanceError):
        record.status = "changed"  # type: ignore[misc]
    assert not hasattr(record, "__dict__")
    assert "Sanitized header condition" not in repr(record)
    assert "app.example.test" not in repr(record)
    assert "provider-record-1" not in repr(record.metadata)
    assert "Missing Security Header" not in repr(record.classification)
    assert "app.example.test" not in repr(record.context)
    assert "provider-record-1" not in repr(record.metadata.references[0])
    with pytest.raises(ValueError):
        EvidenceSummary("x" * 513)
    with pytest.raises(ValueError):
        FindingTag("!!!")


def test_reference_validation_is_typed_and_bounded() -> None:
    assert (
        FindingReference(FindingReferenceKind.CVE, "CVE-2026-12345").kind
        is FindingReferenceKind.CVE
    )
    assert FindingReference(FindingReferenceKind.GHSA, "GHSA-2345-6789-cfgh")
    assert FindingReference(
        FindingReferenceKind.VENDOR_ADVISORY,
        "https://security.example.test/advisory",
    )
    with pytest.raises(ValueError):
        FindingReference(FindingReferenceKind.CVE, "scanner-123")
    with pytest.raises(ValueError):
        FindingReference(
            FindingReferenceKind.RESEARCH_ARTICLE,
            "http://example.test/article",
        )


def test_collection_deduplicates_exact_records_and_rejects_conflicts() -> None:
    record = _record()
    assert FindingRecordCollection((record, record)).records == (record,)

    conflicting = _record(source="scanner_b")
    with pytest.raises(ValueError):
        FindingRecordCollection((record, conflicting))

    other = _record(title="Exposed Administrative Interface")
    assert FindingRecordCollection((record, other)) == FindingRecordCollection(
        (other, record)
    )


def test_serialization_is_deterministic_explicit_and_sanitized() -> None:
    record = _record()

    first = serialize_finding_record(record)
    second = serialize_finding_record(record)
    payload = json.loads(first)

    assert first == second
    assert payload["fingerprint"] == record.fingerprint.value
    assert payload["context"]["endpoint"] == (
        "https://app.example.test:8443/login"
    )
    assert "request" not in first
    assert "response" not in first
    assert "cookie" not in first
    assert "headers" not in first


@pytest.mark.parametrize(
    "value",
    tuple(EvidenceConfidence),
)
def test_confidence_values_are_categorical(value: EvidenceConfidence) -> None:
    assert value.value in {"unknown", "low", "medium", "high", "certain"}


@pytest.mark.parametrize("value", tuple(EvidenceQuality))
def test_quality_values_are_categorical(value: EvidenceQuality) -> None:
    assert value.value in {"unknown", "weak", "normal", "strong", "verified"}
