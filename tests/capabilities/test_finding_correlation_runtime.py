"""Runtime integration tests for canonical finding correlation."""

from redforge.capabilities import FindingCorrelationCapability
from redforge.domain import (
    AffectedAsset,
    AssetIdentityKind,
    CanonicalFindingCollection,
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
    FindingIdentity,
    FindingMetadata,
    FindingRecord,
    FindingRecordCollection,
    FindingReference,
    FindingReferenceKind,
    FindingSeverity,
    finding_fingerprint,
)
from redforge.runtime import Pipeline
from redforge.sdk import (
    FINDING_CORRELATION,
    Context,
    PipelineStateKey,
    Status,
)


def _record(*, title: str = "Synthetic finding") -> FindingRecord:
    asset = AffectedAsset(AssetIdentityKind.HOSTNAME, "example.test")
    classification = FindingClassification.from_title(
        title,
        severity=FindingSeverity.HIGH,
    )
    identity = FindingIdentity(classification.identifier, asset)
    source = EvidenceSource(EvidenceSourceKind.TOOL, "synthetic")
    return FindingRecord(
        identity,
        finding_fingerprint(identity),
        classification,
        FindingContext(asset),
        (
            FindingEvidence(
                EvidenceKind.HTTP,
                DetectionMethod.ACTIVE,
                EvidenceConfidence.HIGH,
                EvidenceQuality.STRONG,
                source,
                EvidenceSummary("Synthetic evidence."),
            ),
        ),
        FindingMetadata(
            source,
            references=(FindingReference(FindingReferenceKind.CVE, "CVE-2026-12345"),),
        ),
    )


def test_correlation_publishes_typed_deterministic_collection() -> None:
    record = _record()
    context = Context(
        target_id="example.test",
        state={PipelineStateKey.VULNERABILITIES: FindingRecordCollection((record, record))},
    )

    result = FindingCorrelationCapability().execute(context)

    assert result.status is Status.SUCCESS
    assert result.publications[0].key is PipelineStateKey.CANONICAL_FINDINGS
    canonical = result.publications[0].value
    assert len(canonical) == 1  # type: ignore[arg-type]


def test_empty_correlation_succeeds_and_pipeline_publishes_once() -> None:
    pipeline = Pipeline()
    pipeline.add(
        FindingCorrelationCapability(),
        capability_id=FINDING_CORRELATION,
        provides=(PipelineStateKey.CANONICAL_FINDINGS,),
    )
    context = Context(
        target_id="example.test",
        state={PipelineStateKey.VULNERABILITIES: FindingRecordCollection()},
    )

    execution = pipeline.run(context)

    assert execution.status is Status.SUCCESS
    assert len(execution.executions) == 1
    assert execution.context.get(PipelineStateKey.CANONICAL_FINDINGS) == (
        CanonicalFindingCollection()
    )


def test_invalid_correlation_input_fails_safely_without_publication() -> None:
    result = FindingCorrelationCapability().execute(Context(target_id="example.test"))

    assert result.status is Status.ERROR
    assert result.publications == ()
    assert result.errors == ["Finding correlation input is invalid"]
