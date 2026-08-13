"""Runtime orchestration for pure canonical finding correlation."""

from typing import cast

from redforge.domain.finding_correlation import (
    CanonicalFindingCollection,
    FindingCorrelator,
)
from redforge.domain.finding_intelligence import FindingRecordCollection
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, StatePublication, Status
from redforge.sdk.state import PipelineStateKey


class FindingCorrelationCapability(Capability):
    """Publish deterministic canonical findings from normalized records."""

    def execute(self, context: Context) -> Result[None]:
        records = context.state.get(PipelineStateKey.VULNERABILITIES)
        if not isinstance(cast(object, records), FindingRecordCollection):
            return Result(
                status=Status.ERROR,
                data=None,
                errors=["Finding correlation input is invalid"],
            )
        try:
            findings = cast(
                object,
                FindingCorrelator.correlate(cast(FindingRecordCollection, records)),
            )
        except Exception:
            return Result(
                status=Status.ERROR,
                data=None,
                errors=["Finding correlation failed unexpectedly"],
            )
        if not isinstance(findings, CanonicalFindingCollection):
            return Result(
                status=Status.ERROR,
                data=None,
                errors=["Finding correlation returned an invalid result"],
            )
        return Result(
            status=Status.SUCCESS,
            data=None,
            publications=(StatePublication(PipelineStateKey.CANONICAL_FINDINGS, findings),),
        )

    @property
    def name(self) -> str:
        return "finding_correlation"
