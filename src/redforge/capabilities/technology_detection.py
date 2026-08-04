"""Tool-agnostic technology-detection capability."""

from typing import Any, cast

from redforge.domain.endpoint import Endpoint
from redforge.domain.technology import Technology
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, StatePublication, Status
from redforge.sdk.technology_detection import (
    TechnologyDetectionProvider,
    TechnologyDetectionProviderResult,
    TechnologyDetectionProviderStatus,
)


class _UnavailableTechnologyDetectionProvider:
    """Safe default for manual capability construction."""

    def detect(
        self,
        endpoints: tuple[Endpoint, ...],
    ) -> TechnologyDetectionProviderResult:
        del endpoints
        return TechnologyDetectionProviderResult(
            status=TechnologyDetectionProviderStatus.UNAVAILABLE,
            message="Technology detection provider is unavailable.",
        )


def _technology_sort_key(technology: Technology) -> tuple[object, ...]:
    return (
        technology.source or "",
        technology.name.casefold(),
        technology.name,
        technology.category,
        technology.version or "",
        technology.vendor or "",
        technology.description or "",
        technology.evidence,
        technology.confidence if technology.confidence is not None else -1,
    )


def _normalize_technologies(
    technologies: tuple[Technology, ...],
) -> tuple[Technology, ...]:
    normalized: dict[Technology, Technology] = {}
    for technology in technologies:
        normalized.setdefault(technology, technology)
    return tuple(sorted(normalized.values(), key=_technology_sort_key))


class TechnologyDetectionCapability(Capability):
    """Detect provider-neutral technology evidence on crawler endpoints."""

    def __init__(
        self,
        *,
        provider: TechnologyDetectionProvider | None = None,
        detector: TechnologyDetectionProvider | None = None,
    ) -> None:
        """Initialize with one provider; detector is a compatibility keyword."""
        if provider is not None and detector is not None:
            raise ValueError("provider and detector cannot both be configured")
        self._provider = (
            provider
            or detector
            or _UnavailableTechnologyDetectionProvider()
        )

    def execute(self, context: Context) -> Result[None]:
        """Detect and atomically publish the canonical technology tuple."""
        endpoints = self._get_endpoints_from_state(context.state)
        if not endpoints:
            return self._publishable_result(
                status=Status.SUCCESS,
                technologies=(),
                provider_status=TechnologyDetectionProviderStatus.SUCCESS,
            )

        try:
            response = cast(object, self._provider.detect(endpoints))
        except Exception:
            return self._error_result(
                "Technology provider failed with an unexpected execution error"
            )
        if not isinstance(response, TechnologyDetectionProviderResult):
            return self._error_result(
                "Technology provider returned an invalid result"
            )
        response_technologies = cast(object, response.technologies)
        if not isinstance(response_technologies, tuple) or not all(
            isinstance(item, Technology)
            for item in cast(tuple[object, ...], response_technologies)
        ):
            return self._error_result(
                "Technology provider returned an invalid result"
            )
        try:
            technologies = _normalize_technologies(
                cast(tuple[Technology, ...], response_technologies)
            )
        except (TypeError, ValueError):
            return self._error_result(
                "Technology provider returned an invalid result"
            )

        status = self._status(response.status, has_evidence=bool(technologies))
        errors = (
            [response.message or "Technology detection failed."]
            if status in {Status.FAILURE, Status.ERROR}
            else []
        )
        publications = (
            (
                StatePublication(
                    PipelineStateKey.TECHNOLOGIES,
                    technologies,
                ),
            )
            if status in {Status.SUCCESS, Status.PARTIAL}
            else ()
        )
        return Result(
            status=status,
            data=None,
            errors=errors,
            metadata={
                "technology_count": len(technologies),
                "provider_status": response.status.value,
                "malformed_record_count": response.malformed_record_count,
                "out_of_scope_count": response.out_of_scope_count,
                "duplicate_count": response.duplicate_count,
                "truncated": response.truncated,
                "partial_reasons": response.partial_reasons,
            },
            publications=publications,
        )

    @staticmethod
    def _status(
        provider_status: TechnologyDetectionProviderStatus,
        *,
        has_evidence: bool,
    ) -> Status:
        if provider_status is TechnologyDetectionProviderStatus.SUCCESS:
            return Status.SUCCESS
        if provider_status is TechnologyDetectionProviderStatus.PARTIAL:
            return Status.PARTIAL if has_evidence else Status.FAILURE
        if provider_status is TechnologyDetectionProviderStatus.FAILURE:
            return Status.FAILURE
        return Status.ERROR

    @staticmethod
    def _publishable_result(
        *,
        status: Status,
        technologies: tuple[Technology, ...],
        provider_status: TechnologyDetectionProviderStatus,
    ) -> Result[None]:
        return Result(
            status=status,
            data=None,
            metadata={
                "technology_count": len(technologies),
                "provider_status": provider_status.value,
                "malformed_record_count": 0,
                "out_of_scope_count": 0,
                "duplicate_count": 0,
                "truncated": False,
                "partial_reasons": (),
            },
            publications=(
                StatePublication(
                    PipelineStateKey.TECHNOLOGIES,
                    technologies,
                ),
            ),
        )

    @staticmethod
    def _get_endpoints_from_state(
        state: dict[str, Any],  # type: ignore[reportUnknownParameterType]
    ) -> tuple[Endpoint, ...]:
        value = state.get(PipelineStateKey.ENDPOINTS)
        if not isinstance(value, (list, tuple)):
            return ()
        return tuple(
            item
            for item in cast(list[object] | tuple[object, ...], value)
            if isinstance(item, Endpoint)
        )

    @staticmethod
    def _error_result(message: str) -> Result[None]:
        return Result(status=Status.ERROR, data=None, errors=[message])

    @property
    def name(self) -> str:
        """Return the stable capability identity."""
        return "technology_detection"
