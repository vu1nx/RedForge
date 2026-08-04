"""Tests for the tool-agnostic Technology Detection capability."""

from dataclasses import dataclass

import pytest  # type: ignore[reportMissingImports]

from redforge.capabilities.technology_detection import TechnologyDetectionCapability
from redforge.domain.endpoint import Endpoint
from redforge.domain.technology import Technology
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk import (
    Context,
    Status,
    TechnologyDetectionPartialReason,
    TechnologyDetectionProviderResult,
    TechnologyDetectionProviderStatus,
)


@dataclass
class FakeProvider:
    response: object
    calls: list[tuple[Endpoint, ...]]

    def detect(
        self,
        endpoints: tuple[Endpoint, ...],
    ) -> TechnologyDetectionProviderResult:
        self.calls.append(endpoints)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response  # type: ignore[return-value]


def _endpoints() -> tuple[Endpoint, ...]:
    return (
        Endpoint("example.com", 443, "https", "/"),
        Endpoint("api.example.com", 8080, "http", "/v1"),
    )


def _context(endpoints: object = _endpoints()) -> Context:
    return Context(
        target_id="example.com",
        state={PipelineStateKey.ENDPOINTS: endpoints},
    )


def _technology() -> Technology:
    return Technology(
        name="nginx",
        category="web-server",
        source="https://example.com/",
        evidence=("string: nginx",),
        confidence=100,
    )


def test_capability_calls_provider_once_and_publishes_immutable_evidence() -> None:
    technology = _technology()
    provider = FakeProvider(
        TechnologyDetectionProviderResult((technology,)),
        [],
    )

    result = TechnologyDetectionCapability(provider=provider).execute(_context())

    assert result.status is Status.SUCCESS
    assert result.data is None
    assert provider.calls == [_endpoints()]
    assert result.publications[0].key is PipelineStateKey.TECHNOLOGIES
    assert result.publications[0].value == (technology,)


def test_empty_input_is_successful_publication_without_provider_call() -> None:
    provider = FakeProvider(TechnologyDetectionProviderResult(), [])

    result = TechnologyDetectionCapability(provider=provider).execute(
        Context(target_id="example.com")
    )

    assert result.status is Status.SUCCESS
    assert result.publications[0].value == ()
    assert provider.calls == []


def test_partial_with_evidence_publishes_and_continues() -> None:
    provider = FakeProvider(
        TechnologyDetectionProviderResult(
            technologies=(_technology(),),
            status=TechnologyDetectionProviderStatus.PARTIAL,
            message="Technology output contained rejected records.",
            malformed_record_count=1,
            partial_reasons=(
                TechnologyDetectionPartialReason.MALFORMED_RECORDS_SKIPPED,
            ),
        ),
        [],
    )

    result = TechnologyDetectionCapability(provider=provider).execute(_context())

    assert result.status is Status.PARTIAL
    assert result.publications[0].value == (_technology(),)
    assert result.errors == []
    assert result.metadata["partial_reasons"] == (
        TechnologyDetectionPartialReason.MALFORMED_RECORDS_SKIPPED,
    )


@pytest.mark.parametrize(
    "provider_status",
    [
        TechnologyDetectionProviderStatus.PARTIAL,
        TechnologyDetectionProviderStatus.FAILURE,
        TechnologyDetectionProviderStatus.UNAVAILABLE,
        TechnologyDetectionProviderStatus.ERROR,
    ],
)
def test_non_publishable_outcomes_publish_nothing(
    provider_status: TechnologyDetectionProviderStatus,
) -> None:
    provider = FakeProvider(
        TechnologyDetectionProviderResult(
            status=provider_status,
            message="Technology detection did not produce evidence.",
        ),
        [],
    )

    result = TechnologyDetectionCapability(provider=provider).execute(_context())

    expected = (
        Status.FAILURE
        if provider_status
        in {
            TechnologyDetectionProviderStatus.PARTIAL,
            TechnologyDetectionProviderStatus.FAILURE,
        }
        else Status.ERROR
    )
    assert result.status is expected
    assert result.publications == ()


@pytest.mark.parametrize("invalid", [None, {}, "invalid"])
def test_invalid_provider_return_is_error(invalid: object) -> None:
    result = TechnologyDetectionCapability(
        provider=FakeProvider(invalid, [])
    ).execute(_context())

    assert result.status is Status.ERROR
    assert result.publications == ()
    assert result.errors == ["Technology provider returned an invalid result"]


def test_provider_exception_is_sanitized_error() -> None:
    result = TechnologyDetectionCapability(
        provider=FakeProvider(
            RuntimeError("Authorization secret C:\\private\\provider"),
            [],
        )
    ).execute(_context())

    assert result.status is Status.ERROR
    assert result.publications == ()
    assert "Authorization" not in repr(result)
    assert "private" not in repr(result)


def test_compatibility_detector_keyword_and_conflict_validation() -> None:
    provider = FakeProvider(TechnologyDetectionProviderResult(), [])

    assert TechnologyDetectionCapability(detector=provider).name == (
        "technology_detection"
    )
    with pytest.raises(ValueError, match="cannot both"):
        TechnologyDetectionCapability(provider=provider, detector=provider)
