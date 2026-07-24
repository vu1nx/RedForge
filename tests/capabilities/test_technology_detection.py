"""Tests for the typed Technology Detection boundary."""

from dataclasses import dataclass

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.errors import AdapterResponseError
from redforge.adapters.technology_detection import TechnologyDetectionResult
from redforge.capabilities.technology_detection import TechnologyDetectionCapability
from redforge.domain.endpoint import Endpoint
from redforge.domain.technology import Technology
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.context import Context
from redforge.sdk.result import Status


@dataclass
class FakeDetector:
    response: object
    calls: list[tuple[str, ...]]

    def detect(self, endpoints: tuple[str, ...]) -> TechnologyDetectionResult:
        self.calls.append(endpoints)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response  # type: ignore[return-value]


def _context() -> Context:
    return Context(
        target_id="example.com",
        state={
            PipelineStateKey.ENDPOINTS: [
                Endpoint("example.com", 443, "https", "/"),
                Endpoint("api.example.com", 8080, "http", "/v1"),
            ]
        },
    )


def test_capability_uses_typed_detector_result() -> None:
    technology = Technology(
        name="nginx",
        category="web-server",
        source="https://example.com/",
        evidence=("string: nginx",),
        confidence=100,
    )
    detector = FakeDetector(TechnologyDetectionResult((technology,)), [])

    result = TechnologyDetectionCapability(detector=detector).execute(_context())

    assert result.status == Status.SUCCESS
    assert result.data == [technology]
    assert detector.calls == [
        ("https://example.com/", "http://api.example.com:8080/v1")
    ]


def test_missing_endpoints_is_successful_noop() -> None:
    detector = FakeDetector(TechnologyDetectionResult(), [])
    result = TechnologyDetectionCapability(detector=detector).execute(
        Context(target_id="example.com")
    )

    assert result.status == Status.SUCCESS
    assert result.data == []
    assert detector.calls == []


def test_expected_detector_failure_is_sanitized_failure() -> None:
    detector = FakeDetector(
        AdapterResponseError("api-key=super-secret-token"),
        [],
    )
    result = TechnologyDetectionCapability(detector=detector).execute(_context())

    assert result.status == Status.FAILURE
    assert "super-secret-token" not in repr(result)


@pytest.mark.parametrize("invalid", [None, {}, "invalid"])
def test_invalid_detector_return_is_error(invalid: object) -> None:
    result = TechnologyDetectionCapability(
        detector=FakeDetector(invalid, [])
    ).execute(_context())

    assert result.status == Status.ERROR
    assert result.errors == ["Technology detector returned an invalid result"]


def test_unexpected_detector_exception_is_sanitized_error() -> None:
    result = TechnologyDetectionCapability(
        detector=FakeDetector(RuntimeError("/home/user/private/provider"), [])
    ).execute(_context())

    assert result.status == Status.ERROR
    assert "private" not in repr(result)


def test_name() -> None:
    assert TechnologyDetectionCapability(
        detector=FakeDetector(TechnologyDetectionResult(), [])
    ).name == "technology_detection"
