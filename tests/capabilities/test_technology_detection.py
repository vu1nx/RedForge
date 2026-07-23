"""Tests for the technology detection capability."""

from unittest.mock import MagicMock, patch

from redforge.adapters.technology_detection import TechnologyDetectionExecutionError
from redforge.capabilities.technology_detection import TechnologyDetectionCapability
from redforge.domain.endpoint import Endpoint
from redforge.domain.technology import Technology
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.context import Context
from redforge.sdk.result import Status


@patch(
    "redforge.capabilities.technology_detection."
    "TechnologyDetectionAdapter.detect_technologies"
)
def test_execute_detects_technologies_for_pipeline_endpoints(
    detect_technologies: MagicMock,
) -> None:
    """Endpoint domain objects are converted to URLs before adapter execution."""
    capability = TechnologyDetectionCapability()
    expected = Technology(
        name="nginx",
        category="web-server",
        version="1.25.4",
        source="https://example.com/",
        evidence=("string: nginx/1.25.4",),
        confidence=100,
    )
    detect_technologies.return_value = [expected]
    context = Context(
        target_id="example.com",
        state={
            PipelineStateKey.ENDPOINTS: [
                Endpoint(host="example.com", port=443, protocol="https", path="/"),
                Endpoint(host="api.example.com", port=8080, protocol="http", path="/v1"),
            ]
        },
    )

    result = capability.execute(context)

    assert result.status == Status.SUCCESS
    assert result.data == [expected]
    assert result.errors == []
    assert result.data[0].source == "https://example.com/"
    assert result.data[0].evidence == ("string: nginx/1.25.4",)
    assert result.data[0].confidence == 100
    detect_technologies.assert_called_once_with(
        ["https://example.com/", "http://api.example.com:8080/v1"]
    )


@patch(
    "redforge.capabilities.technology_detection."
    "TechnologyDetectionAdapter.detect_technologies"
)
def test_execute_with_no_endpoints_skips_adapter(
    detect_technologies: MagicMock,
) -> None:
    """Missing endpoint state is a successful no-op."""
    capability = TechnologyDetectionCapability()

    result = capability.execute(Context(target_id="example.com"))

    assert result.status == Status.SUCCESS
    assert result.data == []
    detect_technologies.assert_not_called()


@patch(
    "redforge.capabilities.technology_detection."
    "TechnologyDetectionAdapter.detect_technologies"
)
def test_execute_ignores_invalid_endpoint_state_entries(
    detect_technologies: MagicMock,
) -> None:
    """Only Endpoint domain objects are accepted from shared state."""
    capability = TechnologyDetectionCapability()
    detect_technologies.return_value = []
    context = Context(
        target_id="example.com",
        state={
            PipelineStateKey.ENDPOINTS: [
                "https://example.com",
                Endpoint(host="example.com", port=80, protocol="http", path=None),
            ]
        },
    )

    result = capability.execute(context)

    assert result.status == Status.SUCCESS
    detect_technologies.assert_called_once_with(["http://example.com/"])


@patch(
    "redforge.capabilities.technology_detection."
    "TechnologyDetectionAdapter.detect_technologies"
)
def test_execute_converts_adapter_error_to_error_result(
    detect_technologies: MagicMock,
) -> None:
    """Expected adapter failures do not escape the capability boundary."""
    capability = TechnologyDetectionCapability()
    detect_technologies.side_effect = TechnologyDetectionExecutionError(
        2, "scan failed"
    )
    context = Context(
        target_id="example.com",
        state={
            PipelineStateKey.ENDPOINTS: [
                Endpoint(host="example.com", port=443, protocol="https", path="/")
            ]
        },
    )

    result = capability.execute(context)

    assert result.status == Status.ERROR
    assert result.data == []
    assert result.errors == [
        "WhatWeb execution failed with return code 2: scan failed"
    ]


def test_name() -> None:
    """Capability exposes the stable pipeline registration name."""
    assert TechnologyDetectionCapability().name == "technology_detection"
