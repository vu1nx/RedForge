"""Application translation from ScanLimits to neutral runtime policy."""

from dataclasses import FrozenInstanceError

import pytest  # type: ignore[reportMissingImports]

from redforge.application import (
    ScanLimits,
    create_scan_limit_policy,
)
from redforge.runtime import StateLimit
from redforge.sdk import PipelineStateKey


class FixedClock:
    def __init__(self, value: float) -> None:
        self.value = value
        self.calls = 0

    def monotonic(self) -> float:
        self.calls += 1
        return self.value


def test_every_collection_scan_limit_maps_to_one_typed_state_limit() -> None:
    limits = ScanLimits(
        max_subdomains=1,
        max_hosts=2,
        max_alive_hosts=3,
        max_http_endpoints=4,
        max_crawl_endpoints=5,
        max_technologies=6,
        overall_timeout_seconds=7,
    )
    clock = FixedClock(10)

    policy = create_scan_limit_policy(limits, clock=clock)

    assert policy.limits == (
        StateLimit(PipelineStateKey.ALIVE_HOSTS, 3),
        StateLimit(PipelineStateKey.ENDPOINTS, 5),
        StateLimit(PipelineStateKey.HOSTS, 2),
        StateLimit(PipelineStateKey.HTTP_ENDPOINTS, 4),
        StateLimit(PipelineStateKey.SUBDOMAINS, 1),
        StateLimit(PipelineStateKey.TECHNOLOGIES, 6),
    )
    assert policy.deadline is not None
    assert policy.deadline.expires_at == 17
    assert clock.calls == 1


def test_policy_translation_is_immutable_isolated_and_validated() -> None:
    first = create_scan_limit_policy(ScanLimits(), clock=FixedClock(0))
    second = create_scan_limit_policy(ScanLimits(), clock=FixedClock(0))

    assert first == second
    assert first is not second
    assert not hasattr(first, "__dict__")
    with pytest.raises(FrozenInstanceError):
        first.limits = ()  # type: ignore[misc]
    with pytest.raises(TypeError, match="ScanLimits"):
        create_scan_limit_policy(object())  # type: ignore[arg-type]
