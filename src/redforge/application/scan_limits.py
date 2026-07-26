"""Translate validated application scan limits into neutral runtime policy."""

from typing import cast

from redforge.application.scan_config import ScanLimits
from redforge.runtime.execution_policy import (
    ExecutionDeadline,
    MonotonicClock,
    StateLimit,
    StateLimitPolicy,
    SystemMonotonicClock,
)
from redforge.sdk.state import PipelineStateKey


def create_scan_limit_policy(
    limits: ScanLimits,
    *,
    clock: MonotonicClock | None = None,
) -> StateLimitPolicy:
    """Create one immutable runtime policy for one application scan."""
    if not isinstance(cast(object, limits), ScanLimits):
        raise TypeError("scan limit policy requires ScanLimits")
    selected_clock = (
        clock if clock is not None else SystemMonotonicClock()
    )
    return StateLimitPolicy(
        limits=(
            StateLimit(PipelineStateKey.SUBDOMAINS, limits.max_subdomains),
            StateLimit(PipelineStateKey.HOSTS, limits.max_hosts),
            StateLimit(PipelineStateKey.ALIVE_HOSTS, limits.max_alive_hosts),
            StateLimit(
                PipelineStateKey.HTTP_ENDPOINTS,
                limits.max_http_endpoints,
            ),
            StateLimit(
                PipelineStateKey.ENDPOINTS,
                limits.max_crawl_endpoints,
            ),
            StateLimit(
                PipelineStateKey.TECHNOLOGIES,
                limits.max_technologies,
            ),
        ),
        deadline=ExecutionDeadline.after(
            limits.overall_timeout_seconds,
            clock=selected_clock,
        ),
    )
