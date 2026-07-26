"""RedForge Runtime.

This package provides the runtime foundation for orchestrating
capability execution.
"""

from redforge.runtime.discovery import register_capabilities
from redforge.runtime.exceptions import (
    CapabilityNotFoundError,
    DuplicateCapabilityError,
    RuntimeError,
)
from redforge.runtime.execution_policy import (
    DeadlinePhase,
    DeadlineViolation,
    ExecutionDeadline,
    ExecutionPolicy,
    ExecutionPolicyViolation,
    MonotonicClock,
    StateLimit,
    StateLimitExceeded,
    StateLimitPolicy,
    StateLimitViolation,
    SystemMonotonicClock,
)
from redforge.runtime.pipeline import Pipeline, PipelineResult
from redforge.runtime.registry import CapabilityRegistry
from redforge.runtime.runtime import Runtime

__all__ = [
    "CapabilityNotFoundError",
    "DuplicateCapabilityError",
    "RuntimeError",
    "CapabilityRegistry",
    "DeadlinePhase",
    "DeadlineViolation",
    "ExecutionDeadline",
    "ExecutionPolicy",
    "ExecutionPolicyViolation",
    "MonotonicClock",
    "Pipeline",
    "PipelineResult",
    "Runtime",
    "StateLimit",
    "StateLimitExceeded",
    "StateLimitPolicy",
    "StateLimitViolation",
    "SystemMonotonicClock",
    "register_capabilities",
]
