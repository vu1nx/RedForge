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
from redforge.runtime.pipeline import Pipeline, PipelineResult
from redforge.runtime.registry import CapabilityRegistry
from redforge.runtime.runtime import Runtime

__all__ = [
    "CapabilityNotFoundError",
    "DuplicateCapabilityError",
    "RuntimeError",
    "CapabilityRegistry",
    "Pipeline",
    "PipelineResult",
    "Runtime",
    "register_capabilities",
]
