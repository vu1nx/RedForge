"""Stable profile identity without composition implementation imports."""

from enum import StrEnum


class CompositionProfile(StrEnum):
    """Explicit deterministic application composition profile."""

    RECONNAISSANCE = "reconnaissance"
    FULL_ASSESSMENT = "full_assessment"
    LOCAL_SMOKE = "local_smoke"
