"""Domain-facing contracts for replaceable technology-detection providers."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from redforge.domain.endpoint import Endpoint
from redforge.domain.technology import Technology


class TechnologyDetectionProviderStatus(StrEnum):
    """Provider outcome before capability-level status mapping."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class TechnologyDetectionProviderResult:
    """Sanitized immutable technology evidence and parse metadata."""

    technologies: tuple[Technology, ...] = ()
    status: TechnologyDetectionProviderStatus = (
        TechnologyDetectionProviderStatus.SUCCESS
    )
    message: str | None = None
    malformed_record_count: int = 0
    out_of_scope_count: int = 0
    duplicate_count: int = 0
    truncated: bool = False

    def __post_init__(self) -> None:
        technologies = cast(object, self.technologies)
        if not isinstance(technologies, tuple) or not all(
            isinstance(item, Technology)
            for item in cast(tuple[object, ...], technologies)
        ):
            raise TypeError("technology evidence must be an immutable tuple")
        if not isinstance(
            cast(object, self.status), TechnologyDetectionProviderStatus
        ):
            raise TypeError("technology detection provider status is invalid")
        if self.message is not None and (
            not isinstance(cast(object, self.message), str)
            or not self.message.strip()
        ):
            raise ValueError(
                "technology detection provider message must not be empty"
            )
        for label, value in (
            ("malformed record count", self.malformed_record_count),
            ("out-of-scope count", self.out_of_scope_count),
            ("duplicate count", self.duplicate_count),
        ):
            if (
                not isinstance(cast(object, value), int)
                or isinstance(cast(object, value), bool)
                or value < 0
            ):
                raise ValueError(f"{label} must be a non-negative integer")
        if not isinstance(cast(object, self.truncated), bool):
            raise TypeError("technology detection truncation flag must be boolean")


class TechnologyDetectionProvider(Protocol):
    """Replaceable domain port for detecting endpoint technologies."""

    def detect(
        self,
        endpoints: tuple[Endpoint, ...],
    ) -> TechnologyDetectionProviderResult:
        """Detect technologies on one immutable collection of endpoints."""
        ...
