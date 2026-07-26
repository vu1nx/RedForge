"""Domain-facing contracts for replaceable subdomain discovery providers."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast


class SubdomainDiscoveryStatus(StrEnum):
    """Provider-level outcome before capability status mapping."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    ERROR = "error"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class SubdomainDiscoveryResult:
    """Sanitized immutable provider result with deterministic findings."""

    hostnames: tuple[str, ...] = ()
    status: SubdomainDiscoveryStatus = SubdomainDiscoveryStatus.SUCCESS
    message: str | None = None
    malformed_record_count: int = 0
    out_of_scope_count: int = 0
    duplicate_count: int = 0
    truncated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.hostnames), tuple) or not all(
            isinstance(cast(object, hostname), str) and bool(hostname)
            for hostname in self.hostnames
        ):
            raise TypeError("subdomain findings must be a tuple of strings")
        if not isinstance(cast(object, self.status), SubdomainDiscoveryStatus):
            raise TypeError("subdomain discovery status is invalid")
        if self.message is not None and (
            not isinstance(cast(object, self.message), str)
            or not self.message.strip()
        ):
            raise ValueError("subdomain discovery message must not be empty")
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
            raise TypeError("subdomain truncation flag must be boolean")


class SubdomainProvider(Protocol):
    """Replaceable domain port for passive subdomain discovery."""

    def discover(self, domain: str) -> SubdomainDiscoveryResult:
        """Discover normalized subdomains within one requested root domain."""
        ...
