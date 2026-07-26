"""Domain-facing contracts for replaceable HTTP probe providers."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from redforge.domain.host import Host
from redforge.domain.http_probe import HttpProbeEndpoint


class HttpProbeProviderStatus(StrEnum):
    """Provider outcome before capability-level status mapping."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class HttpProbeProviderResult:
    """Sanitized immutable HTTP probe evidence and responsive input hosts."""

    endpoints: tuple[HttpProbeEndpoint, ...] = ()
    responsive_hosts: tuple[Host, ...] = ()
    status: HttpProbeProviderStatus = HttpProbeProviderStatus.SUCCESS
    message: str | None = None
    malformed_record_count: int = 0
    out_of_scope_count: int = 0
    duplicate_count: int = 0
    truncated: bool = False

    def __post_init__(self) -> None:
        endpoints = cast(object, self.endpoints)
        if not isinstance(endpoints, tuple) or not all(
            isinstance(item, HttpProbeEndpoint)
            for item in cast(tuple[object, ...], endpoints)
        ):
            raise TypeError("HTTP probe endpoints must be an immutable tuple")
        responsive_hosts = cast(object, self.responsive_hosts)
        if not isinstance(responsive_hosts, tuple) or not all(
            isinstance(item, Host)
            for item in cast(tuple[object, ...], responsive_hosts)
        ):
            raise TypeError("responsive hosts must be an immutable tuple")
        if not isinstance(cast(object, self.status), HttpProbeProviderStatus):
            raise TypeError("HTTP probe provider status is invalid")
        if self.message is not None and (
            not isinstance(cast(object, self.message), str)
            or not self.message.strip()
        ):
            raise ValueError("HTTP probe provider message must not be empty")
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
            raise TypeError("HTTP probe truncation flag must be boolean")


class HttpProbeProvider(Protocol):
    """Replaceable domain port for probing resolved hosts for HTTP services."""

    def probe(self, hosts: tuple[Host, ...]) -> HttpProbeProviderResult:
        """Probe one immutable collection of approved resolved hosts."""
        ...
