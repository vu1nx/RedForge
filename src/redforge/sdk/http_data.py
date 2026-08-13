"""Minimal provider-neutral contracts for bounded external HTTP reads."""

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_HTTPS_URL = re.compile(r"https://[^\s\x00-\x1f\x7f]+")


class HttpDataTransportFailure(StrEnum):
    """Sanitized transport failures with no upstream implementation detail."""

    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    RESPONSE_TOO_LARGE = "response_too_large"
    ERROR = "error"


class HttpDataTransportError(RuntimeError):
    """Typed safe failure raised by an HTTP data transport."""

    def __init__(self, failure: HttpDataTransportFailure) -> None:
        if not isinstance(cast(object, failure), HttpDataTransportFailure):
            raise TypeError("HTTP transport failure is invalid")
        self.failure = failure
        super().__init__("HTTP data request failed")

    def __repr__(self) -> str:
        return f"HttpDataTransportError(failure={self.failure!r})"


@dataclass(frozen=True, slots=True, repr=False)
class HttpGetRequest:
    """One immutable HTTPS GET request with explicit operational bounds."""

    url: str
    headers: tuple[tuple[str, str], ...] = ()
    timeout_seconds: float = 15.0
    max_response_bytes: int = 2 * 1024 * 1024

    def __post_init__(self) -> None:
        if (
            not isinstance(cast(object, self.url), str)
            or len(self.url) > 4096
            or _HTTPS_URL.fullmatch(self.url) is None
            or "#" in self.url
            or "@" in self.url.split("/", 3)[2]
        ):
            raise ValueError("HTTP request URL is invalid")
        raw_headers = cast(object, self.headers)
        if not isinstance(raw_headers, tuple):
            raise TypeError("HTTP request headers must be a bounded immutable tuple")
        typed_headers = cast(tuple[object, ...], raw_headers)
        if len(typed_headers) > 16:
            raise TypeError("HTTP request headers must be a bounded immutable tuple")
        normalized: list[tuple[str, str]] = []
        names: set[str] = set()
        for item in typed_headers:
            if not isinstance(item, tuple):
                raise TypeError("HTTP request header is invalid")
            pair = cast(tuple[object, ...], item)
            if len(pair) != 2:
                raise TypeError("HTTP request header is invalid")
            name, value = pair
            if (
                not isinstance(name, str)
                or _HEADER_NAME.fullmatch(name) is None
                or not isinstance(value, str)
                or len(value) > 4096
                or any(ord(character) < 32 or ord(character) == 127 for character in value)
            ):
                raise ValueError("HTTP request header is invalid")
            canonical = name.casefold()
            if canonical in names:
                raise ValueError("HTTP request headers contain duplicate names")
            names.add(canonical)
            normalized.append((name, value))
        object.__setattr__(self, "headers", tuple(sorted(normalized, key=lambda item: item[0].casefold())))
        timeout = cast(object, self.timeout_seconds)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int | float)
            or not 0.1 <= float(timeout) <= 120.0
        ):
            raise ValueError("HTTP request timeout is out of bounds")
        object.__setattr__(self, "timeout_seconds", float(timeout))
        limit = cast(object, self.max_response_bytes)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 16 * 1024 * 1024
        ):
            raise ValueError("HTTP response byte limit is out of bounds")

    def __repr__(self) -> str:
        return (
            "HttpGetRequest(url=<configured>, "
            f"header_count={len(self.headers)!r}, timeout_seconds={self.timeout_seconds!r}, "
            f"max_response_bytes={self.max_response_bytes!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class HttpDataResponse:
    """Bounded immutable HTTP response without retained headers."""

    status_code: int
    body: bytes = b""

    def __post_init__(self) -> None:
        if (
            isinstance(cast(object, self.status_code), bool)
            or not isinstance(cast(object, self.status_code), int)
            or not 100 <= self.status_code <= 599
        ):
            raise ValueError("HTTP response status is invalid")
        if not isinstance(cast(object, self.body), bytes):
            raise TypeError("HTTP response body must be bytes")
        if len(self.body) > 16 * 1024 * 1024:
            raise ValueError("HTTP response body exceeds absolute limit")

    def __repr__(self) -> str:
        return f"HttpDataResponse(status_code={self.status_code!r}, body_bytes={len(self.body)!r})"


class HttpDataTransport(Protocol):
    """Execute one bounded GET without target or provider semantics."""

    def get(self, request: HttpGetRequest) -> HttpDataResponse: ...


__all__ = [
    "HttpDataResponse",
    "HttpDataTransport",
    "HttpDataTransportError",
    "HttpDataTransportFailure",
    "HttpGetRequest",
]
