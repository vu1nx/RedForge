"""Deterministic socket-free transport for external-provider contract tests."""

from collections.abc import Iterable
from typing import cast

from redforge.sdk.http_data import (
    HttpDataResponse,
    HttpDataTransportError,
    HttpDataTransportFailure,
    HttpGetRequest,
)

type FakeHttpOutcome = HttpDataResponse | HttpDataTransportError


class FakeHttpDataTransport:
    """Return queued responses or safe failures and record immutable requests."""

    def __init__(self, outcomes: Iterable[FakeHttpOutcome] = ()) -> None:
        self._outcomes = list(outcomes)
        self._requests: list[HttpGetRequest] = []

    @property
    def requests(self) -> tuple[HttpGetRequest, ...]:
        return tuple(self._requests)

    def get(self, request: HttpGetRequest) -> HttpDataResponse:
        if not isinstance(cast(object, request), HttpGetRequest):
            raise TypeError("fake HTTP transport requires an HttpGetRequest")
        self._requests.append(request)
        if not self._outcomes:
            raise HttpDataTransportError(HttpDataTransportFailure.ERROR)
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, HttpDataTransportError):
            raise HttpDataTransportError(outcome.failure)
        return outcome


__all__ = ["FakeHttpDataTransport", "FakeHttpOutcome"]
