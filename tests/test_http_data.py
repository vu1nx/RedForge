"""Contract tests for bounded provider-neutral HTTP data transport models."""

import urllib.request
from dataclasses import FrozenInstanceError

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters import LocalHttpsDataTransport
from redforge.sdk import (
    HttpDataResponse,
    HttpDataTransportError,
    HttpDataTransportFailure,
    HttpGetRequest,
)
from redforge.testing import FakeHttpDataTransport


def test_http_request_is_immutable_bounded_deterministic_and_safe() -> None:
    request = HttpGetRequest(
        "https://provider.example/data?cve=CVE-2026-12345",
        headers=(("X-Secret", "synthetic-secret"), ("Accept", "application/json")),
        timeout_seconds=3,
        max_response_bytes=1024,
    )
    assert request.headers[0][0] == "Accept"
    assert "synthetic-secret" not in repr(request)
    assert "provider.example" not in repr(request)
    with pytest.raises(FrozenInstanceError):
        request.url = "https://other.example"  # type: ignore[misc]


@pytest.mark.parametrize(
    "kwargs",
    (
        {"url": "http://provider.example/data"},
        {"url": "https://user:secret@provider.example/data"},
        {"url": "https://provider.example/data#fragment"},
        {"url": "https://provider.example/data\nunsafe"},
        {"url": "https://provider.example", "timeout_seconds": 0},
        {"url": "https://provider.example", "max_response_bytes": 0},
        {
            "url": "https://provider.example",
            "headers": (("Authorization", "one"), ("authorization", "two")),
        },
    ),
)
def test_http_request_rejects_unsafe_or_unbounded_values(kwargs: dict[str, object]) -> None:
    with pytest.raises((TypeError, ValueError)):
        HttpGetRequest(**kwargs)  # type: ignore[arg-type]


def test_http_response_and_fake_transport_are_immutable_and_socket_free() -> None:
    response = HttpDataResponse(200, b"payload")
    transport = FakeHttpDataTransport((response,))
    request = HttpGetRequest("https://provider.example/data")
    assert transport.get(request) is response
    assert transport.requests == (request,)
    assert "payload" not in repr(response)


def test_fake_transport_replays_typed_failures_without_raw_detail() -> None:
    transport = FakeHttpDataTransport(
        (HttpDataTransportError(HttpDataTransportFailure.TIMEOUT),)
    )
    with pytest.raises(HttpDataTransportError) as caught:
        transport.get(HttpGetRequest("https://provider.example/data"))
    assert caught.value.failure is HttpDataTransportFailure.TIMEOUT
    assert str(caught.value) == "HTTP data request failed"


def test_local_transport_ignores_proxy_environment_during_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.setenv(name, "http://synthetic.invalid:9999")

    def fail_if_discovered() -> dict[str, str]:
        raise AssertionError("proxy environment was inspected")

    monkeypatch.setattr(urllib.request, "getproxies", fail_if_discovered)
    transport = LocalHttpsDataTransport()
    assert "synthetic.invalid" not in repr(transport)
