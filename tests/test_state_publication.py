"""Immutable publication model and atomic Context batch tests."""

from dataclasses import FrozenInstanceError
from typing import cast

import pytest  # type: ignore[reportMissingImports]

import redforge.sdk as public_sdk
from redforge.domain import HttpProbeEndpoint as PublicHttpProbeEndpoint
from redforge.domain.host import Host
from redforge.domain.http_probe import HttpProbeEndpoint
from redforge.sdk.context import Context
from redforge.sdk.http_probe import HttpProbeProviderResult
from redforge.sdk.result import Result, StatePublication, Status
from redforge.sdk.state import PipelineStateKey


def test_http_endpoints_state_key_is_public_stable_and_distinct() -> None:
    assert public_sdk.PipelineStateKey.HTTP_ENDPOINTS.value == "http_endpoints"
    assert (
        public_sdk.PipelineStateKey.HTTP_ENDPOINTS
        is PipelineStateKey.HTTP_ENDPOINTS
    )
    assert PipelineStateKey.HTTP_ENDPOINTS != PipelineStateKey.ENDPOINTS
    assert str(PipelineStateKey.HTTP_ENDPOINTS) == "http_endpoints"
    assert public_sdk.HttpProbeEndpoint is HttpProbeEndpoint
    assert PublicHttpProbeEndpoint is HttpProbeEndpoint


def test_state_publication_is_typed_immutable_slotted_and_equal() -> None:
    first = StatePublication(PipelineStateKey.HOSTS, ("host",))
    second = StatePublication(PipelineStateKey.HOSTS, ("host",))

    assert first == second
    assert not hasattr(first, "__dict__")
    with pytest.raises(FrozenInstanceError):
        first.value = ("changed",)  # type: ignore[misc]
    with pytest.raises(TypeError, match="PipelineStateKey"):
        StatePublication("hosts", ())  # type: ignore[arg-type]


def test_result_normalizes_publication_iterable_and_rejects_duplicates() -> None:
    publication = StatePublication(PipelineStateKey.HOSTS, ())
    result = Result[None](
        status=Status.SUCCESS,
        data=None,
        publications=[publication],  # type: ignore[arg-type]
    )

    assert result.publications == (publication,)
    assert isinstance(result.publications, tuple)
    with pytest.raises(ValueError, match="duplicate"):
        Result[None](
            status=Status.SUCCESS,
            data=None,
            publications=(publication, publication),
        )


def test_context_publish_many_empty_one_and_multiple() -> None:
    context = Context(target_id="example.com")
    context.publish_many(())
    assert context.available_state_keys() == ()

    context.publish(StatePublication(PipelineStateKey.HOSTS, ("host",)))
    context.publish_many(
        (
            StatePublication(PipelineStateKey.SUBDOMAINS, ("a.example",)),
            StatePublication(PipelineStateKey.ALIVE_HOSTS, ()),
        )
    )

    assert context.has(PipelineStateKey.HOSTS)
    assert context.get(PipelineStateKey.HOSTS) == ("host",)
    assert context.available_state_keys() == (
        PipelineStateKey.ALIVE_HOSTS,
        PipelineStateKey.HOSTS,
        PipelineStateKey.SUBDOMAINS,
    )


def test_context_batch_replaces_existing_values() -> None:
    context = Context(
        target_id="example.com",
        state={PipelineStateKey.HOSTS: ("old",)},
    )

    context.publish_many((StatePublication(PipelineStateKey.HOSTS, ("new",)),))

    assert context.get(PipelineStateKey.HOSTS) == ("new",)


def test_context_batch_duplicate_is_atomic() -> None:
    context = Context(
        target_id="example.com",
        state={PipelineStateKey.TECHNOLOGIES: ("preserved",)},
    )
    original = dict(context.state)

    with pytest.raises(ValueError, match="duplicate"):
        context.publish_many(
            (
                StatePublication(PipelineStateKey.HOSTS, ("first",)),
                StatePublication(PipelineStateKey.HOSTS, ("second",)),
                StatePublication(PipelineStateKey.SUBDOMAINS, ("third",)),
            )
        )

    assert context.state == original


def test_context_invalid_batch_is_atomic_and_preserves_input() -> None:
    context = Context(target_id="example.com")
    publication = StatePublication(PipelineStateKey.HOSTS, ("host",))
    supplied = [publication]

    context.publish_many(supplied)
    assert supplied == [publication]

    original = dict(context.state)
    malformed = cast(
        tuple[StatePublication, ...],
        (StatePublication(PipelineStateKey.SUBDOMAINS, ()), object()),
    )
    with pytest.raises(TypeError, match="StatePublication"):
        context.publish_many(malformed)
    assert context.state == original


def _http_endpoint() -> HttpProbeEndpoint:
    return HttpProbeEndpoint(
        url="https://api.example.com",
        scheme="https",
        hostname="api.example.com",
        port=443,
        status_code=200,
    )


def test_http_endpoint_state_accepts_only_immutable_typed_tuples() -> None:
    endpoint = _http_endpoint()
    context = Context(target_id="example.com")
    context.publish_many(
        (
            StatePublication(PipelineStateKey.ALIVE_HOSTS, (Host(hostname="api.example.com"),)),
            StatePublication(PipelineStateKey.HTTP_ENDPOINTS, (endpoint,)),
        )
    )
    assert context.get(PipelineStateKey.HTTP_ENDPOINTS) == (endpoint,)

    invalid_values = (
        [endpoint],
        ("https://api.example.com",),
        ({"url": endpoint.url},),
        HttpProbeProviderResult(endpoints=(endpoint,)),
        None,
        (endpoint, "invalid"),
    )
    for value in invalid_values:
        with pytest.raises(TypeError, match="http_endpoints"):
            Context(target_id="example.com").publish(
                StatePublication(PipelineStateKey.HTTP_ENDPOINTS, value)
            )


def test_typed_multi_output_validation_is_atomic() -> None:
    endpoint = _http_endpoint()
    context = Context(
        target_id="example.com",
        state={PipelineStateKey.SUBDOMAINS: ("preserved.example.com",)},
    )
    original = dict(context.state)

    with pytest.raises(TypeError, match="http_endpoints"):
        context.publish_many(
            (
                StatePublication(
                    PipelineStateKey.ALIVE_HOSTS,
                    (Host(hostname="api.example.com"),),
                ),
                StatePublication(PipelineStateKey.HTTP_ENDPOINTS, [endpoint]),
            )
        )
    assert context.state == original

    with pytest.raises(TypeError, match="alive_hosts"):
        context.publish_many(
            (
                StatePublication(PipelineStateKey.ALIVE_HOSTS, ["invalid"]),
                StatePublication(PipelineStateKey.HTTP_ENDPOINTS, (endpoint,)),
            )
        )
    assert context.state == original
