"""Immutable publication model and atomic Context batch tests."""

from dataclasses import FrozenInstanceError
from typing import cast

import pytest  # type: ignore[reportMissingImports]

from redforge.sdk.context import Context
from redforge.sdk.result import Result, StatePublication, Status
from redforge.sdk.state import PipelineStateKey


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
