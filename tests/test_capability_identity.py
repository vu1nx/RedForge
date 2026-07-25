"""Capability Registry v2 identity and definition model tests."""

from dataclasses import FrozenInstanceError

import pytest  # type: ignore[reportMissingImports]

from redforge.sdk import (
    HOST_RESOLUTION,
    CapabilityDefinition,
    CapabilityId,
    PipelineStateKey,
)


def test_builtin_and_custom_capability_ids_are_stable_typed_values() -> None:
    custom = CapabilityId("custom_discovery")

    assert str(HOST_RESOLUTION) == "host_resolution"
    assert HOST_RESOLUTION.value == "host_resolution"
    assert custom == CapabilityId("custom_discovery")
    assert hash(custom) == hash(CapabilityId("custom_discovery"))
    assert sorted((custom, HOST_RESOLUTION)) == [
        custom,
        HOST_RESOLUTION,
    ]
    assert not hasattr(custom, "__dict__")
    with pytest.raises(FrozenInstanceError):
        custom.value = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    "value",
    (
        "",
        "UPPER",
        "with space",
        "with-dash",
        "9prefix",
        "_prefix",
        "suffix_",
        "a__b",
    ),
)
def test_capability_id_rejects_malformed_values(value: str) -> None:
    with pytest.raises(ValueError, match="capability ID"):
        CapabilityId(value)


def test_definition_normalizes_collections_and_metadata() -> None:
    definition = CapabilityDefinition(
        capability_id="custom_discovery",
        display_name=" Custom Discovery ",
        description=" Discovers custom asset records. ",
        version=" 1.0 ",
        requires=[PipelineStateKey.HOSTS],
        provides=[PipelineStateKey.ENDPOINTS, PipelineStateKey.SUBDOMAINS],
        tags=["Passive", "recon"],
    )

    assert definition.capability_id == CapabilityId("custom_discovery")
    assert definition.display_name == "Custom Discovery"
    assert definition.description == "Discovers custom asset records."
    assert definition.version == "1.0"
    assert definition.requires == (PipelineStateKey.HOSTS,)
    assert definition.provides == (
        PipelineStateKey.ENDPOINTS,
        PipelineStateKey.SUBDOMAINS,
    )
    assert definition.tags == ("passive", "recon")
    assert definition == CapabilityDefinition(
        capability_id=CapabilityId("custom_discovery"),
        display_name="Custom Discovery",
        description="Discovers custom asset records.",
        version="1.0",
        requires=(PipelineStateKey.HOSTS,),
        provides=(
            PipelineStateKey.SUBDOMAINS,
            PipelineStateKey.ENDPOINTS,
        ),
        tags=("recon", "passive"),
    )


@pytest.mark.parametrize(
    "changes",
    (
        {"display_name": ""},
        {"description": ""},
        {"version": ""},
    ),
)
def test_definition_rejects_empty_metadata(changes: dict[str, str]) -> None:
    arguments = {
        "capability_id": "custom",
        "display_name": "Custom",
        "description": "Custom contract.",
        "version": "1.0",
        "provides": (PipelineStateKey.HOSTS,),
    }
    arguments.update(changes)
    with pytest.raises(ValueError):
        CapabilityDefinition(**arguments)  # type: ignore[arg-type]


def test_definition_rejects_duplicate_invalid_state_and_tags() -> None:
    with pytest.raises(ValueError, match="duplicate state"):
        CapabilityDefinition(
            "duplicate_state",
            provides=(PipelineStateKey.HOSTS, PipelineStateKey.HOSTS),
        )
    with pytest.raises(ValueError, match="invalid state"):
        CapabilityDefinition(
            "invalid_state",
            provides=("not_a_state",),
        )
    with pytest.raises(ValueError, match="duplicates"):
        CapabilityDefinition(
            "duplicate_tag",
            provides=(PipelineStateKey.HOSTS,),
            tags=("Recon", "recon"),
        )
    with pytest.raises(ValueError, match="tag"):
        CapabilityDefinition(
            "invalid_tag",
            provides=(PipelineStateKey.HOSTS,),
            tags=("not valid",),
        )
