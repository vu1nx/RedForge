"""Immutable static capability definitions."""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

from redforge.sdk.capability_id import CapabilityId, normalize_capability_id
from redforge.sdk.state import PipelineStateKey


def _state_keys(
    values: Iterable[PipelineStateKey | str],
    *,
    field_name: str,
) -> tuple[PipelineStateKey, ...]:
    values_object = cast(object, values)
    if isinstance(values_object, (str, bytes)):
        raise TypeError(f"{field_name} must be a collection")
    try:
        items = tuple(PipelineStateKey(item) for item in values)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field_name} contains an invalid state key") from error
    if len(items) != len(set(items)):
        raise ValueError(f"{field_name} contains duplicate state keys")
    return tuple(sorted(items))


def _tags(values: Iterable[str]) -> tuple[str, ...]:
    values_object = cast(object, values)
    if isinstance(values_object, (str, bytes)):
        raise TypeError("tags must be a collection")
    try:
        raw = tuple(values)
    except TypeError as error:
        raise TypeError("tags must be iterable") from error
    normalized: list[str] = []
    for value in raw:
        if not isinstance(cast(object, value), str):
            raise TypeError("tags must contain strings")
        tag = value.strip().lower()
        if (
            not tag
            or tag[0] in "-_"
            or tag[-1] in "-_"
            or any(
                not (character.isascii() and character.isalnum())
                and character not in "-_"
                for character in tag
            )
        ):
            raise ValueError("capability tag is invalid")
        normalized.append(tag)
    if len(normalized) != len(set(normalized)):
        raise ValueError("capability tags contain duplicates")
    return tuple(sorted(normalized))


@dataclass(frozen=True, slots=True, init=False)
class CapabilityDefinition:
    """Canonical identity and implementation-independent execution metadata."""

    capability_id: CapabilityId
    requires: tuple[PipelineStateKey, ...]
    provides: tuple[PipelineStateKey, ...]
    display_name: str
    description: str
    version: str
    tags: tuple[str, ...]

    def __init__(
        self,
        capability_id: CapabilityId | str | None = None,
        requires: Iterable[PipelineStateKey | str] = (),
        provides: Iterable[PipelineStateKey | str] = (),
        display_name: str | None = None,
        description: str | None = None,
        version: str = "1.0",
        tags: Iterable[str] = (),
        *,
        name: str | None = None,
    ) -> None:
        """Create a definition, accepting legacy ``name=`` during migration."""
        if capability_id is not None and name is not None:
            raise ValueError("use capability_id or legacy name, not both")
        identity_input = capability_id if capability_id is not None else name
        if identity_input is None:
            raise ValueError("capability identity is required")
        identity = normalize_capability_id(identity_input)
        resolved_display = (
            display_name
            if display_name is not None
            else identity.value.replace("_", " ").title()
        )
        resolved_description = (
            description
            if description is not None
            else f"{resolved_display} capability contract."
        )
        if not isinstance(cast(object, resolved_display), str) or not resolved_display.strip():
            raise ValueError("capability display name must not be empty")
        if (
            not isinstance(cast(object, resolved_description), str)
            or not resolved_description.strip()
        ):
            raise ValueError("capability description must not be empty")
        if not isinstance(cast(object, version), str) or not version.strip():
            raise ValueError("capability version must not be empty")
        required = _state_keys(requires, field_name="requires")
        provided = _state_keys(provides, field_name="provides")
        if not provided:
            raise ValueError("capability definition must provide state")

        object.__setattr__(self, "capability_id", identity)
        object.__setattr__(self, "requires", required)
        object.__setattr__(self, "provides", provided)
        object.__setattr__(self, "display_name", resolved_display.strip())
        object.__setattr__(self, "description", resolved_description.strip())
        object.__setattr__(self, "version", version.strip())
        object.__setattr__(self, "tags", _tags(tags))

    @property
    def name(self) -> str:
        """Return the legacy serialized identity field."""
        return self.capability_id.value


CapabilityDescriptor = CapabilityDefinition
"""Compatibility alias for the TASK-0019 descriptor API."""
