"""Deterministic descriptor-only capability registry."""

from typing import cast

from redforge.planning.errors import UnknownCapabilityError
from redforge.planning.models import CapabilityDescriptor, validate_state_key


class CapabilityRegistry:
    """Configure and query immutable public views of planning descriptors."""

    def __init__(self) -> None:
        self._by_name: dict[str, CapabilityDescriptor] = {}

    def register(self, descriptor: CapabilityDescriptor) -> None:
        """Register one descriptor without silent replacement."""
        descriptor_value = cast(object, descriptor)
        if not isinstance(descriptor_value, CapabilityDescriptor):
            raise TypeError("registry accepts CapabilityDescriptor values only")
        if descriptor.name in self._by_name:
            raise ValueError(f"duplicate capability descriptor: '{descriptor.name}'")
        self._by_name[descriptor.name] = descriptor

    def get(self, name: str) -> CapabilityDescriptor:
        """Return a descriptor by canonical capability name."""
        name_value = cast(object, name)
        if not isinstance(name_value, str):
            raise UnknownCapabilityError("invalid")
        try:
            return self._by_name[name]
        except KeyError as error:
            raise UnknownCapabilityError(name_value) from error

    @property
    def descriptors(self) -> tuple[CapabilityDescriptor, ...]:
        """Return descriptors sorted independently of registration order."""
        return tuple(self._by_name[name] for name in sorted(self._by_name))

    def producers_for(self, state_key: str) -> tuple[CapabilityDescriptor, ...]:
        """Return deterministic descriptors that provide one state key."""
        key = validate_state_key(state_key)
        producers: dict[str, CapabilityDescriptor] = {}
        for descriptor in self._by_name.values():
            if key in descriptor.provides:
                producers[descriptor.name] = descriptor
        return tuple(producers[name] for name in sorted(producers))
