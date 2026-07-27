"""Public application composition framework."""

from typing import TYPE_CHECKING

from redforge.composition.profile import CompositionProfile

if TYPE_CHECKING:
    from redforge.composition.application import (
        ApplicationComposition,
        CompositionProviders,
    )

__all__ = [
    "ApplicationComposition",
    "CompositionProviders",
    "CompositionProfile",
]


def __getattr__(name: str) -> object:
    """Load concrete composition machinery only when explicitly requested."""
    if name in {"ApplicationComposition", "CompositionProviders"}:
        from redforge.composition.application import (
            ApplicationComposition,
            CompositionProviders,
        )

        return {
            "ApplicationComposition": ApplicationComposition,
            "CompositionProviders": CompositionProviders,
        }[name]
    raise AttributeError(name)
