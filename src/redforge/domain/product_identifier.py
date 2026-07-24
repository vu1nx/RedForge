"""Provider-independent product identifier value object."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProductIdentifier:
    """Identifies a software product using a named identifier scheme."""

    scheme: str
    """Identifier scheme, such as ``cpe23``."""

    value: str
    """Canonical identifier value within the scheme."""
