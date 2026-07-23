"""Asset domain model."""

from dataclasses import dataclass

from redforge.domain.endpoint import Endpoint
from redforge.domain.host import Host


@dataclass(frozen=True, slots=True)
class Asset:
    """Represents the stable identity of an asset within a target environment.

    Security knowledge is related to an asset through explicit associations
    rather than being owned by this identity model.
    """

    identifier: str
    """Unique identifier for the asset."""

    type: str
    """Type or category of the asset."""

    name: str | None = None
    """Human-readable name for the asset."""

    description: str | None = None
    """Additional description or context about the asset."""

    aliases: tuple[str, ...] = ()
    """Normalized domain names and addresses that identify the asset."""

    hosts: tuple[Host, ...] = ()
    """Host identities resolved for the asset."""

    endpoints: tuple[Endpoint, ...] = ()
    """Known network endpoints through which the asset can be reached."""
