"""Typed, extensible capability identities."""

from dataclasses import dataclass
from typing import cast


@dataclass(frozen=True, slots=True, order=True)
class CapabilityId:
    """Stable serialized identity for a built-in or custom capability."""

    value: str

    def __post_init__(self) -> None:
        value = cast(object, self.value)
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip().lower()
            or not (value[0].isascii() and value[0].islower())
            or value[0] == "_"
            or value[-1] == "_"
            or "__" in value
            or any(
                not (character.isascii() and character.isalnum())
                and character != "_"
                for character in value
            )
        ):
            raise ValueError("capability ID is invalid")

    def __str__(self) -> str:
        """Return the stable serialized value."""
        return self.value


def normalize_capability_id(value: CapabilityId | str) -> CapabilityId:
    """Return a validated typed identity, accepting legacy strings narrowly."""
    if isinstance(value, CapabilityId):
        return value
    if isinstance(cast(object, value), str):
        return CapabilityId(value)
    raise TypeError("capability identity must be CapabilityId or string")


SUBDOMAIN_DISCOVERY = CapabilityId("subdomain_discovery")
HOST_RESOLUTION = CapabilityId("host_resolution")
HTTP_PROBE = CapabilityId("http_probe")
WEB_CRAWL = CapabilityId("web_crawl")
TECHNOLOGY_DETECTION = CapabilityId("technology_detection")
ASSET_INTELLIGENCE = CapabilityId("asset_intelligence")
VULNERABILITY_INTELLIGENCE = CapabilityId("vulnerability_intelligence")
VULNERABILITY_DETECTION = CapabilityId("vulnerability_detection")
FINDING_CORRELATION = CapabilityId("finding_correlation")
VULNERABILITY_ENRICHMENT = CapabilityId("vulnerability_enrichment")
KNOWLEDGE_GRAPH = CapabilityId("knowledge_graph")
RISK_INTELLIGENCE = CapabilityId("risk_intelligence")

BUILTIN_CAPABILITY_IDS = (
    ASSET_INTELLIGENCE,
    FINDING_CORRELATION,
    HOST_RESOLUTION,
    HTTP_PROBE,
    KNOWLEDGE_GRAPH,
    RISK_INTELLIGENCE,
    SUBDOMAIN_DISCOVERY,
    TECHNOLOGY_DETECTION,
    VULNERABILITY_DETECTION,
    VULNERABILITY_ENRICHMENT,
    VULNERABILITY_INTELLIGENCE,
    WEB_CRAWL,
)
"""Built-in identities sorted by serialized value."""
