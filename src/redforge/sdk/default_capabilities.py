"""Canonical built-in RedForge capability definitions."""

from redforge.sdk.capability_definition import CapabilityDefinition
from redforge.sdk.capability_id import (
    ASSET_INTELLIGENCE,
    HOST_RESOLUTION,
    HTTP_PROBE,
    KNOWLEDGE_GRAPH,
    RISK_INTELLIGENCE,
    SUBDOMAIN_DISCOVERY,
    TECHNOLOGY_DETECTION,
    VULNERABILITY_INTELLIGENCE,
    WEB_CRAWL,
)
from redforge.sdk.state import PipelineStateKey

DEFAULT_CAPABILITY_DEFINITIONS = (
    CapabilityDefinition(
        capability_id=ASSET_INTELLIGENCE,
        display_name="Asset Intelligence",
        description="Builds normalized asset records from available observations.",
        version="1.0",
        provides=(PipelineStateKey.ASSET_INTELLIGENCE,),
        tags=("analysis", "intelligence"),
    ),
    CapabilityDefinition(
        capability_id=HOST_RESOLUTION,
        display_name="Host Resolution",
        description="Resolves discovered subdomains into normalized host records.",
        version="1.0",
        requires=(PipelineStateKey.SUBDOMAINS,),
        provides=(PipelineStateKey.HOSTS,),
        tags=("network", "recon"),
    ),
    CapabilityDefinition(
        capability_id=HTTP_PROBE,
        display_name="HTTP Probe",
        description="Identifies hosts with responsive HTTP services.",
        version="1.0",
        requires=(PipelineStateKey.HOSTS,),
        provides=(
            PipelineStateKey.ALIVE_HOSTS,
            PipelineStateKey.HTTP_ENDPOINTS,
        ),
        tags=("active", "http", "recon"),
    ),
    CapabilityDefinition(
        capability_id=KNOWLEDGE_GRAPH,
        display_name="Knowledge Graph",
        description="Builds explicit relationships across security intelligence.",
        version="1.0",
        requires=(
            PipelineStateKey.ASSET_INTELLIGENCE,
            PipelineStateKey.VULNERABILITY_INTELLIGENCE,
        ),
        provides=(PipelineStateKey.KNOWLEDGE_GRAPH,),
        tags=("analysis", "graph", "intelligence"),
    ),
    CapabilityDefinition(
        capability_id=RISK_INTELLIGENCE,
        display_name="Risk Intelligence",
        description="Prioritizes explicit knowledge graph findings for investigation.",
        version="1.0",
        requires=(PipelineStateKey.KNOWLEDGE_GRAPH,),
        provides=(PipelineStateKey.RISK_INTELLIGENCE,),
        tags=("analysis", "intelligence", "risk"),
    ),
    CapabilityDefinition(
        capability_id=SUBDOMAIN_DISCOVERY,
        display_name="Subdomain Discovery",
        description="Discovers subdomain identities associated with a target.",
        version="1.0",
        provides=(PipelineStateKey.SUBDOMAINS,),
        tags=("passive", "recon"),
    ),
    CapabilityDefinition(
        capability_id=TECHNOLOGY_DETECTION,
        display_name="Technology Detection",
        description="Identifies technologies observed on discovered endpoints.",
        version="1.0",
        requires=(PipelineStateKey.ENDPOINTS,),
        provides=(PipelineStateKey.TECHNOLOGIES,),
        tags=("analysis", "http", "recon"),
    ),
    CapabilityDefinition(
        capability_id=VULNERABILITY_INTELLIGENCE,
        display_name="Vulnerability Intelligence",
        description="Correlates asset technologies with vulnerability records.",
        version="1.0",
        requires=(PipelineStateKey.ASSET_INTELLIGENCE,),
        provides=(PipelineStateKey.VULNERABILITY_INTELLIGENCE,),
        tags=("analysis", "intelligence"),
    ),
    CapabilityDefinition(
        capability_id=WEB_CRAWL,
        display_name="Web Crawl",
        description="Discovers application endpoints on responsive HTTP hosts.",
        version="1.0",
        requires=(PipelineStateKey.ALIVE_HOSTS,),
        provides=(PipelineStateKey.ENDPOINTS,),
        tags=("active", "http", "recon"),
    ),
)
"""Built-in definitions sorted by capability identity."""
