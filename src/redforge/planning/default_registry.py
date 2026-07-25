"""Central planning declarations for existing RedForge capabilities."""

from redforge.planning.models import CapabilityDescriptor
from redforge.planning.registry import CapabilityRegistry
from redforge.runtime.pipeline_state import PipelineStateKey


def create_default_registry() -> CapabilityRegistry:
    """Return a new registry containing current capability state contracts."""
    descriptors = (
        CapabilityDescriptor(
            name="subdomain_discovery",
            provides=(PipelineStateKey.SUBDOMAINS,),
        ),
        CapabilityDescriptor(
            name="host_resolution",
            requires=(PipelineStateKey.SUBDOMAINS,),
            provides=(PipelineStateKey.HOSTS,),
        ),
        CapabilityDescriptor(
            name="http_probe",
            requires=(PipelineStateKey.HOSTS,),
            provides=(PipelineStateKey.ALIVE_HOSTS,),
        ),
        CapabilityDescriptor(
            name="web_crawl",
            requires=(PipelineStateKey.ALIVE_HOSTS,),
            provides=(PipelineStateKey.ENDPOINTS,),
        ),
        CapabilityDescriptor(
            name="technology_detection",
            requires=(PipelineStateKey.ENDPOINTS,),
            provides=(PipelineStateKey.TECHNOLOGIES,),
        ),
        CapabilityDescriptor(
            name="asset_intelligence",
            provides=(PipelineStateKey.ASSET_INTELLIGENCE,),
        ),
        CapabilityDescriptor(
            name="vulnerability_intelligence",
            requires=(PipelineStateKey.ASSET_INTELLIGENCE,),
            provides=(PipelineStateKey.VULNERABILITY_INTELLIGENCE,),
        ),
        CapabilityDescriptor(
            name="knowledge_graph",
            requires=(
                PipelineStateKey.ASSET_INTELLIGENCE,
                PipelineStateKey.VULNERABILITY_INTELLIGENCE,
            ),
            provides=(PipelineStateKey.KNOWLEDGE_GRAPH,),
        ),
        CapabilityDescriptor(
            name="risk_intelligence",
            requires=(PipelineStateKey.KNOWLEDGE_GRAPH,),
            provides=(PipelineStateKey.RISK_INTELLIGENCE,),
        ),
    )
    registry = CapabilityRegistry()
    for descriptor in descriptors:
        registry.register(descriptor)
    return registry
