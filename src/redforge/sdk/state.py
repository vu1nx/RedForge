"""Typed state-key identities shared by capabilities and the runtime."""

from enum import StrEnum
from typing import cast


class PipelineStateKey(StrEnum):
    """Canonical keys used to pass typed data between capabilities."""

    HOSTS = "hosts"
    SUBDOMAINS = "subdomains"
    ALIVE_HOSTS = "alive_hosts"
    HTTP_ENDPOINTS = "http_endpoints"
    ENDPOINTS = "endpoints"
    TECHNOLOGIES = "technologies"
    ASSET_INTELLIGENCE = "asset_intelligence"
    VULNERABILITY_INTELLIGENCE = "vulnerability_intelligence"
    VULNERABILITIES = "vulnerabilities"
    CANONICAL_FINDINGS = "canonical_findings"
    ENRICHED_VULNERABILITIES = "enriched_vulnerabilities"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    RISK_INTELLIGENCE = "risk_intelligence"


def validate_pipeline_state_value(key: PipelineStateKey, value: object) -> None:
    """Validate every canonical state value before atomic publication."""
    if key is PipelineStateKey.SUBDOMAINS:
        from redforge.sdk.subdomain_discovery import SubdomainDiscoveryResult

        _validate_instance(value, SubdomainDiscoveryResult, key)
    elif key is PipelineStateKey.HOSTS:
        from redforge.domain.host import HostResolution

        _validate_instance(value, HostResolution, key)
    elif key is PipelineStateKey.ALIVE_HOSTS:
        from redforge.domain.host import Host

        _validate_typed_tuple(value, Host, key)
    elif key is PipelineStateKey.HTTP_ENDPOINTS:
        from redforge.domain.http_probe import HttpProbeEndpoint

        _validate_typed_tuple(value, HttpProbeEndpoint, key)
    elif key is PipelineStateKey.ENDPOINTS:
        from redforge.domain.endpoint import Endpoint

        _validate_typed_tuple(value, Endpoint, key)
    elif key is PipelineStateKey.TECHNOLOGIES:
        from redforge.domain.technology import Technology

        _validate_typed_tuple(value, Technology, key)
    elif key is PipelineStateKey.ASSET_INTELLIGENCE:
        from redforge.domain.asset_intelligence import AssetIntelligence

        _validate_instance(value, AssetIntelligence, key)
    elif key is PipelineStateKey.VULNERABILITY_INTELLIGENCE:
        from redforge.domain.vulnerability_intelligence import (
            VulnerabilityIntelligence,
        )

        _validate_instance(value, VulnerabilityIntelligence, key)
    elif key is PipelineStateKey.VULNERABILITIES:
        from redforge.domain.finding_intelligence import FindingRecordCollection

        _validate_instance(value, FindingRecordCollection, key)
    elif key is PipelineStateKey.CANONICAL_FINDINGS:
        from redforge.domain.finding_correlation import CanonicalFindingCollection

        _validate_instance(value, CanonicalFindingCollection, key)
    elif key is PipelineStateKey.ENRICHED_VULNERABILITIES:
        from redforge.domain.vulnerability_enrichment import (
            EnrichedCanonicalFindingCollection,
        )

        _validate_instance(value, EnrichedCanonicalFindingCollection, key)
    elif key is PipelineStateKey.KNOWLEDGE_GRAPH:
        from redforge.domain.knowledge_graph import KnowledgeGraph

        _validate_instance(value, KnowledgeGraph, key)
    elif key is PipelineStateKey.RISK_INTELLIGENCE:
        from redforge.domain.risk_intelligence import RiskIntelligence

        _validate_instance(value, RiskIntelligence, key)


def _validate_instance(
    value: object,
    expected_type: type[object],
    key: PipelineStateKey,
) -> None:
    if not isinstance(value, expected_type):
        raise TypeError(f"state value for '{key.value}' has an invalid type")


def _validate_typed_tuple(
    value: object,
    item_type: type[object],
    key: PipelineStateKey,
) -> None:
    if not isinstance(value, tuple) or not all(
        isinstance(item, item_type) for item in cast(tuple[object, ...], value)
    ):
        raise TypeError(f"state value for '{key.value}' has an invalid type")
