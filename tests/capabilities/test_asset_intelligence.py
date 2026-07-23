"""Tests for the Asset Intelligence capability."""

from datetime import UTC, datetime
from ipaddress import ip_address

from redforge.capabilities.asset_intelligence import AssetIntelligenceCapability
from redforge.domain.endpoint import Endpoint
from redforge.domain.evidence import Evidence
from redforge.domain.finding import Finding, Severity
from redforge.domain.host import Host
from redforge.domain.service import Service
from redforge.domain.technology import Technology
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.context import Context
from redforge.sdk.result import Status


def test_execute_builds_assets_and_correlates_technologies() -> None:
    """Aliases merge into stable assets and technology source creates explicit edges."""
    host = Host(address=ip_address("203.0.113.10"), hostname="WWW.Example.COM")
    endpoint = Endpoint(host="www.example.com", port=443, protocol="https", path="/admin")
    nginx = Technology(
        name="nginx",
        category="web-server",
        version="1.24.0",
        source="https://www.example.com/admin",
        evidence=("string: nginx/1.24.0",),
        confidence=100,
    )
    wordpress = Technology(
        name="WordPress",
        category="cms",
        source="https://blog.example.com/",
        confidence=75,
    )
    context = Context(
        target_id="example.com",
        state={
            PipelineStateKey.SUBDOMAINS: {"subdomains": ["www.example.com.", "blog.example.com"]},
            PipelineStateKey.ALIVE_HOSTS: [host],
            PipelineStateKey.HOSTS: [host],
            PipelineStateKey.ENDPOINTS: [endpoint],
            PipelineStateKey.TECHNOLOGIES: [nginx, wordpress],
        },
    )

    result = AssetIntelligenceCapability().execute(context)

    assert result.status == Status.SUCCESS
    assert [asset.identifier for asset in result.data.assets] == [
        "asset:blog.example.com",
        "asset:www.example.com",
    ]

    web_asset = next(
        asset for asset in result.data.assets if asset.identifier == "asset:www.example.com"
    )
    assert web_asset.type == "host"
    assert web_asset.aliases == ("203.0.113.10", "www.example.com")
    assert web_asset.hosts == (host,)
    assert web_asset.endpoints == (endpoint,)

    assert {
        (association.asset_id, association.knowledge.name)
        for association in result.data.technology_associations
    } == {
        ("asset:www.example.com", "nginx"),
        ("asset:blog.example.com", "WordPress"),
    }
    assert result.metadata["unassociated_technology_count"] == 0


def test_same_technology_on_different_assets_remains_distinct() -> None:
    """Correlation does not globally deduplicate observations across assets."""
    first = Technology(
        name="nginx",
        category="web-server",
        source="https://a.example.com/",
    )
    second = Technology(
        name="nginx",
        category="web-server",
        source="https://b.example.com/",
    )
    context = Context(
        target_id="example.com",
        state={PipelineStateKey.TECHNOLOGIES: [first, second]},
    )

    result = AssetIntelligenceCapability().execute(context)

    assert len(result.data.assets) == 2
    assert len(result.data.technology_associations) == 2
    assert {association.asset_id for association in result.data.technology_associations} == {
        "asset:a.example.com",
        "asset:b.example.com",
    }


def test_findings_require_explicit_asset_identifier_and_evidence_is_transitive() -> None:
    """Target-level findings are not guessed onto assets."""
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    associated = Finding(
        identifier="finding-1",
        title="Exposed panel",
        severity=Severity.INFO,
        description="Administrative panel observed",
        target_id="asset:admin.example.com",
        timestamp=timestamp,
    )
    target_level = Finding(
        identifier="finding-2",
        title="Target note",
        severity=Severity.INFO,
        description="Target-level observation",
        target_id="example.com",
        timestamp=timestamp,
    )
    evidence = Evidence(
        identifier="evidence-1",
        finding_id="finding-1",
        type="log",
        content="HTTP 200",
        timestamp=timestamp,
        source="test",
    )
    context = Context(
        target_id="example.com",
        state={
            PipelineStateKey.ENDPOINTS: [
                Endpoint(
                    host="admin.example.com",
                    port=443,
                    protocol="https",
                    path="/",
                )
            ],
            PipelineStateKey.FINDINGS: [associated, target_level],
            PipelineStateKey.EVIDENCE: [evidence],
        },
    )

    result = AssetIntelligenceCapability().execute(context)

    assert len(result.data.finding_associations) == 1
    assert result.data.finding_associations[0].knowledge is associated
    assert len(result.data.evidence_associations) == 1
    assert result.data.evidence_associations[0].asset_id == ("asset:admin.example.com")
    assert result.metadata["unassociated_finding_count"] == 1


def test_services_without_provenance_are_not_guessed_onto_assets() -> None:
    """Matching a common port alone is insufficient evidence of ownership."""
    service = Service(name="https", port=443, protocol="tcp")
    context = Context(
        target_id="example.com",
        state={
            PipelineStateKey.ENDPOINTS: [
                Endpoint(host="one.example.com", port=443, protocol="https", path="/"),
                Endpoint(host="two.example.com", port=443, protocol="https", path="/"),
            ],
            PipelineStateKey.SERVICES: [service],
        },
    )

    result = AssetIntelligenceCapability().execute(context)

    assert result.data.service_associations == ()
    assert result.metadata["unassociated_service_count"] == 1


def test_unprovenanced_technology_remains_unassociated() -> None:
    """Knowledge without an addressable source is retained upstream, not guessed."""
    technology = Technology(name="Unknown", category="other")
    context = Context(
        target_id="example.com",
        state={PipelineStateKey.TECHNOLOGIES: [technology]},
    )

    result = AssetIntelligenceCapability().execute(context)

    assert result.data.assets == ()
    assert result.data.technology_associations == ()
    assert result.metadata["unassociated_technology_count"] == 1


def test_invalid_or_empty_state_returns_empty_successful_snapshot() -> None:
    """Malformed optional pipeline collections do not break aggregation."""
    context = Context(
        target_id="example.com",
        state={
            PipelineStateKey.SUBDOMAINS: "not-a-list",
            PipelineStateKey.ALIVE_HOSTS: {"host": "example.com"},
            PipelineStateKey.ENDPOINTS: None,
            PipelineStateKey.TECHNOLOGIES: [object()],
        },
    )

    result = AssetIntelligenceCapability().execute(context)

    assert result.status == Status.SUCCESS
    assert result.data.assets == ()
    assert result.data.technology_associations == ()


def test_name() -> None:
    """Capability exposes its stable pipeline registration name."""
    assert AssetIntelligenceCapability().name == "asset_intelligence"
