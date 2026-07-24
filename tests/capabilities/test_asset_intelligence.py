"""Tests for the Asset Intelligence capability."""

from ipaddress import ip_address

import pytest  # type: ignore[reportMissingImports]

from redforge.capabilities.asset_intelligence import AssetIntelligenceCapability
from redforge.domain.asset_intelligence import AssetIntelligence
from redforge.domain.endpoint import Endpoint
from redforge.domain.host import Host
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


@pytest.mark.parametrize(
    "source",
    [
        "https://[invalid",
        "https://[gggg::1]/",
        "not-a-url",
    ],
)
def test_malformed_technology_source_is_ignored(source: str) -> None:
    """Untrusted provenance cannot terminate Asset Intelligence."""
    technology = Technology(name="Unknown", category="other", source=source)
    context = Context(
        target_id="example.com",
        state={
            PipelineStateKey.ENDPOINTS: [
                Endpoint(host="valid.example.com", port=443, protocol="https")
            ],
            PipelineStateKey.TECHNOLOGIES: [technology],
        },
    )

    result = AssetIntelligenceCapability().execute(context)

    assert result.status == Status.SUCCESS
    assert [asset.identifier for asset in result.data.assets] == ["asset:valid.example.com"]
    assert result.data.technology_associations == ()
    assert result.metadata["unassociated_technology_count"] == 1


def test_identifiers_and_aliases_are_independent_of_input_order() -> None:
    """The same snapshot facts produce identical ordered identity output."""
    first_host = Host(address=ip_address("203.0.113.10"), hostname="z.example.com")
    second_host = Host(address=ip_address("203.0.113.10"), hostname="a.example.com")
    first_endpoint = Endpoint(host="z.example.com", port=443, protocol="https", path="/z")
    second_endpoint = Endpoint(host="a.example.com", port=80, protocol="http", path="/a")

    def execute(*, reverse: bool) -> AssetIntelligence:
        hosts = [first_host, second_host]
        endpoints = [first_endpoint, second_endpoint]
        subdomains = ["z.example.com", "a.example.com"]
        if reverse:
            hosts.reverse()
            endpoints.reverse()
            subdomains.reverse()
        context = Context(
            target_id="example.com",
            state={
                PipelineStateKey.SUBDOMAINS: subdomains,
                PipelineStateKey.ALIVE_HOSTS: hosts,
                PipelineStateKey.ENDPOINTS: endpoints,
            },
        )
        return AssetIntelligenceCapability().execute(context).data

    forward = execute(reverse=False)
    reverse = execute(reverse=True)

    assert forward == reverse
    assert forward.assets[0].identifier == "asset:a.example.com"
    assert forward.assets[0].aliases == (
        "203.0.113.10",
        "a.example.com",
        "z.example.com",
    )


def test_identifier_is_snapshot_local_to_available_identity_data() -> None:
    """Enrichment can change an ID because cross-scan persistence is out of scope."""
    address = ip_address("203.0.113.10")
    ip_only = Context(
        target_id="example.com",
        state={PipelineStateKey.HOSTS: [Host(address=address)]},
    )
    enriched = Context(
        target_id="example.com",
        state={PipelineStateKey.HOSTS: [Host(address=address, hostname="www.example.com")]},
    )

    ip_asset = AssetIntelligenceCapability().execute(ip_only).data.assets[0]
    enriched_asset = AssetIntelligenceCapability().execute(enriched).data.assets[0]

    assert ip_asset.identifier == "asset:203.0.113.10"
    assert enriched_asset.identifier == "asset:www.example.com"


def test_duplicate_technology_associations_are_deduplicated() -> None:
    """Set-backed deduplication preserves one deterministic relationship."""
    technology = Technology(
        name="nginx",
        category="web-server",
        source="https://www.example.com/",
    )
    context = Context(
        target_id="example.com",
        state={PipelineStateKey.TECHNOLOGIES: [technology, technology]},
    )

    result = AssetIntelligenceCapability().execute(context)

    assert len(result.data.technology_associations) == 1
    assert result.metadata["unassociated_technology_count"] == 0


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
