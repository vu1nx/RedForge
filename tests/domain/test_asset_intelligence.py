"""Tests for Asset Intelligence domain models."""

from dataclasses import FrozenInstanceError
from ipaddress import ip_address

import pytest  # type: ignore[reportMissingImports]

from redforge.domain.asset import Asset
from redforge.domain.asset_association import AssetAssociation
from redforge.domain.asset_intelligence import AssetIntelligence
from redforge.domain.endpoint import Endpoint
from redforge.domain.host import Host
from redforge.domain.technology import Technology


def test_asset_remains_backward_compatible() -> None:
    """Existing identity fields can still construct a minimal asset."""
    asset = Asset(identifier="asset:example.com", type="domain", name="example.com")

    assert asset.aliases == ()
    assert asset.hosts == ()
    assert asset.endpoints == ()


def test_asset_contains_identity_and_reachability_only() -> None:
    """Asset stores aliases, hosts, and endpoints without owning security knowledge."""
    host = Host(address=ip_address("203.0.113.10"), hostname="www.example.com")
    endpoint = Endpoint(host="www.example.com", port=443, protocol="https", path="/")

    asset = Asset(
        identifier="asset:www.example.com",
        type="host",
        aliases=("203.0.113.10", "www.example.com"),
        hosts=(host,),
        endpoints=(endpoint,),
    )

    assert asset.hosts == (host,)
    assert asset.endpoints == (endpoint,)
    assert not hasattr(asset, "technologies")


def test_asset_is_immutable() -> None:
    """Stable asset identity snapshots cannot be mutated."""
    asset = Asset(identifier="asset:example.com", type="domain")

    with pytest.raises(FrozenInstanceError):
        asset.name = "changed"  # type: ignore[misc]


def test_asset_association_keeps_knowledge_independent() -> None:
    """Knowledge is connected by an explicit typed relationship."""
    technology = Technology(name="nginx", category="web-server")
    association = AssetAssociation(asset_id="asset:example.com", knowledge=technology)

    assert association.asset_id == "asset:example.com"
    assert association.knowledge is technology


def test_asset_intelligence_defaults_to_empty_snapshot() -> None:
    """The read model has safe immutable defaults."""
    assert AssetIntelligence() == AssetIntelligence(
        assets=(),
        technology_associations=(),
    )


def test_read_model_exposes_only_supported_relationships() -> None:
    """Unsupported knowledge relationships are not implied by the contract."""
    intelligence = AssetIntelligence()

    assert not hasattr(intelligence, "service_associations")
    assert not hasattr(intelligence, "finding_associations")
    assert not hasattr(intelligence, "evidence_associations")
