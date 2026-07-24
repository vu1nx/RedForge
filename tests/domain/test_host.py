"""Tests for resolved host domain models."""

from dataclasses import FrozenInstanceError
from ipaddress import IPv4Address

import pytest  # type: ignore[reportMissingImports]

from redforge.domain.host import Host, HostAddress, HostResolution, IPVersion


def test_host_address_canonicalizes_ipv4_and_ipv6() -> None:
    ipv4 = HostAddress("192.0.2.1", IPVersion.IPV4)
    ipv6 = HostAddress("2001:0db8:0000::1", IPVersion.IPV6)

    assert ipv4.value == "192.0.2.1"
    assert ipv6.value == "2001:db8::1"


def test_host_address_rejects_version_mismatch_and_invalid_values() -> None:
    with pytest.raises(ValueError):
        HostAddress("192.0.2.1", IPVersion.IPV6)
    with pytest.raises(ValueError):
        HostAddress("not-an-address", IPVersion.IPV4)


def test_host_models_are_immutable_slotted_and_tuple_based() -> None:
    address = HostAddress("192.0.2.1", IPVersion.IPV4)
    host = Host(
        hostname="example.com",
        addresses=(address,),
        evidence=("hostname-input:example.com",),
    )
    resolution = HostResolution(hosts=(host,))

    assert host.addresses == (address,)
    assert host.address == IPv4Address("192.0.2.1")
    assert resolution.hosts == (host,)
    assert not hasattr(address, "__dict__")
    assert not hasattr(host, "__dict__")
    assert not hasattr(resolution, "__dict__")
    with pytest.raises(FrozenInstanceError):
        host.hostname = "other.example"  # type: ignore[misc]


def test_host_rejects_mutable_address_and_evidence_collections() -> None:
    address = HostAddress("192.0.2.1", IPVersion.IPV4)
    with pytest.raises(TypeError):
        Host(hostname="example.com", addresses=[address])  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        Host(hostname="example.com", evidence=["mutable"])  # type: ignore[arg-type]


def test_legacy_single_address_view_remains_compatible() -> None:
    host = Host(address=IPv4Address("192.0.2.1"), hostname="example.com")

    assert host.addresses == (HostAddress("192.0.2.1", IPVersion.IPV4),)
    assert host.address == IPv4Address("192.0.2.1")
