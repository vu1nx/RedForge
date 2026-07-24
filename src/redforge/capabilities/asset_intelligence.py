"""Asset Intelligence capability for correlating reconnaissance knowledge."""

from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Any, cast
from urllib.parse import urlsplit

from redforge.domain.asset import Asset
from redforge.domain.asset_association import AssetAssociation
from redforge.domain.asset_intelligence import AssetIntelligence
from redforge.domain.endpoint import Endpoint
from redforge.domain.host import Host
from redforge.domain.technology import Technology
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


@dataclass(slots=True)
class _AssetBuilder:
    """Mutable identity accumulator used only while constructing the read model."""

    aliases: set[str] = field(default_factory=lambda: set[str]())
    hosts: set[Host] = field(default_factory=lambda: set[Host]())
    endpoints: set[Endpoint] = field(default_factory=lambda: set[Endpoint]())


class _IdentityIndex:
    """Resolve aliases to identity builders and merge explicitly linked aliases."""

    def __init__(self) -> None:
        self.builders: list[_AssetBuilder] = []
        self.by_alias: dict[str, _AssetBuilder] = {}

    def add(self, aliases: set[str]) -> _AssetBuilder:
        existing: list[_AssetBuilder] = []
        for alias in aliases:
            builder = self.by_alias.get(alias)
            if builder is not None and all(builder is not item for item in existing):
                existing.append(builder)

        if existing:
            builder = existing[0]
            for other in existing[1:]:
                self._merge(builder, other)
        else:
            builder = _AssetBuilder()
            self.builders.append(builder)

        builder.aliases.update(aliases)
        for alias in builder.aliases:
            self.by_alias[alias] = builder
        return builder

    def find(self, alias: str) -> _AssetBuilder | None:
        return self.by_alias.get(alias)

    def _merge(self, destination: _AssetBuilder, source: _AssetBuilder) -> None:
        destination.aliases.update(source.aliases)
        destination.hosts.update(source.hosts)
        destination.endpoints.update(source.endpoints)
        for alias in source.aliases:
            self.by_alias[alias] = destination
        self.builders.remove(source)


class AssetIntelligenceCapability(Capability):
    """Build snapshot-local asset identities and explicit technology relationships."""

    def execute(self, context: Context) -> Result[AssetIntelligence]:
        """Correlate pipeline knowledge into the Asset Intelligence read model."""
        subdomains = self._get_subdomains(context.state)
        discovered_hosts = self._get_typed_list(context.state, PipelineStateKey.HOSTS, Host)
        alive_hosts = self._get_typed_list(context.state, PipelineStateKey.ALIVE_HOSTS, Host)
        hosts = list(dict.fromkeys([*discovered_hosts, *alive_hosts]))
        endpoints = self._get_typed_list(context.state, PipelineStateKey.ENDPOINTS, Endpoint)
        technologies = self._get_typed_list(
            context.state, PipelineStateKey.TECHNOLOGIES, Technology
        )

        index = self._build_identity_index(subdomains, hosts, endpoints, technologies)
        assets, assets_by_builder = self._build_assets(index)

        technology_associations, unassociated_technology_count = self._associate_technologies(
            technologies, index, assets_by_builder
        )

        intelligence = AssetIntelligence(
            assets=assets,
            technology_associations=technology_associations,
        )
        return Result(
            status=Status.SUCCESS,
            data=intelligence,
            metadata={
                "asset_count": len(assets),
                "technology_association_count": len(technology_associations),
                "unassociated_technology_count": unassociated_technology_count,
            },
        )

    def _build_identity_index(
        self,
        subdomains: list[str],
        hosts: list[Host],
        endpoints: list[Endpoint],
        technologies: list[Technology],
    ) -> _IdentityIndex:
        index = _IdentityIndex()

        for host in hosts:
            aliases = {self._normalize_alias(str(host.address))}
            if host.hostname:
                aliases.add(self._normalize_alias(host.hostname))
            builder = index.add(aliases)
            builder.hosts.add(host)

        for subdomain in subdomains:
            alias = self._normalize_alias(subdomain)
            if alias:
                index.add({alias})

        for endpoint in endpoints:
            alias = self._normalize_alias(endpoint.host)
            if not alias:
                continue
            builder = index.add({alias})
            builder.endpoints.add(endpoint)

        for technology in technologies:
            alias = self._source_host(technology.source)
            if alias:
                index.add({alias})

        return index

    def _build_assets(self, index: _IdentityIndex) -> tuple[tuple[Asset, ...], dict[int, Asset]]:
        assets: list[Asset] = []
        by_builder: dict[int, Asset] = {}

        for builder in index.builders:
            canonical = min(builder.aliases, key=self._alias_sort_key)
            asset = Asset(
                identifier=f"asset:{canonical}",
                type=self._asset_type(builder),
                name=canonical,
                aliases=tuple(sorted(builder.aliases)),
                hosts=tuple(
                    sorted(
                        builder.hosts,
                        key=lambda host: (str(host.address), host.hostname or ""),
                    )
                ),
                endpoints=tuple(
                    sorted(
                        builder.endpoints,
                        key=lambda endpoint: (
                            endpoint.host,
                            endpoint.port,
                            endpoint.protocol,
                            endpoint.path or "",
                        ),
                    )
                ),
            )
            assets.append(asset)
            by_builder[id(builder)] = asset

        assets.sort(key=lambda asset: asset.identifier)
        return tuple(assets), by_builder

    def _associate_technologies(
        self,
        technologies: list[Technology],
        index: _IdentityIndex,
        assets_by_builder: dict[int, Asset],
    ) -> tuple[tuple[AssetAssociation[Technology], ...], int]:
        associations: list[AssetAssociation[Technology]] = []
        seen: set[AssetAssociation[Technology]] = set()
        unassociated_count = 0
        for technology in technologies:
            alias = self._source_host(technology.source)
            builder = index.find(alias) if alias else None
            if builder is None:
                unassociated_count += 1
                continue
            asset = assets_by_builder[id(builder)]
            association = AssetAssociation(asset_id=asset.identifier, knowledge=technology)
            if association not in seen:
                seen.add(association)
                associations.append(association)

        associations.sort(
            key=lambda association: (
                association.asset_id,
                association.knowledge.name,
                association.knowledge.category,
                association.knowledge.version or "",
                association.knowledge.vendor or "",
                association.knowledge.description or "",
                association.knowledge.source or "",
                association.knowledge.evidence,
                association.knowledge.confidence
                if association.knowledge.confidence is not None
                else -1,
            )
        )
        return tuple(associations), unassociated_count

    def _get_subdomains(self, state: dict[str, Any]) -> list[str]:  # type: ignore[reportUnknownParameterType]
        value = state.get(PipelineStateKey.SUBDOMAINS, [])
        if isinstance(value, dict):
            value = cast(dict[str, Any], value).get("subdomains", [])
        if not isinstance(value, list):
            return []
        return [
            item
            for item in cast(list[Any], value)
            if isinstance(item, str) and self._normalize_alias(item)
        ]

    def _get_typed_list[T](
        self,
        state: dict[str, Any],
        key: str,
        expected_type: type[T],  # type: ignore[reportUnknownParameterType]
    ) -> list[T]:
        value = state.get(key, [])
        if not isinstance(value, list):
            return []
        return [item for item in cast(list[Any], value) if isinstance(item, expected_type)]

    def _source_host(self, source: str | None) -> str | None:
        if not source:
            return None
        try:
            hostname = urlsplit(source).hostname
        except ValueError:
            return None
        if not hostname:
            return None
        return self._normalize_alias(hostname)

    def _normalize_alias(self, value: str) -> str:
        return value.strip().rstrip(".").lower()

    def _alias_sort_key(self, alias: str) -> tuple[int, str]:
        try:
            ip_address(alias)
        except ValueError:
            return (0, alias)
        return (1, alias)

    def _asset_type(self, builder: _AssetBuilder) -> str:
        if builder.hosts:
            return "host"
        if any(self._alias_sort_key(alias)[0] == 1 for alias in builder.aliases):
            return "host"
        return "domain"

    @property
    def name(self) -> str:
        """Return the stable pipeline capability name."""
        return "asset_intelligence"
