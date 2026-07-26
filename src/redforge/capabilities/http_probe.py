"""Tool-agnostic HTTP service probing capability."""

from ipaddress import ip_address
from typing import Any, cast

from redforge.domain.host import Host, HostAddress, HostResolution, IPVersion
from redforge.domain.hostname import normalize_dns_hostname
from redforge.domain.http_probe import HttpProbeEndpoint
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.http_probe import (
    HttpProbeProvider,
    HttpProbeProviderResult,
    HttpProbeProviderStatus,
)
from redforge.sdk.result import Result, StatePublication, Status


class _UnavailableHttpProbeProvider:
    """Safe default for manual capability construction."""

    def probe(self, hosts: tuple[Host, ...]) -> HttpProbeProviderResult:
        del hosts
        return HttpProbeProviderResult(
            status=HttpProbeProviderStatus.UNAVAILABLE,
            message="HTTP probe provider is unavailable.",
        )


def _host_sort_key(host: Host) -> tuple[object, ...]:
    return (
        host.hostname or "",
        tuple(address.value for address in host.addresses),
        host.evidence,
    )


def _endpoint_identity(endpoint: HttpProbeEndpoint) -> tuple[str, str, int]:
    return endpoint.scheme, endpoint.hostname, endpoint.port


def _normalize_endpoints(
    endpoints: tuple[HttpProbeEndpoint, ...],
) -> tuple[HttpProbeEndpoint, ...]:
    """Return unique endpoints in canonical identity order."""
    normalized: dict[tuple[str, str, int], HttpProbeEndpoint] = {}
    for endpoint in endpoints:
        identity = _endpoint_identity(endpoint)
        existing = normalized.get(identity)
        if existing is not None and existing != endpoint:
            raise ValueError("HTTP probe provider returned conflicting endpoints")
        normalized.setdefault(identity, endpoint)
    return tuple(normalized[identity] for identity in sorted(normalized))


def _address(value: str) -> HostAddress:
    parsed = ip_address(value)
    return HostAddress(
        value=str(parsed),
        version=IPVersion.IPV4 if parsed.version == 4 else IPVersion.IPV6,
    )


def _derive_alive_hosts(
    endpoints: tuple[HttpProbeEndpoint, ...],
    source_hosts: tuple[Host, ...],
) -> tuple[Host, ...]:
    """Derive one deterministic host per endpoint host identity."""
    sources: dict[str, Host] = {}
    for host in sorted(set(source_hosts), key=_host_sort_key):
        if host.hostname is not None:
            sources.setdefault(normalize_dns_hostname(host.hostname), host)
        for address in host.addresses:
            sources.setdefault(str(ip_address(address.value)), host)

    alive: set[Host] = set()
    for endpoint in endpoints:
        source = sources.get(endpoint.hostname)
        if source is None and endpoint.ip_address is not None:
            source = sources.get(endpoint.ip_address)
        if source is not None:
            alive.add(source)
            continue
        try:
            endpoint_address = _address(endpoint.hostname)
        except ValueError:
            addresses = (
                (_address(endpoint.ip_address),)
                if endpoint.ip_address is not None
                else ()
            )
            alive.add(Host(hostname=endpoint.hostname, addresses=addresses))
        else:
            alive.add(Host(addresses=(endpoint_address,)))
    return tuple(sorted(alive, key=_host_sort_key))


class HttpProbeCapability(Capability):
    """Identify responsive HTTP services through an injected domain provider."""

    def __init__(self, *, provider: HttpProbeProvider | None = None) -> None:
        self._provider = provider or _UnavailableHttpProbeProvider()

    def execute(self, context: Context) -> Result[None]:
        """Probe the current resolved-host state exactly once."""
        hosts = self._get_hosts_from_state(context.state)
        if not hosts:
            return self._publishable_result(
                status=Status.SUCCESS,
                endpoints=(),
                responsive_hosts=(),
                provider_status=HttpProbeProviderStatus.SUCCESS,
            )
        try:
            response = cast(object, self._provider.probe(hosts))
        except Exception:
            return self._error_result(
                "HTTP probe provider failed with an unexpected execution error"
            )
        if not isinstance(response, HttpProbeProviderResult):
            return self._error_result(
                "HTTP probe provider returned an invalid result"
            )

        try:
            endpoints = _normalize_endpoints(response.endpoints)
            responsive_hosts = _derive_alive_hosts(endpoints, hosts)
        except (TypeError, ValueError):
            return self._error_result(
                "HTTP probe provider returned invalid endpoint evidence"
            )
        if response.status is HttpProbeProviderStatus.SUCCESS:
            status = Status.SUCCESS
        elif response.status is HttpProbeProviderStatus.PARTIAL:
            status = Status.PARTIAL if endpoints else Status.FAILURE
        elif response.status is HttpProbeProviderStatus.FAILURE:
            status = Status.FAILURE
        else:
            status = Status.ERROR
        errors = (
            []
            if status is Status.SUCCESS
            else [
                response.message
                or (
                    "HTTP probing completed with partial findings"
                    if status is Status.PARTIAL
                    else "HTTP probing failed"
                )
            ]
        )
        publications = (
            (
                StatePublication(PipelineStateKey.ALIVE_HOSTS, responsive_hosts),
                StatePublication(PipelineStateKey.HTTP_ENDPOINTS, endpoints),
            )
            if status in {Status.SUCCESS, Status.PARTIAL}
            else ()
        )
        return Result(
            status=status,
            data=None,
            errors=errors,
            metadata={
                "responsive_host_count": len(responsive_hosts),
                "endpoint_count": len(endpoints),
                "provider_status": response.status.value,
                "malformed_record_count": response.malformed_record_count,
                "out_of_scope_count": response.out_of_scope_count,
                "duplicate_count": response.duplicate_count,
                "truncated": response.truncated,
            },
            publications=publications,
        )

    @staticmethod
    def _publishable_result(
        *,
        status: Status,
        endpoints: tuple[HttpProbeEndpoint, ...],
        responsive_hosts: tuple[Host, ...],
        provider_status: HttpProbeProviderStatus,
    ) -> Result[None]:
        return Result(
            status=status,
            data=None,
            metadata={
                "responsive_host_count": len(responsive_hosts),
                "endpoint_count": len(endpoints),
                "provider_status": provider_status.value,
                "malformed_record_count": 0,
                "out_of_scope_count": 0,
                "duplicate_count": 0,
                "truncated": False,
            },
            publications=(
                StatePublication(PipelineStateKey.ALIVE_HOSTS, responsive_hosts),
                StatePublication(PipelineStateKey.HTTP_ENDPOINTS, endpoints),
            ),
        )

    @staticmethod
    def _get_hosts_from_state(state: dict[str, Any]) -> tuple[Host, ...]:  # type: ignore[reportUnknownParameterType]
        resolution = state.get(PipelineStateKey.HOSTS)
        if not isinstance(resolution, HostResolution):
            return ()
        return resolution.hosts

    @staticmethod
    def _error_result(message: str) -> Result[None]:
        return Result(
            status=Status.ERROR,
            data=None,
            errors=[message],
        )

    @property
    def name(self) -> str:
        """Return the stable capability identity."""
        return "http_probe"
