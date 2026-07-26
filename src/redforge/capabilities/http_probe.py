"""Tool-agnostic HTTP service probing capability."""

from typing import Any, cast

from redforge.domain.host import Host, HostResolution
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.http_probe import (
    HttpProbeProvider,
    HttpProbeProviderResult,
    HttpProbeProviderStatus,
)
from redforge.sdk.result import Result, Status


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


class HttpProbeCapability(Capability):
    """Identify responsive HTTP services through an injected domain provider."""

    def __init__(self, *, provider: HttpProbeProvider | None = None) -> None:
        self._provider = provider or _UnavailableHttpProbeProvider()

    def execute(self, context: Context) -> Result[tuple[Host, ...]]:
        """Probe the current resolved-host state exactly once."""
        hosts = self._get_hosts_from_state(context.state)
        if not hosts:
            return Result(status=Status.SUCCESS, data=())
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

        responsive_hosts = tuple(
            sorted(set(response.responsive_hosts), key=_host_sort_key)
        )
        if response.status is HttpProbeProviderStatus.SUCCESS:
            status = Status.SUCCESS
        elif response.status is HttpProbeProviderStatus.PARTIAL:
            status = Status.PARTIAL if responsive_hosts else Status.FAILURE
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
        return Result(
            status=status,
            data=responsive_hosts,
            errors=errors,
            metadata={
                "responsive_host_count": len(responsive_hosts),
                "endpoint_count": len(response.endpoints),
                "provider_status": response.status.value,
                "malformed_record_count": response.malformed_record_count,
                "out_of_scope_count": response.out_of_scope_count,
                "duplicate_count": response.duplicate_count,
                "truncated": response.truncated,
            },
        )

    @staticmethod
    def _get_hosts_from_state(state: dict[str, Any]) -> tuple[Host, ...]:  # type: ignore[reportUnknownParameterType]
        resolution = state.get(PipelineStateKey.HOSTS)
        if not isinstance(resolution, HostResolution):
            return ()
        return resolution.hosts

    @staticmethod
    def _error_result(message: str) -> Result[tuple[Host, ...]]:
        return Result(
            status=Status.ERROR,
            data=(),
            errors=[message],
        )

    @property
    def name(self) -> str:
        """Return the stable capability identity."""
        return "http_probe"
