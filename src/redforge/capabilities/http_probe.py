"""HTTP probing capability using httpx."""

from typing import Any, cast

from redforge.adapters.errors import AdapterError
from redforge.adapters.httpx import (
    HttpProbeAdapterResult,
    HttpProbeTransport,
    HttpxAdapter,
)
from redforge.domain.host import Host, HostResolution
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


class HttpProbeCapability(Capability):
    """HTTP probing capability using ProjectDiscovery httpx.

    This capability probes discovered hosts for reachable HTTP/HTTPS services
    using the httpx external tool through the adapter pattern.
    """

    def __init__(
        self,
        binary_path: str = "httpx",
        *,
        transport: HttpProbeTransport | None = None,
    ) -> None:
        """Initialize the HTTP probe capability.

        Args:
            binary_path: Path to the httpx binary (default: "httpx").
        """
        self._transport = transport or HttpxAdapter(binary_path=binary_path)

    def execute(self, context: Context) -> Result[list[Host]]:
        """Execute HTTP probing against hosts from pipeline state.

        Args:
            context: Runtime context containing discovered hosts in state.

        Returns:
            Result containing alive hosts or error information.
        """
        hosts = self._get_hosts_from_state(context.state)

        if not hosts:
            return Result(status=Status.SUCCESS, data=[])

        try:
            response = cast(object, self._transport.probe(tuple(hosts)))
        except AdapterError:
            return Result(
                status=Status.FAILURE,
                data=[],
                errors=["HTTP probe adapter is unavailable or returned an invalid response"],
            )
        except Exception:
            return Result(
                status=Status.ERROR,
                data=[],
                errors=["HTTP probe adapter failed with an unexpected execution error"],
            )
        if not isinstance(response, HttpProbeAdapterResult):
            return Result(
                status=Status.ERROR,
                data=[],
                errors=["HTTP probe adapter returned an invalid result"],
            )
        response_hosts = cast(object, response.hosts)
        if not isinstance(response_hosts, tuple) or not all(
            isinstance(host, Host)
            for host in cast(tuple[object, ...], response_hosts)
        ):
            return Result(
                status=Status.ERROR,
                data=[],
                errors=["HTTP probe adapter returned an invalid result"],
            )
        alive_hosts = sorted(
            set(cast(tuple[Host, ...], response_hosts)),
            key=lambda host: (
                host.hostname or "",
                tuple(address.value for address in host.addresses),
            ),
        )
        return Result(status=Status.SUCCESS, data=alive_hosts)

    def _get_hosts_from_state(self, state: dict[str, Any]) -> list[Host]:  # type: ignore[reportUnknownParameterType]
        resolution = state.get(PipelineStateKey.HOSTS)
        if not isinstance(resolution, HostResolution):
            return []
        return list(resolution.hosts)

    @property
    def name(self) -> str:
        """Get the name of the capability.

        Returns:
            The capability name.
        """
        return "http_probe"
