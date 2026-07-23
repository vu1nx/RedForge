"""HTTP probing capability using httpx."""

from typing import Any, cast

from redforge.adapters.httpx import HttpxAdapter, HttpxAdapterError
from redforge.domain.host import Host
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


class HttpProbeCapability(Capability):
    """HTTP probing capability using ProjectDiscovery httpx.

    This capability probes discovered hosts for reachable HTTP/HTTPS services
    using the httpx external tool through the adapter pattern.
    """

    _HOSTS_STATE_KEY = "hosts"

    def __init__(self, binary_path: str = "httpx") -> None:
        """Initialize the HTTP probe capability.

        Args:
            binary_path: Path to the httpx binary (default: "httpx").
        """
        self._adapter = HttpxAdapter(binary_path=binary_path)

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
            alive_hosts = self._adapter.probe_hosts(hosts)
            return Result(status=Status.SUCCESS, data=alive_hosts)
        except HttpxAdapterError as e:
            return Result(status=Status.ERROR, data=[], errors=[str(e)])

    def _get_hosts_from_state(self, state: dict[str, Any]) -> list[Host]:  # type: ignore[reportUnknownParameterType]
        hosts = state.get(self._HOSTS_STATE_KEY, [])
        if not isinstance(hosts, list):
            return []
        return cast(list[Host], hosts)

    @property
    def name(self) -> str:
        """Get the name of the capability.

        Returns:
            The capability name.
        """
        return "http_probe"
