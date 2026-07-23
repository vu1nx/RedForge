"""Web crawling capability using Katana."""

from typing import Any

from redforge.adapters.katana import KatanaAdapter, KatanaAdapterError
from redforge.domain.endpoint import Endpoint
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


class WebCrawlCapability(Capability):
    """Web crawling capability using ProjectDiscovery Katana.

    This capability crawls reachable hosts for endpoints using the Katana
    external tool through the adapter pattern.
    """

    _ALIVE_HOSTS_STATE_KEY = "alive_hosts"

    def __init__(self, binary_path: str = "katana") -> None:
        """Initialize the web crawl capability.

        Args:
            binary_path: Path to the Katana binary (default: "katana").
        """
        self._adapter = KatanaAdapter(binary_path=binary_path)

    def execute(self, context: Context) -> Result[list[Endpoint]]:
        """Execute web crawling against alive hosts from pipeline state.

        Args:
            context: Runtime context containing alive hosts in state.

        Returns:
            Result containing discovered endpoints or error information.
        """
        hosts = self._get_hosts_from_state(context.state)

        if not hosts:
            return Result(status=Status.SUCCESS, data=[])

        try:
            endpoints = self._adapter.crawl_hosts(hosts)
            return Result(status=Status.SUCCESS, data=endpoints)
        except KatanaAdapterError as e:
            return Result(status=Status.ERROR, data=[], errors=[str(e)])

    def _get_hosts_from_state(self, state: dict[str, Any]) -> list[str]:  # type: ignore[reportUnknownParameterType]
        alive_hosts = state.get(self._ALIVE_HOSTS_STATE_KEY, [])
        if not isinstance(alive_hosts, list):
            return []

        # Convert Host objects to strings for Katana input
        from redforge.domain.host import Host

        host_strings: list[str] = []
        for host in alive_hosts:  # type: ignore[reportUnknownVariableType]
            if isinstance(host, Host):
                if host.hostname:
                    host_strings.append(f"http://{host.hostname}")
                    host_strings.append(f"https://{host.hostname}")
                else:
                    host_strings.append(f"http://{host.address}")
                    host_strings.append(f"https://{host.address}")

        return host_strings

    @property
    def name(self) -> str:
        """Get the name of the capability.

        Returns:
            The capability name.
        """
        return "web_crawl"
