"""Web crawling capability using Katana."""

from typing import Any, cast

from redforge.adapters.errors import AdapterError
from redforge.adapters.katana import (
    KatanaAdapter,
    WebCrawlAdapterResult,
    WebCrawler,
)
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

    def __init__(
        self,
        binary_path: str = "katana",
        *,
        crawler: WebCrawler | None = None,
    ) -> None:
        """Initialize the web crawl capability.

        Args:
            binary_path: Path to the Katana binary (default: "katana").
        """
        self._crawler = crawler or KatanaAdapter(binary_path=binary_path)

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
            response = cast(object, self._crawler.crawl(tuple(hosts)))
        except AdapterError:
            return Result(
                status=Status.FAILURE,
                data=[],
                errors=["Web crawler is unavailable or returned an invalid response"],
            )
        except Exception:
            return Result(
                status=Status.ERROR,
                data=[],
                errors=["Web crawler failed with an unexpected execution error"],
            )
        if not isinstance(response, WebCrawlAdapterResult):
            return Result(
                status=Status.ERROR,
                data=[],
                errors=["Web crawler returned an invalid result"],
            )
        response_endpoints = cast(object, response.endpoints)
        if not isinstance(response_endpoints, tuple) or not all(
            isinstance(item, Endpoint)
            for item in cast(tuple[object, ...], response_endpoints)
        ):
            return Result(
                status=Status.ERROR,
                data=[],
                errors=["Web crawler returned an invalid result"],
            )
        return Result(
            status=Status.SUCCESS,
            data=list(cast(tuple[Endpoint, ...], response_endpoints)),
        )

    def _get_hosts_from_state(self, state: dict[str, Any]) -> list[str]:  # type: ignore[reportUnknownParameterType]
        alive_hosts = state.get(self._ALIVE_HOSTS_STATE_KEY, [])
        if not isinstance(alive_hosts, (list, tuple)):
            return []

        # Convert Host objects to strings for Katana input
        from redforge.domain.host import Host

        host_strings: list[str] = []
        for host in cast(list[object] | tuple[object, ...], alive_hosts):
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
