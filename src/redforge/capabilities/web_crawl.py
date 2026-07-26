"""Tool-agnostic web-crawl capability."""

from typing import Any, cast

from redforge.domain.endpoint import Endpoint
from redforge.domain.host import Host
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, StatePublication, Status
from redforge.sdk.web_crawl import (
    WebCrawlProvider,
    WebCrawlProviderResult,
    WebCrawlProviderStatus,
)


class _UnavailableWebCrawlProvider:
    """Safe default for manual capability construction."""

    def crawl(self, hosts: tuple[Host, ...]) -> WebCrawlProviderResult:
        del hosts
        return WebCrawlProviderResult(
            status=WebCrawlProviderStatus.UNAVAILABLE,
            message="Web crawl provider is unavailable.",
        )


def _endpoint_sort_key(endpoint: Endpoint) -> tuple[object, ...]:
    return (
        endpoint.protocol,
        endpoint.host,
        endpoint.port,
        endpoint.path or "/",
        endpoint.description or "",
    )


def _normalize_endpoints(
    endpoints: tuple[Endpoint, ...],
) -> tuple[Endpoint, ...]:
    normalized: dict[tuple[str, str, int, str], Endpoint] = {}
    for endpoint in endpoints:
        identity = (
            endpoint.protocol,
            endpoint.host,
            endpoint.port,
            endpoint.path or "/",
        )
        existing = normalized.get(identity)
        if existing is not None and existing != endpoint:
            raise ValueError("web crawl provider returned conflicting endpoints")
        normalized.setdefault(identity, endpoint)
    return tuple(sorted(normalized.values(), key=_endpoint_sort_key))


class WebCrawlCapability(Capability):
    """Discover application endpoints through an injected domain provider."""

    def __init__(
        self,
        *,
        provider: WebCrawlProvider | None = None,
        crawler: WebCrawlProvider | None = None,
    ) -> None:
        if provider is not None and crawler is not None:
            raise ValueError("use provider or crawler, not both")
        self._provider = provider or crawler or _UnavailableWebCrawlProvider()

    def execute(self, context: Context) -> Result[None]:
        """Crawl the current responsive-host state exactly once."""
        hosts = self._get_hosts_from_state(context.state)
        if not hosts:
            return self._publishable_result(
                status=Status.SUCCESS,
                endpoints=(),
                provider_status=WebCrawlProviderStatus.SUCCESS,
            )
        try:
            response = cast(object, self._provider.crawl(hosts))
        except Exception:
            return self._error_result(
                "Web crawl provider failed with an unexpected execution error"
            )
        if not isinstance(response, WebCrawlProviderResult):
            return self._error_result(
                "Web crawl provider returned an invalid result"
            )
        try:
            endpoints = _normalize_endpoints(response.endpoints)
        except (TypeError, ValueError):
            return self._error_result(
                "Web crawl provider returned invalid endpoint evidence"
            )
        if response.status is WebCrawlProviderStatus.SUCCESS:
            status = Status.SUCCESS
        elif response.status is WebCrawlProviderStatus.PARTIAL:
            status = Status.PARTIAL if endpoints else Status.FAILURE
        elif response.status is WebCrawlProviderStatus.FAILURE:
            status = Status.FAILURE
        else:
            status = Status.ERROR
        errors = (
            []
            if status is Status.SUCCESS
            else [
                response.message
                or (
                    "Web crawling completed with partial findings"
                    if status is Status.PARTIAL
                    else "Web crawling failed"
                )
            ]
        )
        publications = (
            (StatePublication(PipelineStateKey.ENDPOINTS, endpoints),)
            if status in {Status.SUCCESS, Status.PARTIAL}
            else ()
        )
        return Result(
            status=status,
            data=None,
            errors=errors,
            metadata={
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
        endpoints: tuple[Endpoint, ...],
        provider_status: WebCrawlProviderStatus,
    ) -> Result[None]:
        return Result(
            status=status,
            data=None,
            metadata={
                "endpoint_count": len(endpoints),
                "provider_status": provider_status.value,
                "malformed_record_count": 0,
                "out_of_scope_count": 0,
                "duplicate_count": 0,
                "truncated": False,
            },
            publications=(
                StatePublication(PipelineStateKey.ENDPOINTS, endpoints),
            ),
        )

    @staticmethod
    def _get_hosts_from_state(state: dict[str, Any]) -> tuple[Host, ...]:  # type: ignore[reportUnknownParameterType]
        value = state.get(PipelineStateKey.ALIVE_HOSTS)
        if not isinstance(value, (list, tuple)):
            return ()
        return tuple(
            item
            for item in cast(list[object] | tuple[object, ...], value)
            if isinstance(item, Host)
        )

    @staticmethod
    def _error_result(message: str) -> Result[None]:
        return Result(status=Status.ERROR, data=None, errors=[message])

    @property
    def name(self) -> str:
        """Return the stable capability identity."""
        return "web_crawl"
