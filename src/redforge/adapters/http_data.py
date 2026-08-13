"""Standard-library HTTPS transport for external intelligence providers."""

import ssl
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from redforge.sdk.http_data import (
    HttpDataResponse,
    HttpDataTransportError,
    HttpDataTransportFailure,
    HttpGetRequest,
)


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


class LocalHttpsDataTransport:
    """Execute HTTPS GETs with TLS verification, no proxies, and no redirects."""

    def __init__(self) -> None:
        context = ssl.create_default_context()
        self._opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=context),
            _RejectRedirects(),
        )

    def get(self, request: HttpGetRequest) -> HttpDataResponse:
        if not isinstance(cast(object, request), HttpGetRequest):
            raise TypeError("HTTP transport requires an HttpGetRequest")
        raw_request = Request(
            request.url,
            headers=dict(request.headers),
            method="GET",
        )
        try:
            response = self._opener.open(raw_request, timeout=request.timeout_seconds)
            try:
                status = int(response.status)
                body = response.read(request.max_response_bytes + 1)
            finally:
                response.close()
        except HTTPError as error:
            return HttpDataResponse(status_code=error.code)
        except TimeoutError:
            raise HttpDataTransportError(HttpDataTransportFailure.TIMEOUT) from None
        except URLError as error:
            failure = (
                HttpDataTransportFailure.TIMEOUT
                if isinstance(error.reason, TimeoutError)
                else HttpDataTransportFailure.UNAVAILABLE
            )
            raise HttpDataTransportError(failure) from None
        except OSError:
            raise HttpDataTransportError(HttpDataTransportFailure.UNAVAILABLE) from None
        except Exception:
            raise HttpDataTransportError(HttpDataTransportFailure.ERROR) from None
        if len(body) > request.max_response_bytes:
            raise HttpDataTransportError(HttpDataTransportFailure.RESPONSE_TOO_LARGE)
        return HttpDataResponse(status_code=status, body=body)


__all__ = ["LocalHttpsDataTransport"]
