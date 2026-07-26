"""Validated HTTP endpoint evidence produced by web-service probes."""

import math
import re
from dataclasses import dataclass
from ipaddress import IPv6Address, ip_address
from typing import cast

from redforge.domain.hostname import normalize_dns_hostname

_HTTP_URL_PATTERN = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://"
    r"(?P<authority>[^/?#]*)(?P<suffix>[^#]*)$"
)


@dataclass(frozen=True, slots=True)
class NormalizedHttpUrl:
    """Canonical components of one supported HTTP or HTTPS URL."""

    value: str
    scheme: str
    hostname: str
    port: int


def normalize_http_url(value: str) -> NormalizedHttpUrl:
    """Return a canonical credential-free HTTP(S) URL."""
    if (
        not isinstance(cast(object, value), str)
        or not value
        or value != value.strip()
        or any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            for character in value
        )
    ):
        raise ValueError("invalid HTTP URL")
    match = _HTTP_URL_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError("invalid HTTP URL")
    scheme = match.group("scheme").lower()
    authority = match.group("authority")
    if scheme not in {"http", "https"} or not authority or "@" in authority:
        raise ValueError("invalid HTTP URL")
    hostname_value, port = _split_authority(authority)
    hostname = _normalize_url_host(hostname_value)
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    if not 1 <= effective_port <= 65535:
        raise ValueError("invalid HTTP URL")

    serialized_host = hostname
    try:
        address = ip_address(hostname)
    except ValueError:
        pass
    else:
        if isinstance(address, IPv6Address):
            serialized_host = f"[{address}]"
    netloc = (
        serialized_host
        if effective_port == (443 if scheme == "https" else 80)
        else f"{serialized_host}:{effective_port}"
    )
    canonical = f"{scheme}://{netloc}{match.group('suffix')}"
    return NormalizedHttpUrl(
        value=canonical,
        scheme=scheme,
        hostname=hostname,
        port=effective_port,
    )


def _normalize_url_host(value: str) -> str:
    if "%" in value:
        raise ValueError("invalid HTTP URL")
    try:
        return str(ip_address(value))
    except ValueError:
        return normalize_dns_hostname(value)


def _split_authority(authority: str) -> tuple[str, int | None]:
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            raise ValueError("invalid HTTP URL")
        hostname = authority[1:closing]
        remainder = authority[closing + 1 :]
        if not remainder:
            return hostname, None
        if not remainder.startswith(":"):
            raise ValueError("invalid HTTP URL")
        port_text = remainder[1:]
    else:
        if authority.count(":") > 1:
            raise ValueError("invalid HTTP URL")
        if ":" not in authority:
            return authority, None
        hostname, port_text = authority.rsplit(":", 1)
    if (
        not port_text
        or not port_text.isascii()
        or not port_text.isdigit()
    ):
        raise ValueError("invalid HTTP URL")
    return hostname, int(port_text)


def _optional_text(
    value: str | None,
    *,
    label: str,
    maximum_length: int,
) -> str | None:
    if value is None:
        return None
    if not isinstance(cast(object, value), str):
        raise TypeError(f"HTTP endpoint {label} must be text or None")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum_length
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in normalized
        )
    ):
        raise ValueError(f"HTTP endpoint {label} is invalid")
    return normalized


@dataclass(frozen=True, slots=True)
class HttpProbeEndpoint:
    """Minimal immutable HTTP response metadata retained from a probe."""

    url: str
    scheme: str
    hostname: str
    port: int
    status_code: int
    ip_address: str | None = None
    content_type: str | None = None
    title: str | None = None
    web_server: str | None = None
    redirect_location: str | None = None
    response_time_seconds: float | None = None

    def __post_init__(self) -> None:
        normalized = normalize_http_url(self.url)
        if (
            self.scheme != normalized.scheme
            or self.hostname != normalized.hostname
            or self.port != normalized.port
        ):
            raise ValueError("HTTP endpoint URL components do not match")
        if (
            not isinstance(cast(object, self.status_code), int)
            or isinstance(cast(object, self.status_code), bool)
            or not 100 <= self.status_code <= 599
        ):
            raise ValueError("HTTP endpoint status code is invalid")
        if self.ip_address is not None:
            if not isinstance(cast(object, self.ip_address), str):
                raise TypeError("HTTP endpoint IP address must be text or None")
            object.__setattr__(
                self,
                "ip_address",
                str(ip_address(self.ip_address)),
            )
        for field_name, label, maximum in (
            ("content_type", "content type", 256),
            ("title", "title", 512),
            ("web_server", "web server", 256),
            ("redirect_location", "redirect location", 2048),
        ):
            object.__setattr__(
                self,
                field_name,
                _optional_text(
                    cast(str | None, getattr(self, field_name)),
                    label=label,
                    maximum_length=maximum,
                ),
            )
        duration = cast(object, self.response_time_seconds)
        if duration is not None and (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(duration)
            or duration < 0
        ):
            raise ValueError("HTTP endpoint response time is invalid")
        if duration is not None:
            object.__setattr__(self, "response_time_seconds", float(duration))
