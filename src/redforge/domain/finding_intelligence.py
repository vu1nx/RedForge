"""Immutable provider-neutral finding intelligence domain."""

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_address
from typing import cast
from unicodedata import normalize

from redforge.domain.hostname import normalize_dns_hostname
from redforge.domain.http_probe import normalize_http_url

_MAX_IDENTIFIER = 256
_MAX_TITLE = 512
_MAX_SUMMARY = 512
_MAX_REFERENCE = 2048


def _text(value: object, *, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _slug(value: object, *, label: str) -> str:
    text = _text(value, label=label, maximum=_MAX_IDENTIFIER)
    slug = re.sub(r"[^a-z0-9]+", "_", normalize("NFKC", text).casefold()).strip("_")
    if not slug or len(slug) > _MAX_IDENTIFIER:
        raise ValueError(f"{label} is invalid")
    return slug


@dataclass(frozen=True, slots=True, repr=False)
class FindingIdentity:
    """Provider-neutral identity inputs for one affected subject and condition."""

    classification_id: str
    asset: "AffectedAsset"
    endpoint: "AffectedEndpoint | None" = None
    technology: "AffectedTechnology | None" = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "classification_id",
            _slug(self.classification_id, label="finding classification identity"),
        )
        if not isinstance(cast(object, self.asset), AffectedAsset):
            raise TypeError("finding identity asset is invalid")
        if self.endpoint is not None and not isinstance(
            cast(object, self.endpoint), AffectedEndpoint
        ):
            raise TypeError("finding identity endpoint is invalid")
        if self.technology is not None and not isinstance(
            cast(object, self.technology), AffectedTechnology
        ):
            raise TypeError("finding identity technology is invalid")

    def __repr__(self) -> str:
        return (
            "FindingIdentity("
            f"classification_id={self.classification_id!r}, "
            f"has_endpoint={self.endpoint is not None!r}, "
            f"has_technology={self.technology is not None!r})"
        )


@dataclass(frozen=True, slots=True, order=True)
class FindingFingerprint:
    """Deterministic digest of canonical provider-neutral identity fields."""

    value: str

    def __post_init__(self) -> None:
        value = _text(
            cast(object, self.value),
            label="finding fingerprint",
            maximum=64,
        )
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("finding fingerprint is invalid")

    @classmethod
    def from_identity(cls, identity: FindingIdentity) -> "FindingFingerprint":
        return finding_fingerprint(identity)

    def __str__(self) -> str:
        return self.value


class AssetIdentityKind(StrEnum):
    """Canonical affected-asset identity type."""

    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    LOGICAL = "logical"


@dataclass(frozen=True, slots=True, order=True, repr=False)
class AffectedAsset:
    """One canonical affected asset without provider ownership."""

    kind: AssetIdentityKind
    value: str

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.kind), AssetIdentityKind):
            raise TypeError("affected asset kind is invalid")
        value = _text(
            cast(object, self.value),
            label="affected asset identity",
            maximum=_MAX_IDENTIFIER,
        )
        if self.kind is AssetIdentityKind.HOSTNAME:
            value = normalize_dns_hostname(value)
        elif self.kind is AssetIdentityKind.IP_ADDRESS:
            value = str(ip_address(value))
        else:
            value = _slug(value, label="affected logical asset identity")
        object.__setattr__(self, "value", value)

    def __repr__(self) -> str:
        return f"AffectedAsset(kind={self.kind!r})"


@dataclass(frozen=True, slots=True, order=True, repr=False)
class AffectedEndpoint:
    """Canonical HTTP endpoint identity without request or response content."""

    scheme: str
    hostname: str
    port: int
    path: str = "/"

    def __post_init__(self) -> None:
        scheme = _text(
            cast(object, self.scheme),
            label="affected endpoint scheme",
            maximum=16,
        ).lower()
        path = _text(
            cast(object, self.path),
            label="affected endpoint path",
            maximum=2048,
        )
        if not path.startswith("/"):
            raise ValueError("affected endpoint path is invalid")
        try:
            normalized = normalize_http_url(
                f"{scheme}://{_authority(self.hostname, self.port)}{path}"
            )
        except (TypeError, ValueError):
            raise ValueError("affected endpoint is invalid") from None
        authority = _serialized_authority(
            normalized.hostname,
            normalized.port,
            normalized.scheme,
        )
        normalized_path = normalized.value.removeprefix(
            f"{normalized.scheme}://{authority}"
        ) or "/"
        object.__setattr__(self, "scheme", normalized.scheme)
        object.__setattr__(self, "hostname", normalized.hostname)
        object.__setattr__(self, "port", normalized.port)
        object.__setattr__(self, "path", normalized_path)

    @classmethod
    def from_url(cls, value: str) -> "AffectedEndpoint":
        normalized = normalize_http_url(value)
        prefix = f"{normalized.scheme}://{_serialized_authority(normalized.hostname, normalized.port, normalized.scheme)}"
        path = normalized.value.removeprefix(prefix) or "/"
        return cls(
            scheme=normalized.scheme,
            hostname=normalized.hostname,
            port=normalized.port,
            path=path,
        )

    @property
    def canonical_url(self) -> str:
        return (
            f"{self.scheme}://"
            f"{_serialized_authority(self.hostname, self.port, self.scheme)}"
            f"{self.path}"
        )

    def __repr__(self) -> str:
        return (
            "AffectedEndpoint("
            f"scheme={self.scheme!r}, "
            f"port={self.port!r}, "
            f"path_length={len(self.path)!r})"
        )


def _authority(hostname: object, port: object) -> str:
    host = _text(hostname, label="affected endpoint hostname", maximum=253)
    if (
        not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65_535
    ):
        raise ValueError("affected endpoint port is invalid")
    try:
        address = ip_address(host)
    except ValueError:
        serialized = normalize_dns_hostname(host)
    else:
        serialized = f"[{address}]" if address.version == 6 else str(address)
    return f"{serialized}:{port}"


def _serialized_authority(hostname: str, port: int, scheme: str) -> str:
    try:
        address = ip_address(hostname)
    except ValueError:
        serialized = hostname
    else:
        serialized = f"[{address}]" if address.version == 6 else str(address)
    default = 443 if scheme == "https" else 80
    return serialized if port == default else f"{serialized}:{port}"


@dataclass(frozen=True, slots=True, repr=False)
class AffectedTechnology:
    """Optional canonical technology subject for a finding."""

    name: str
    version: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "name",
            " ".join(
                normalize(
                    "NFKC",
                    _text(
                        cast(object, self.name),
                        label="affected technology name",
                        maximum=_MAX_IDENTIFIER,
                    ),
                )
                .casefold()
                .split()
            ),
        )
        if self.version is not None:
            object.__setattr__(
                self,
                "version",
                _text(
                    cast(object, self.version),
                    label="affected technology version",
                    maximum=_MAX_IDENTIFIER,
                ),
            )

    def __repr__(self) -> str:
        return (
            "AffectedTechnology("
            f"has_version={self.version is not None!r})"
        )


class DetectionMethod(StrEnum):
    ACTIVE = "active"
    PASSIVE = "passive"
    MANUAL = "manual"
    EXTERNAL = "external"
    CORRELATED = "correlated"


class EvidenceConfidence(StrEnum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CERTAIN = "certain"


class EvidenceQuality(StrEnum):
    UNKNOWN = "unknown"
    WEAK = "weak"
    NORMAL = "normal"
    STRONG = "strong"
    VERIFIED = "verified"


class EvidenceKind(StrEnum):
    HTTP = "http"
    DNS = "dns"
    TLS = "tls"
    TCP = "tcp"
    SCREENSHOT = "screenshot"
    BANNER = "banner"
    HEADER = "header"
    CERTIFICATE = "certificate"
    MANUAL = "manual"


class EvidenceSourceKind(StrEnum):
    TOOL = "tool"
    ANALYST = "analyst"
    IMPORT = "import"
    CORRELATION = "correlation"
    AI = "ai"


@dataclass(frozen=True, slots=True, order=True, repr=False)
class EvidenceSource:
    kind: EvidenceSourceKind
    name: str

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.kind), EvidenceSourceKind):
            raise TypeError("evidence source kind is invalid")
        object.__setattr__(
            self,
            "name",
            _slug(self.name, label="evidence source name"),
        )

    def __repr__(self) -> str:
        return f"EvidenceSource(kind={self.kind!r})"


@dataclass(frozen=True, slots=True, order=True, repr=False)
class EvidenceSummary:
    value: str

    def __post_init__(self) -> None:
        _text(
            cast(object, self.value),
            label="evidence summary",
            maximum=_MAX_SUMMARY,
        )

    def __repr__(self) -> str:
        return f"EvidenceSummary(length={len(self.value)!r})"


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class FindingStatus(StrEnum):
    DETECTED = "detected"


@dataclass(frozen=True, slots=True, order=True, repr=False)
class FindingTag:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _slug(self.value, label="finding tag"))

    def __repr__(self) -> str:
        return f"FindingTag(length={len(self.value)!r})"


class FindingReferenceKind(StrEnum):
    CVE = "cve"
    CWE = "cwe"
    GHSA = "ghsa"
    OSV = "osv"
    VENDOR_ADVISORY = "vendor_advisory"
    RESEARCH_ARTICLE = "research_article"
    INTERNAL = "internal"


@dataclass(frozen=True, slots=True, order=True, repr=False)
class FindingReference:
    kind: FindingReferenceKind
    value: str

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.kind), FindingReferenceKind):
            raise TypeError("finding reference kind is invalid")
        value = _text(
            cast(object, self.value),
            label="finding reference",
            maximum=_MAX_REFERENCE,
        )
        _validate_reference(self.kind, value)
        if self.kind in {
            FindingReferenceKind.CVE,
            FindingReferenceKind.CWE,
            FindingReferenceKind.GHSA,
        }:
            value = value.upper()
        elif self.kind in {
            FindingReferenceKind.VENDOR_ADVISORY,
            FindingReferenceKind.RESEARCH_ARTICLE,
        }:
            value = normalize_http_url(value).value
        object.__setattr__(self, "value", value)

    def __repr__(self) -> str:
        return f"FindingReference(kind={self.kind!r})"


def _validate_reference(kind: FindingReferenceKind, value: str) -> None:
    patterns = {
        FindingReferenceKind.CVE: r"CVE-[0-9]{4}-[0-9]{4,}",
        FindingReferenceKind.CWE: r"CWE-[0-9]+",
        FindingReferenceKind.GHSA: r"GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}",
    }
    pattern = patterns.get(kind)
    if pattern is not None and re.fullmatch(pattern, value.upper()) is None:
        raise ValueError("finding reference is invalid")
    if kind in {
        FindingReferenceKind.VENDOR_ADVISORY,
        FindingReferenceKind.RESEARCH_ARTICLE,
    }:
        normalized = normalize_http_url(value)
        if normalized.scheme != "https":
            raise ValueError("finding reference is invalid")


@dataclass(frozen=True, slots=True, repr=False)
class FindingClassification:
    identifier: str
    title: str
    severity: FindingSeverity = FindingSeverity.UNKNOWN

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "identifier",
            _slug(self.identifier, label="finding classification identifier"),
        )
        object.__setattr__(
            self,
            "title",
            _text(
                cast(object, self.title),
                label="finding classification title",
                maximum=_MAX_TITLE,
            ),
        )
        if not isinstance(cast(object, self.severity), FindingSeverity):
            raise TypeError("finding severity is invalid")

    @classmethod
    def from_title(
        cls,
        title: str,
        *,
        severity: FindingSeverity = FindingSeverity.UNKNOWN,
    ) -> "FindingClassification":
        return cls(_slug(title, label="finding classification title"), title, severity)

    def __repr__(self) -> str:
        return (
            "FindingClassification("
            f"identifier={self.identifier!r}, severity={self.severity!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class FindingMetadata:
    source: EvidenceSource
    source_record_id: str | None = None
    tags: tuple[FindingTag, ...] = ()
    references: tuple[FindingReference, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.source), EvidenceSource):
            raise TypeError("finding metadata source is invalid")
        if self.source_record_id is not None:
            _text(
                cast(object, self.source_record_id),
                label="source record identity",
                maximum=_MAX_IDENTIFIER,
            )
        object.__setattr__(self, "tags", _typed_tuple(self.tags, FindingTag, "tags"))
        object.__setattr__(
            self,
            "references",
            _typed_tuple(self.references, FindingReference, "references"),
        )

    def __repr__(self) -> str:
        return (
            "FindingMetadata("
            f"source={self.source!r}, "
            f"has_source_record_id={self.source_record_id is not None!r}, "
            f"tag_count={len(self.tags)!r}, "
            f"reference_count={len(self.references)!r})"
        )


def _typed_tuple[T](
    value: object,
    item_type: type[T],
    label: str,
) -> tuple[T, ...]:
    if not isinstance(value, tuple) or not all(
        isinstance(item, item_type) for item in cast(tuple[object, ...], value)
    ):
        raise TypeError(f"finding {label} must be an immutable tuple")
    typed = cast(tuple[T, ...], value)
    return tuple(sorted(set(typed), key=_domain_sort_key))


def _domain_sort_key(value: object) -> tuple[str, ...]:
    if isinstance(value, FindingTag):
        return ("tag", value.value)
    if isinstance(value, FindingReference):
        return ("reference", value.kind.value, value.value)
    if isinstance(value, FindingEvidence):
        return (
            "evidence",
            value.kind.value,
            value.method.value,
            value.confidence.value,
            value.quality.value,
            value.source.kind.value,
            value.source.name,
            value.summary.value,
        )
    raise TypeError("finding collection item is invalid")


@dataclass(frozen=True, slots=True, repr=False)
class FindingContext:
    asset: AffectedAsset
    endpoint: AffectedEndpoint | None = None
    technology: AffectedTechnology | None = None

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.asset), AffectedAsset):
            raise TypeError("finding context asset is invalid")
        if self.endpoint is not None and not isinstance(
            cast(object, self.endpoint), AffectedEndpoint
        ):
            raise TypeError("finding context endpoint is invalid")
        if self.technology is not None and not isinstance(
            cast(object, self.technology), AffectedTechnology
        ):
            raise TypeError("finding context technology is invalid")

    @property
    def identity(self) -> tuple[AffectedAsset, AffectedEndpoint | None, AffectedTechnology | None]:
        return self.asset, self.endpoint, self.technology

    def __repr__(self) -> str:
        return (
            "FindingContext("
            f"asset_kind={self.asset.kind!r}, "
            f"has_endpoint={self.endpoint is not None!r}, "
            f"has_technology={self.technology is not None!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class FindingEvidence:
    kind: EvidenceKind
    method: DetectionMethod
    confidence: EvidenceConfidence
    quality: EvidenceQuality
    source: EvidenceSource
    summary: EvidenceSummary

    def __post_init__(self) -> None:
        for value, expected, label in (
            (self.kind, EvidenceKind, "kind"),
            (self.method, DetectionMethod, "method"),
            (self.confidence, EvidenceConfidence, "confidence"),
            (self.quality, EvidenceQuality, "quality"),
            (self.source, EvidenceSource, "source"),
            (self.summary, EvidenceSummary, "summary"),
        ):
            if not isinstance(cast(object, value), expected):
                raise TypeError(f"finding evidence {label} is invalid")

    def __repr__(self) -> str:
        return (
            "FindingEvidence("
            f"kind={self.kind!r}, method={self.method!r}, "
            f"confidence={self.confidence!r}, quality={self.quality!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class FindingRecord:
    identity: FindingIdentity
    fingerprint: FindingFingerprint
    classification: FindingClassification
    context: FindingContext
    evidence: tuple[FindingEvidence, ...]
    metadata: FindingMetadata
    status: FindingStatus = FindingStatus.DETECTED

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.identity), FindingIdentity):
            raise TypeError("finding record identity is invalid")
        if not isinstance(cast(object, self.fingerprint), FindingFingerprint):
            raise TypeError("finding record fingerprint is invalid")
        if self.fingerprint != finding_fingerprint(self.identity):
            raise ValueError("finding fingerprint does not match identity")
        if not isinstance(cast(object, self.classification), FindingClassification):
            raise TypeError("finding classification is invalid")
        if self.classification.identifier != self.identity.classification_id:
            raise ValueError("finding classification does not match identity")
        if not isinstance(cast(object, self.context), FindingContext):
            raise TypeError("finding context is invalid")
        if self.context.identity != (
            self.identity.asset,
            self.identity.endpoint,
            self.identity.technology,
        ):
            raise ValueError("finding context does not match identity")
        object.__setattr__(
            self,
            "evidence",
            _typed_tuple(self.evidence, FindingEvidence, "evidence"),
        )
        if not self.evidence:
            raise ValueError("finding record requires evidence")
        if not isinstance(cast(object, self.metadata), FindingMetadata):
            raise TypeError("finding metadata is invalid")
        if not isinstance(cast(object, self.status), FindingStatus):
            raise TypeError("finding status is invalid")

    def __repr__(self) -> str:
        return (
            "FindingRecord("
            f"fingerprint={self.fingerprint!r}, "
            f"severity={self.classification.severity!r}, "
            f"status={self.status!r}, evidence_count={len(self.evidence)!r})"
        )


@dataclass(frozen=True, slots=True)
class FindingRecordCollection:
    records: tuple[FindingRecord, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.records), tuple) or not all(
            isinstance(item, FindingRecord)
            for item in cast(tuple[object, ...], self.records)
        ):
            raise TypeError("finding records must be an immutable tuple")
        by_fingerprint: dict[FindingFingerprint, FindingRecord] = {}
        for record in self.records:
            existing = by_fingerprint.get(record.fingerprint)
            if existing is not None and existing != record:
                raise ValueError("finding fingerprint records conflict")
            by_fingerprint.setdefault(record.fingerprint, record)
        object.__setattr__(
            self,
            "records",
            tuple(
                by_fingerprint[key]
                for key in sorted(by_fingerprint)
            ),
        )

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self):
        return iter(self.records)


def finding_fingerprint(identity: FindingIdentity) -> FindingFingerprint:
    if not isinstance(cast(object, identity), FindingIdentity):
        raise TypeError("finding fingerprint requires a FindingIdentity")
    endpoint = identity.endpoint
    technology = identity.technology
    payload = (
        identity.classification_id,
        identity.asset.kind.value,
        identity.asset.value,
        endpoint.scheme if endpoint is not None else "",
        endpoint.hostname if endpoint is not None else "",
        str(endpoint.port) if endpoint is not None else "",
        endpoint.path if endpoint is not None else "",
        technology.name if technology is not None else "",
        technology.version if technology is not None and technology.version else "",
    )
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return FindingFingerprint(hashlib.sha256(encoded).hexdigest())


def serialize_finding_record(record: FindingRecord) -> str:
    """Serialize only explicit sanitized domain fields deterministically."""
    if not isinstance(cast(object, record), FindingRecord):
        raise TypeError("finding serialization requires a FindingRecord")
    endpoint = record.context.endpoint
    technology = record.context.technology
    payload = {
        "classification": {
            "id": record.classification.identifier,
            "severity": record.classification.severity.value,
            "title": record.classification.title,
        },
        "context": {
            "asset_kind": record.context.asset.kind.value,
            "asset_value": record.context.asset.value,
            "endpoint": endpoint.canonical_url if endpoint is not None else None,
            "technology_name": technology.name if technology is not None else None,
            "technology_version": (
                technology.version if technology is not None else None
            ),
        },
        "evidence": [
            {
                "confidence": item.confidence.value,
                "kind": item.kind.value,
                "method": item.method.value,
                "quality": item.quality.value,
                "source_kind": item.source.kind.value,
                "source_name": item.source.name,
                "summary": item.summary.value,
            }
            for item in record.evidence
        ],
        "fingerprint": record.fingerprint.value,
        "references": [
            {"kind": item.kind.value, "value": item.value}
            for item in record.metadata.references
        ],
        "source_record_id": record.metadata.source_record_id,
        "status": record.status.value,
        "tags": [item.value for item in record.metadata.tags],
    }
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
