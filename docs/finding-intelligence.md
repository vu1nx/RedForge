# Finding Intelligence Domain

The Finding Intelligence domain is RedForge's immutable, provider-neutral
representation of detected security conditions. Nuclei is one adapter that
maps into this domain; future OpenVAS, Nessus, Qualys, Burp, custom, manual,
imported, or AI-assisted producers use the same model.

This layer does not implement CVSS, EPSS, KEV, exploit intelligence, risk
scoring, knowledge-graph enrichment, remediation, persistence, cross-provider
correlation, canonical aggregation, or cross-scan merging.

## Identity and fingerprint

`FindingIdentity` contains only a normalized classification identifier, the
affected asset, and optional affected endpoint and technology identities.
Scanner names, source record IDs, evidence, severity, confidence, and quality
do not participate in identity.

`FindingFingerprint` is a lowercase SHA-256 digest over an explicitly ordered
JSON tuple of those canonical fields. It never hashes raw requests, responses,
headers, bodies, banners, screenshots, or scanner output.

## Context, evidence, and provenance

`FindingContext` identifies the affected asset and optional endpoint or
technology. `AffectedEndpoint` retains canonical scheme, hostname or IP, port,
and path.

`FindingEvidence` separately describes evidence kind, detection method,
categorical confidence, categorical quality, generic source provenance, and
one bounded sanitized summary. Evidence kinds cover HTTP, DNS, TLS, TCP,
screenshot, banner, header, certificate, and manual observations without
storing raw payloads.

`FindingMetadata` stores immutable tags, generic references, and an optional
source record ID as provenance only. References support CVE, CWE, GHSA, OSV,
vendor advisory, research article, and internal identifiers.

## Records and serialization

`FindingRecord` binds identity, its verified fingerprint, classification,
context, immutable evidence, metadata, and status. `FindingRecordCollection`
sorts by fingerprint, removes exact duplicates, and rejects conflicting records
that claim the same fingerprint. Cross-provider evidence merging is deferred
to a future milestone.

`serialize_finding_record()` explicitly serializes only sanitized domain
fields with deterministic ordering. It does not use generic object recursion,
`default=str`, or mutable metadata bags.

## Adapter boundary

The Nuclei adapter validates JSONL and translates supported records into this
domain. Nuclei template IDs are retained only as generic source provenance.
Template IDs, matcher names, scanner output, and scanner-specific hashes do not
define finding identity, and no Nuclei type exists in the domain package.
