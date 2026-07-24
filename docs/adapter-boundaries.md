# Adapter Boundaries

TASK-0018 standardizes how RedForge crosses external-system boundaries.

```text
Capability -> Port -> Adapter -> External System
External Response -> Adapter Translation -> Typed Result -> Capability
```

Dependency direction is inward: domain models contain deterministic security
knowledge; capabilities orchestrate domain behavior; small typed ports describe
external responsibilities; concrete adapters own subprocess, socket, HTTP, and
provider details.

## Responsibilities

Ports are focused protocols for vulnerability lookup, HTTP probing, subdomain
discovery, technology detection, web crawling, and host resolution. Their
responses are immutable, slotted, deterministic models or typed tuples.
Arbitrary provider dictionaries, HTTP response objects, subprocess results, and
operating-system resolver tuples are not capability contracts.

Concrete adapters own request and command construction, authentication,
pagination, provider JSON parsing, CVSS selection, external status handling,
address canonicalization, and translation into typed results. Capabilities own
input selection, conservative correlation, deterministic domain output,
metadata, and RedForge status semantics.

Every affected capability accepts its port through construction. Production
adapters remain defaults; unit tests use deterministic fakes and perform no
network activity.

## Errors and statuses

Expected adapter failures use the shared hierarchy:

- `AdapterUnavailableError` for an external system that cannot be used;
- `AdapterResponseError` for malformed or unsupported external responses;
- `AdapterConfigurationError` for invalid or incomplete configuration.

Legacy adapter-specific exception names remain compatible subclasses. Messages
are sanitized: raw response bodies, stderr, credentials, configured paths,
tracebacks, and raw transport exception messages do not cross the boundary.

Single-operation expected failures normally become capability `FAILURE`.
Item-oriented operations retain successful items and return `PARTIAL`; if every
requested item fails, they return `FAILURE`. Unexpected defects and invalid
typed adapter returns become sanitized `ERROR`. The pipeline publishes only
`SUCCESS` and `PARTIAL` data under the execution contract.

## Provider notes

NVD owns HTTP construction, API-key headers, bounded pagination, JSON parsing,
CPE DTO construction, CVSS metric selection, and severity translation.
Vulnerability Intelligence receives typed CPE candidates and vulnerability
records and retains conservative exact product/version matching.

The ProjectDiscovery and WhatWeb adapters translate subprocess output into
typed host, endpoint, technology, or discovered-name results. Host Resolution
continues to canonicalize IPv4/IPv6 addresses without making reachability
claims.

Retries remain provider-local where already implemented. There is no plugin
registry, global retry or timeout framework, circuit breaker, caching,
telemetry backend, or dependency-injection container.
