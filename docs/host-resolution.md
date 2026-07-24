# Host Resolution

TASK-0017 introduces the explicit boundary between discovered names and network
probing:

```text
discovered hostname strings -> Host Resolution -> resolved Host objects -> HTTP probe
```

DNS resolution records network identity evidence. It does not prove that a host
is alive, reachable, externally exposed, or serving HTTP.

## Input and normalization

`HostResolutionCapability` consumes the existing subdomain-discovery mapping
from `PipelineStateKey.SUBDOMAINS`. The mapping's `subdomains` value must be a
list. A missing state key returns `FAILURE`, an invalid state shape returns
`ERROR`, and a legitimate empty list returns an empty `SUCCESS`.

Before resolution, each string is stripped, lowercased, has one trailing dot
removed, and is encoded label-by-label with IDNA. URLs, paths, query strings,
fragments, embedded ports, empty labels, invalid IDNA, oversized labels, and
oversized full names are rejected. Names that normalize identically are
resolved once.

## Resolver and output

The capability depends on the minimal `HostResolver` protocol and shared
sanitized adapter-error contract. The production
`StandardHostResolver` uses standard-library address resolution and returns
canonical, deduplicated IPv4 and IPv6 strings. It performs no HTTP requests,
reverse DNS, retries, or reachability checks.

`HostResolution` is an immutable tuple of `Host` values sorted by normalized
hostname. Each hostname produces at most one Host containing every valid unique
address. Addresses sort IPv4 before IPv6 and then by canonical value. IPv6 uses
compressed representation. Evidence contains only deterministic normalized
hostname and canonical-address values.

## Status and diagnostics

- all names resolved: `SUCCESS`;
- some usable hosts plus invalid, unresolved, or malformed data: `PARTIAL`;
- no supplied name resolved: `FAILURE`;
- unexpected resolver exception or invalid resolver response: `ERROR`.

Expected diagnostics mention only the normalized hostname or input index.
Unexpected failures use a stable sanitized message without raw exception text,
tracebacks, paths, secrets, or resolver internals.

The runtime publishes `SUCCESS` and `PARTIAL` output under
`PipelineStateKey.HOSTS`. HTTP probing consumes only this resolved read model
and submits the hostname, preserving application-layer Host and TLS SNI
semantics. Discovered strings cannot bypass Host Resolution.

## Limitations

There are no retries, timeout management, custom nameserver selection, DNSSEC
validation, TTL persistence, reverse DNS, CNAME-chain modeling, historical
resolution, caching, or active reachability claims.
