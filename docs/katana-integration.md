# Katana Web Crawl Integration

Katana is a replaceable provider for the web-crawl capability.
It is not a capability identity and does not appear as a planner step.

```text
WEB_CRAWL Capability
        |
        v
WebCrawlProvider
        |
        v
KatanaWebCrawlProvider
        |
        v
ToolRunner
        |
        v
katana
```

The capability and tool identities remain separate:

```text
CapabilityId("web_crawl")
ToolId("katana")
```

Registry construction, imports, planning, and pipeline building perform no
availability check or process execution.

## Input and state contracts

The canonical dependency remains:

```text
ALIVE_HOSTS -> web_crawl -> ENDPOINTS
```

`WebCrawlCapability` passes an immutable `tuple[Host, ...]` to the provider.
Katana derives conservative HTTP and HTTPS root seeds from each normalized
hostname or IP identity. `HTTP_ENDPOINTS` may coexist in Context but is not a
required input and does not change planning.

`HTTP_ENDPOINTS` is responsive service evidence from probing. `ENDPOINTS` is
path and resource evidence from crawling. The contracts are not interchangeable.

## Tool definition and safe profile

`KATANA_TOOL` uses executable `katana`, version argument `("-version",)`, a
bounded default execution timeout, and deterministic `crawl`, `recon`, and
`web` tags. RedForge does not install, download, update, or version-probe the
binary automatically.

`KatanaConfig` exposes only bounded execution timeout, depth, crawl duration,
request timeout, concurrency, parallelism, rate, and response-read limits.
It has no arbitrary arguments, headers, cookies, credentials, proxy, config
path, output path, resume path, form filling, JavaScript crawling, screenshots,
or headless mode.

The deterministic invocation requests:

```text
-jsonl
-silent
-no-color
-disable-update-check
-omit-raw
-omit-body
-retry 0
-depth <bounded>
-crawl-duration <bounded>
-timeout <bounded>
-concurrency <bounded>
-parallelism <bounded>
-rate-limit <bounded>
-max-response-size <bounded>
-field-scope fqdn
```

Normalized unique seeds are delivered as bounded newline-delimited stdin.
There is no shell, temporary target file, inherited stdin, output file, config
file, or reconstructed command string.

## JSONL, URL normalization, and scope

The provider reads Katana's JSONL `request.endpoint` field. A top-level `url`
field remains accepted for migration compatibility. Unknown fields, including
raw requests and response objects, are ignored and never retained.

Only credential-free HTTP and HTTPS URLs are accepted. Schemes and hostnames
are normalized, IPv4 and IPv6 use canonical identities, default ports are
normalized, explicit non-default ports remain, empty paths become `/`, query
strings are bounded and preserved, and fragments are rejected. Query names
commonly used for credentials or session secrets are rejected.

Every finding is matched against the exact normalized hostname or IP identities
present in the input hosts. Scope does not use suffix matching, parent-domain
widening, or redirect-derived identities. For an approved
`api.example.com`, `api.example.com.attacker.test` and unrelated hosts are
rejected.

Crawler identity is `(scheme, hostname, port, path-with-query)`. The first
valid record wins, duplicates are counted, and final output is an immutable
deterministically ordered tuple. Response bodies, headers, cookies, raw JSON,
and process evidence are not published.

## Status mapping

```text
Tool SUCCESS + clean valid or empty parse -> Provider SUCCESS
Tool SUCCESS + usable findings and rejected/truncated records -> Provider PARTIAL
Tool SUCCESS + records but no approved endpoint -> Provider FAILURE
Tool FAILURE -> Provider FAILURE
Tool TIMEOUT with complete valid endpoints -> Provider PARTIAL
Tool TIMEOUT without endpoints -> Provider FAILURE
Tool NOT_FOUND -> Provider UNAVAILABLE
Tool ERROR -> Provider ERROR
```

An unterminated final line after timeout or truncation is discarded. Safe
diagnostics contain fixed messages and counts only; stdout, stderr, stdin,
argv, target lists, paths, environment values, and exceptions are excluded.

The capability maps usable partial results to `PARTIAL` and publishes
`ENDPOINTS`, allowing sequential execution to continue. Partial results without
endpoints become `FAILURE`. Failure and error publish nothing. Clean empty
output is `SUCCESS` with `ENDPOINTS = ()`. One provider invocation produces
one capability result and one execution-history entry.

## Downstream behavior and testing

Technology detection remains a separate capability consuming `ENDPOINTS`; its
planner dependency and adapter are unchanged. Tests use `FakeToolRunner`, fake
providers, and placeholder reserved targets, requiring no Katana binary,
network, credentials, local configuration, or elevated permissions.

Current limitations:

- crawling is synchronous and sequential;
- there are no dynamic retries, caching, resume, or replanning;
- `ALIVE_HOSTS` remains the canonical input instead of richer probe endpoints;
- output retention is bounded after process capture rather than streamed;
- technology detection remains a legacy direct-subprocess integration.
