# HTTPX Web Probe Integration

HTTPX is a replaceable provider for the HTTP-probe capability. It is not a
capability identity and does not appear as a planner step.

```text
HTTP_PROBE Capability
        |
        v
HttpProbeProvider
        |
        v
HttpxProbeProvider
        |
        v
ToolRunner
        |
        v
httpx
```

The planner retains the existing downstream graph while exposing probe
evidence as a second output:

```text
HOSTS -> http_probe --+--> ALIVE_HOSTS -> web_crawl -> ENDPOINTS
                      |
                      +--> HTTP_ENDPOINTS
ENDPOINTS -> technology_detection
```

HTTPX does not replace crawling or technology detection.

## Identity and composition

The capability identity remains `CapabilityId("http_probe")`; the executable
has the separate `ToolId("httpx")`. `HTTPX_TOOL` is immutable metadata with
executable `httpx`, version argument `("-version",)`, a bounded default
timeout, and deterministic tags. It contains no runner, capability, secret, or
mutable configuration.

The default tool registry contains both HTTPX and Subfinder definitions. The
default capability factory lazily creates a fresh `HttpxProbeProvider` and
injects either the configured `ToolRunner` or a local runner. Imports,
registry construction, planning, and pipeline building execute no process and
perform no availability or version check.

## Input and invocation

The provider accepts only immutable resolved `Host` values from
`PipelineStateKey.HOSTS`. Hostnames are normalized through the shared DNS
helper, IP addresses retain their canonical host-resolution representation,
and duplicate targets are removed and sorted. A host with a hostname is
probed by hostname; an IP-only host is probed by its canonical address.

Targets are encoded as bounded newline-delimited stdin. No temporary file,
parent stdin, or command string is used. The deterministic base argv is:

```text
httpx
  -json
  -silent
  -no-color
  -disable-update-check
  -status-code
  -content-type
  -title
  -web-server
  -ip
  -location
  -response-time
```

Configuration may add a request timeout, threads, rate limit, redirect
following, and all-IP probing in fixed order. Redirect following and all-IP
probing are disabled by default. When enabled, redirects are restricted to the
same host. Retries, technology detection, custom
methods, bodies, headers, cookies, authentication, proxies, paths, ports,
screenshots, unsafe requests, arbitrary arguments, file output, installation,
downloads, and update operations are not supported.

## JSONL and endpoint evidence

Each complete non-empty JSONL record is handled independently. The adapter
requires a supported `url` and integer HTTP `status_code`; unknown fields are
ignored. Optional bounded fields are canonical IP address, content type,
title, web-server value, redirect location, and response time.

No response body, raw headers, cookies, request dump, raw JSON, or unrestricted
metadata is retained. HTTP status values from 100 through 599 are response
evidence: 301, 401, 404, and 500 do not make tool or capability execution fail.

URLs accept only HTTP and HTTPS, reject credentials, fragments, whitespace,
control characters, invalid ports, malformed hostnames, and unsupported
schemes, and normalize IDNA and IPv4/IPv6 representation. Default ports are
omitted from canonical URLs; explicit non-default ports remain. Endpoint
identity is `(scheme, hostname, effective_port)`. The first valid record wins
when duplicate records disagree on optional metadata.

A cleanly exited process may emit a final complete JSON record without a
terminal newline. After timeout or truncation, an unterminated final line is
discarded as malformed.

## Scope and redirects

The approved scope is built only from the input hostnames and their resolved
addresses. A parsed endpoint is accepted only when its normalized URL hostname
matches one approved identity exactly. Suffix matching is never used, so an
input of `api.authorized.example` does not authorize `notauthorized.example` or
`api.authorized.example.attacker.test`.

Redirect following is disabled by default. A bounded relative or credential-
free HTTP(S) location may be retained as metadata, but it is never converted
into an approved endpoint and never expands input scope.

## Status and publication

```text
Tool SUCCESS, clean valid or empty parse -> Provider SUCCESS
Tool SUCCESS, usable findings plus rejected/truncated records -> Provider PARTIAL
Tool SUCCESS, records but no valid approved endpoint -> Provider FAILURE
Tool FAILURE -> Provider FAILURE
Tool TIMEOUT with valid complete findings -> Provider PARTIAL
Tool TIMEOUT without findings -> Provider FAILURE
Tool NOT_FOUND -> Provider UNAVAILABLE
Tool ERROR -> Provider ERROR
```

Diagnostics use fixed messages and safe counts. They never include stdout,
stderr, stdin, target lists, argv, PATH, executable paths, environment values,
or exception messages.

## HTTP Probe Evidence Publication

`HttpProbeCapability` normalizes the provider's typed endpoint tuple, rejects
conflicting duplicate identities, and derives alive hosts from that evidence.
It then emits one atomic publication batch:

```text
HttpProbeCapability
        |
        v
StatePublication
   |-- ALIVE_HOSTS
   `-- HTTP_ENDPOINTS
```

`HTTP_ENDPOINTS` contains responsive HTTP/HTTPS service evidence.

`ENDPOINTS` contains paths and resources discovered by web crawling.

They are separate state contracts.

A successful probe publishes immutable, deterministically ordered tuples for
both keys. A successful empty result publishes `()` for both. A usable
`PARTIAL` result also publishes both tuples and allows sequential execution to
continue; a provider `PARTIAL` with no endpoint evidence is mapped to
`FAILURE`. Provider failure, unavailability, error, invalid evidence, or
publication validation failure commits neither state.

One provider invocation produces one capability result, one atomic batch, and
one execution-history entry. Planning for `ALIVE_HOSTS`, `HTTP_ENDPOINTS`, or
both resolves to one `http_probe` step. State validation accepts only
`tuple[Host, ...]` for `ALIVE_HOSTS` and
`tuple[HttpProbeEndpoint, ...]` for `HTTP_ENDPOINTS`.

`web_crawl` consumes responsive hosts and remains the only default producer of
`ENDPOINTS`; technology detection remains a separate downstream capability.
An empty successful HTTP probe therefore flows through both stages as a
successful empty result.

## Testing and limitations

Unit and planned-execution tests use `FakeToolRunner`; they require no HTTPX
binary, network access, credentials, target files, shell, or local
configuration. Installing HTTPX and authorizing targets are deployment
responsibilities.

Current limitations:

- execution is synchronous and sequential, with no retry or dynamic
  replanning;
- output retention is bounded after process capture rather than streamed;
- version compatibility is not automatically probed;
- duplicate optional metadata uses first-valid-record semantics;
- Katana consumes `ALIVE_HOSTS` through the ToolRunner-backed web-crawl
  provider; a future input-contract milestone may choose to consume richer
  `HTTP_ENDPOINTS` evidence;
- technology detection uses the ToolRunner-backed WhatWeb provider;
- technology detection continues to consume crawler-produced `ENDPOINTS`.
