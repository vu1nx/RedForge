# WhatWeb Technology Detection Integration

WhatWeb is a replaceable provider for the technology-detection capability.
It is not a capability identity and does not appear as a planner step.

```text
TECHNOLOGY_DETECTION Capability
        |
        v
TechnologyDetectionProvider
        |
        v
WhatWebTechnologyDetectionProvider
        |
        v
ToolRunner
        |
        v
whatweb
```

The identities remain separate:

```text
CapabilityId("technology_detection")
ToolId("whatweb")
```

Imports, tool-registry construction, planning, and pipeline building do not
check executable availability, probe a version, or start a process.

## State and provider contracts

The canonical dependency remains:

```text
ENDPOINTS -> technology_detection -> TECHNOLOGIES
```

`HTTP_ENDPOINTS` does not alter this dependency and is not used as fallback
input. `TechnologyDetectionCapability` passes an immutable
`tuple[Endpoint, ...]` to the SDK-owned provider port. It builds no argv,
parses no external output, and imports neither WhatWeb nor `ToolRunner`.

Complete and usable partial results publish one immutable provider-neutral
`Technology` tuple through the existing atomic state-publication contract.
Clean empty output and empty input publish `TECHNOLOGIES = ()`. Empty input
does not invoke the provider. Failure, unavailable execution, and operational
error publish nothing. One capability execution produces one history entry.

## Definition and conservative configuration

`WHATWEB_TOOL` uses `ToolId("whatweb")`, executable `whatweb`, version argument
`("--version",)`, a 120-second default execution timeout, and deterministic
`fingerprint`, `technology`, and `web` tags. RedForge does not install,
download, update, or version-probe WhatWeb automatically.

`WhatWebConfig` is frozen and slotted. It exposes only bounded overall,
connection, and read timeouts; thread, target, input, output, and record
limits. It has no arbitrary arguments, credentials, headers, cookies, proxy,
config path, plugin path, output path, aggression selector, or update option.
The invocation fixes aggression at the least aggressive supported level,
disables redirects, color, error output, and cookie handling, and uses a
bounded thread count.

## Targets and invocation

Only normalized HTTP and HTTPS crawler endpoints are accepted. DNS and IDNA
names, IPv4, IPv6, default ports, explicit ports, paths, and queries use the
same canonical HTTP URL rules as other RedForge adapters. Credentials,
fragments, whitespace, control characters, unsupported schemes, invalid
ports, relative paths, excessive target counts, and excessive serialized
input are rejected before execution.

Duplicate targets are removed and the remaining canonical URLs are sorted.
Each target occupies one argv element in one batch invocation. No shell,
command string, stdin target stream, config file, plugin path, authentication,
proxy, caller-selected output path, retry, or second invocation exists.

WhatWeb's official CLI exposes JSON only through `--log-json=FILE`. The adapter
therefore owns one private temporary result file and removes it immediately
after parsing. This is the sole tool-specific file boundary; `ToolRunner`
still owns executable resolution, environment isolation, timeout enforcement,
and process execution. Tests supply JSON through `FakeToolRunner` and create
no file.

## Parsing, association, and evidence

The adapter parses WhatWeb's JSON array, ignores unknown fields, and retains
only the fields used by the existing `Technology` domain model. Technology
names, versions, confidence, categories, and selected bounded evidence strings
are validated. Raw JSON, HTML, headers, cookies, request configuration,
stdout, stderr, argv, environment, executable paths, and output paths are not
published.

WhatWeb 0.6.4 serializes plugin versions using their native JSON scalar type.
RedForge accepts bounded string, integer, and finite floating-point version
values and normalizes numeric versions to strings in the provider-neutral
`Technology` model using Python's locale-independent, deterministic scalar
representation. Booleans, non-finite numbers, mappings, nested collections,
control characters, and oversized values remain rejected. Other plugin
evidence remains string-only and bounded.

Every record target must equal one canonical requested endpoint URL. There is
no hostname-only fallback, suffix matching, parent-domain widening, redirect
association, or acceptance of unrequested paths. The same technology on
different endpoints remains distinct evidence.

Duplicate `Technology` values are removed using existing domain equality.
First valid evidence wins, and the final immutable tuple is sorted by source,
technology identity, version, evidence, and confidence.

## Outcome mapping

```text
Tool SUCCESS + clean parse -> Provider SUCCESS
Tool SUCCESS + usable rejected/truncated records -> Provider PARTIAL
Tool SUCCESS + clean empty output -> Provider SUCCESS with ()
Tool SUCCESS + records but no approved evidence -> Provider FAILURE
Tool FAILURE -> Provider FAILURE
Tool TIMEOUT with complete valid evidence -> Provider PARTIAL
Tool TIMEOUT without evidence -> Provider FAILURE
Tool NOT_FOUND -> Provider UNAVAILABLE
Tool ERROR -> Provider ERROR
```

Diagnostics are fixed or count-only and never include target URLs, technology
payloads, JSON, stdout, stderr, argv, environment, local paths, or credentials.
There is no retry or second invocation after timeout.

Usable partial provider results also carry an immutable, typed, deterministic
tuple of safe reason codes: `execution_timeout`,
`malformed_records_skipped`, `unassociated_records_skipped`, and
`output_truncated`. Only applicable codes are present. The capability copies
their typed values into result metadata so execution history can explain a
PARTIAL status without retaining endpoints, technology names, process output,
temporary paths, or exception text.

The capability retains these as typed SDK values in its allowlisted
`partial_reasons` metadata entry. Runtime terminal-event emission recognizes
only that exact typed contract and exposes it through the closed diagnostic
field model. Arbitrary strings or other result metadata are ignored. The
logging adapter renders approved values as a deterministic JSON string array;
human summaries and the final scan JSON schema remain unchanged.

Controlled Kali revalidation with the typed diagnostic contract identified
`malformed_records_skipped`. Usable technology evidence was published and the
runtime remained honestly `PARTIAL`; parser strictness was not weakened to
force `SUCCESS`. No raw malformed record crossed the adapter or observability
boundary. See
[Kali Reconnaissance Smoke Validation](kali-smoke-validation.md).

Provider `SUCCESS` maps to capability `SUCCESS`. `PARTIAL` with evidence maps
to capability `PARTIAL` and publishes; `PARTIAL` without evidence and provider
`FAILURE` map to capability `FAILURE`. `UNAVAILABLE` and `ERROR` map to
capability `ERROR`.

## Testing, downstream behavior, and limitations

Unit and planned-execution tests use `FakeToolRunner`, fake providers, and
reserved placeholder endpoints. They require no WhatWeb binary, network,
credentials, local configuration, elevated permissions, or platform shell.
The planned graph and execution history remain:

```text
subdomain_discovery
  -> host_resolution
  -> http_probe
  -> web_crawl
  -> technology_detection
```

Asset Intelligence consumes the unchanged `TECHNOLOGIES` state, and
Vulnerability Intelligence, Knowledge Graph, and Risk Intelligence retain
their existing evidence, matching, and scoring semantics.

Current limitations:

- WhatWeb requires a private temporary file for machine-readable JSON;
- execution is synchronous and sequential;
- output retention is bounded after WhatWeb writes the JSON file;
- there are no retries, caching, resume, fallback providers, or dynamic
  replanning;
- category inference and retained evidence fields preserve the existing
  conservative RedForge mapping rather than exposing the full WhatWeb record.
