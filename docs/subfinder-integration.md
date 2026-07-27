# Subfinder Passive Recon Integration

Subfinder is a replaceable provider for the subdomain-discovery capability. It
is not a capability identity and does not appear as a planner step.

```text
SUBDOMAIN_DISCOVERY Capability
            |
            v
SubdomainDiscoveryProvider
            |
            v
SubfinderSubdomainProvider
            |
            v
ToolRunner
            |
            v
subfinder
```

The capability remains `CapabilityId("subdomain_discovery")`; the executable
uses the separate `ToolId("subfinder")`. Capability Registry v2 contains the
domain contract, while the tool registry contains immutable executable
metadata. Neither registry owns runtime instances.

## Passive invocation

The default provider executes one target per invocation using literal argv:

```text
subfinder -d <normalized-domain> -json -silent -disable-update-check
```

Configuration may add, in deterministic order, `-max-time`, `-rl`,
`-recursive`, `-all`, `-s`, and `-es`. Source names are conservatively
validated and sorted. Explicit sources cannot overlap exclusions, and `-all`
cannot be combined with an explicit include list. Arbitrary arguments, shell
fragments, active enumeration, resolver settings, file output, and provider
configuration paths are not accepted.

`-disable-update-check` prevents update prompts or mutation during machine
execution. The adapter never installs, downloads, updates, or probes the
Subfinder executable during import, registry construction, or planning.

## Input, JSONL, and normalization

Targets are normalized as DNS hostnames before the runner is called. The
boundary rejects schemes, paths, ports, queries, fragments, wildcards,
whitespace, control characters, IP addresses, malformed labels, and
over-length names. Internationalized names use their canonical IDNA ASCII
form.

The adapter reads each complete non-empty JSONL record independently and
accepts the documented string `host` field. Optional and unknown fields,
including source metadata, are ignored; source collection is deliberately not
enabled because this milestone does not retain provenance. Malformed JSON,
non-object records, and missing or invalid hosts are counted without retaining
raw records. After a timeout or truncation, an unterminated final line is
treated as incomplete and discarded; a cleanly exited process may emit its
last complete JSON record without a terminal newline.

Hostnames are normalized through the shared DNS helper, deduplicated, and
lexically sorted into an immutable tuple. Duplicate records do not affect
status and do not create extra history entries.

## Scope policy

For root `authorized.example`, `api.authorized.example` and
`deep.api.authorized.example` are accepted. The root itself is excluded because the
published value represents discovered subdomains. Boundary-safe comparison
uses `candidate.endswith("." + root)` after normalization, so
`notauthorized.example`, `authorized.example.attacker.test`, and
`api.authorized.example.attacker.test` are rejected.

## Status mapping

```text
Tool SUCCESS, clean valid or empty output -> Provider SUCCESS
Tool SUCCESS, valid findings plus rejected/truncated output -> Provider PARTIAL
Tool SUCCESS, records but no valid in-scope findings -> Provider FAILURE
Tool FAILURE -> Provider FAILURE
Tool TIMEOUT with valid findings -> Provider PARTIAL
Tool TIMEOUT without findings -> Provider FAILURE
Tool NOT_FOUND -> Provider UNAVAILABLE
Tool ERROR -> Provider ERROR
```

Diagnostics contain only safe counts and fixed messages. Raw stdout, stderr,
argv, environment values, paths, and exception messages are not copied into
provider or capability errors.

The capability maps provider success to `SUCCESS`, usable partial results to
`PARTIAL`, failure to `FAILURE`, and unavailable/error to `ERROR`. `SUCCESS`
with no findings publishes `SUBDOMAINS = ()`. `SUCCESS` and `PARTIAL` publish
the one typed state value atomically and continue; `FAILURE` and `ERROR`
publish nothing and stop according to the existing runtime contract.

## Composition and testing

The default factory lazily constructs a fresh provider and capability. It uses
an injected `ToolRunner` when supplied and otherwise creates a local runner.
Planning remains structural and never checks executable availability.
Unavailable Subfinder is reported only when execution occurs or when a caller
explicitly invokes the runner's availability operation.

Tests inject `FakeToolRunner`, inspect exact typed invocations, and require no
binary, credentials, subprocess, or network. Deployment operators are
responsible for installing Subfinder and configuring any provider API keys
through Subfinder's normal supported mechanisms. RedForge does not read or
store those credentials.

## Current limitations

- Enumeration is synchronous, sequential, and has no retry or dynamic
  replanning.
- Captured output is bounded after `subprocess.run` completes, so peak child
  output memory is not streaming-bounded.
- Subfinder version compatibility is represented by `("-version",)` metadata
  but is not automatically probed.
- Provider-source provenance is intentionally not retained.
- Legacy HTTPX, Katana, and technology-detection adapters still require
  migration to the shared tool-runner boundary.
