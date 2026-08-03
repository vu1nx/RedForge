# Reconnaissance Toolchain

The production reconnaissance inventory is canonical registry/factory
metadata and is also consumed by `redforge doctor`: Subfinder, HTTPX, Katana,
and WhatWeb. Doctor checks executable availability without duplicating their
names in coordinator logic. Identity-constrained definitions may execute only
their declared target-free version arguments. See
[RedForge Doctor](doctor.md) and
[Kali Linux Platform Policy](kali-platform.md).

RedForge's reconnaissance profile derives its requirements from the canonical
capability registry, execution planner, and lazy factory metadata. Tool names in
this document are deployment requirements, not planner steps. RedForge does not
download, install, update, or configure these programs.

## Capability closure

For the canonical target `authorized.example`, requesting `TECHNOLOGIES`
produces this deterministic closure:

| Order | Capability ID | Requires | Publishes | Execution dependency |
|---|---|---|---|---|
| 1 | `subdomain_discovery` | none | `SUBDOMAINS` | tool `subfinder` |
| 2 | `host_resolution` | `SUBDOMAINS` | `HOSTS` | operating-system resolver port |
| 3 | `http_probe` | `HOSTS` | `ALIVE_HOSTS`, `HTTP_ENDPOINTS` | tool `httpx` |
| 4 | `web_crawl` | `ALIVE_HOSTS` | `ENDPOINTS` | tool `katana` |
| 5 | `technology_detection` | `ENDPOINTS` | `TECHNOLOGIES` | tool `whatweb` |

The host resolver uses the standard-library `socket.getaddrinfo` adapter by
default. It is not an external-tool definition and currently has no separate
readiness probe. Resolution therefore begins only after executable preflight
has succeeded.

## Required tools

| Tool ID | Executable | Adapter and input | Machine output |
|---|---|---|---|
| `subfinder` | `subfinder` | `SubfinderSubdomainProvider`; canonical DNS root follows `-d` | bounded JSONL on stdout |
| `httpx` | `httpx-toolkit`, then `httpx` after identity validation | `HttpxProbeProvider`; bounded normalized host list on stdin | bounded JSONL on stdout |
| `katana` | `katana` | `KatanaWebCrawlProvider`; bounded in-scope HTTP(S) seeds on stdin | bounded JSONL on stdout |
| `whatweb` | `whatweb` | `WhatWebTechnologyDetectionProvider`; bounded canonical endpoint arguments | bounded JSON array in an adapter-owned temporary file |

Every invocation is a typed argument vector executed with `shell=False`.
Subfinder's target is canonicalized before it becomes the value following
`-d`. HTTPX and Katana receive deterministic newline-delimited stdin, so target
values cannot become flags. WhatWeb accepts only normalized HTTP(S) endpoints
generated from typed crawler evidence; arbitrary flags are not supported.

The runner captures stdout and stderr separately. Adapters parse only their
documented machine output and never publish stderr. Runner and provider
diagnostics are fixed sanitized messages; command vectors, executable paths,
environment values, target evidence, stdout, and stderr are excluded.
The minimal child environment retains `HOME` and `USERPROFILE` because some
tool startup contracts require a platform home directory. In particular,
Katana v1.6.1 initializes user-scoped configuration before crawling; its
executable-resolution readiness check never reaches that initialization, and
its separately invoked version path exits before it.

## Status and parser policy

Unavailable executables fail static preflight with `UNAVAILABLE`, before
runtime or `Context` creation. If execution is reached through manual
composition, tool `NOT_FOUND` becomes provider `UNAVAILABLE` and a terminal
runtime error. Permission and operational failures become sanitized errors;
non-zero exits become provider failures; and timeouts with usable complete
evidence may become partial results according to each adapter's contract.

All four parsers:

- accept explicit bounded text or an adapter-owned file;
- reject malformed and out-of-scope records without retaining raw records;
- normalize and deterministically deduplicate typed evidence;
- treat mixed usable and rejected evidence as `PARTIAL`;
- treat rejected-only output as `FAILURE`;
- treat clean empty output as a successful empty result;
- never execute a process, inspect the environment, or access the network.

The runtime publishes successful or usable partial results atomically. State
limits are checked before `Context` mutation. Terminal failure or error
publishes nothing and prevents later capabilities from running.

## Bounds and timeouts

`ToolRunnerConfig` independently bounds retained stdout, stderr, and stdin.
HTTPX and Katana additionally bound serialized stdin. WhatWeb bounds target
count, serialized input bytes, result-file bytes, and parsed record count.
Provider output is then subject to the application `ScanLimits` before atomic
publication.

Subprocess capture is currently bounded after `subprocess.run` returns. The
retained result and parser input are bounded, but peak child-output memory is
not a streaming hard bound. Truncation is explicit and cannot be reported as a
clean complete success.

Per-process timeouts remain adapter/runner bounds. The overall scan deadline is
checked before and after capability execution and is authoritative for the
final result, but it is cooperative: an already-running process is not
hard-cancelled when the remaining overall deadline becomes shorter.

## Readiness and versions

Readiness uses `ToolRunner.is_available()` only. It performs executable
resolution without running version commands or accessing a target. Factory
metadata ensures only requirements in the selected plan are checked and
deduplicated.

Definitions include immutable version arguments, but RedForge does not yet
enforce compatible tool versions. Machine-output format drift is deployment
technical debt. Install tools only from trusted upstream sources and validate
their versions in the deployment environment; RedForge provides no verified
download commands or automatic installation.

Katana v1.6.1's documented JSONL, stdin, scope, redirect, timeout, retry,
concurrency, rate, and output-omission flags match the current adapter
contract. Its remaining Kali revalidation is target-facing operational work
and is not performed by repository validation.

Executable candidates are ordered immutable infrastructure metadata. The
canonical `httpx` definition prefers Kali's `httpx-toolkit`, then considers
`httpx`; either candidate must match the bounded ProjectDiscovery version
output before runtime use. The unrelated Python HTTPX CLI is therefore not
ready. Candidate resolution exposes neither the absolute executable path nor
raw version output, and it is repeated for later runs so `PATH` changes are not
globally cached.

The initial controlled Kali smoke run exposed the HTTPX executable-name
collision. Successful real-tool revalidation remains a separate pending task.
