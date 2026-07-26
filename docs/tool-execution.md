# External Tool Execution

RedForge external processes cross one typed, synchronous execution boundary:

```text
Capability
    |
    v
Tool Adapter
    |
    v
ToolRunner
    |
    +--> LocalSubprocessToolRunner
    |
    +--> FakeToolRunner
    |
    +--> Future Container Runner
    |
    +--> Future Remote Runner
```

Capabilities model security responsibilities. Tools are replaceable execution
providers.

Concrete providers now include passive
[Subfinder discovery](subfinder-integration.md) and conservative
[HTTPX web probing](httpx-integration.md). The framework itself still does not
download, install, or configure external tools and does not change the
capability graph.

## Identity, definitions, and registry

`ToolId` is a frozen, slotted, ordered lowercase-snake-case value object.
Built-in-style and application-defined identities use the same validation.
Identity is not an executable path, display label, capability ID, or
implementation class name.

`ToolDefinition` is immutable static metadata:

- typed identity;
- display name and responsibility-oriented description;
- one executable token;
- generic version arguments;
- a positive default timeout;
- normalized descriptive tags.

Definitions contain no runner, capability, secret, environment, or mutable
configuration. Version probing is intentionally deferred; `version_argument`
provides the generic metadata needed by a later explicit operation without
adding tool-specific parsing or compatibility policy.

`ToolRegistry` stores definitions only. Registration performs no resolution or
execution. `get`, `require`, `contains`, `all`, `ids`, and `by_tag` return
deterministic results, with immutable tuple snapshots for collection queries.
It is separate from Capability Registry v2.

## Invocation contract

`ToolInvocation` contains a typed tool identity, tuple argv, optional timeout
override, optional `Path` working directory, sorted environment pairs, and
optional text or byte stdin. Mutable constructor inputs are copied.

Arguments are never concatenated or parsed as shell syntax. Semicolons, pipes,
quotes, redirects, wildcard characters, command substitutions, and spaces stay
literal argv values. Its safe representation includes only argument count,
environment variable names, stdin size, and other non-secret metadata.

The invocation timeout overrides `ToolDefinition.default_timeout_seconds`.
Both must be positive and finite. The runner uses per-process `cwd`; it never
creates directories or changes the parent process working directory.

## Runner port and local implementation

`ToolRunner` is an SDK protocol with `run` and read-only `is_available`
operations. The protocol imports no subprocess implementation. Tool-specific
adapters depend on this port and retain responsibility for invocation building,
output parsing, and domain semantics.

`LocalSubprocessToolRunner` lives in the adapter/infrastructure layer. It:

- resolves executables with `shutil.which`;
- executes `[resolved_executable, *arguments]`;
- always uses `shell=False`;
- captures stdout and stderr separately as bytes;
- supplies `DEVNULL` when stdin is absent;
- decodes with an explicit configured encoding;
- normalizes process newlines;
- enforces the resolved timeout;
- returns typed, sanitized operational outcomes.

It never parses findings, references capabilities, publishes Context state,
retries, installs tools, or performs network access itself. `is_available`
only resolves the executable and has no installation or execution side effect.

## Status and diagnostics

Framework-level status is deterministic:

```text
exit code 0       -> SUCCESS
non-zero exit     -> FAILURE
timeout           -> TIMEOUT
missing executable -> NOT_FOUND
OS/runner failure -> ERROR
```

Non-zero exit is ordinary evidence, not an exception. Exit codes are preserved
when a process exits. Timeout and not-found results use no fabricated exit
code. Stdout or stderr content never determines status.

`ToolExecutionResult` is frozen and slotted. Adapters can read its bounded
stdout and stderr, but its representation shows only identity, status, exit
code, duration, stream sizes, timeout, and truncation metadata. Raw command
strings, argv, environment values, outputs, filesystem paths, exceptions,
tracebacks, and process objects are not included in diagnostics.

## Environment policy

Safe mode is the default. The runner constructs:

```text
explicit allowlisted parent variables
        +
invocation overrides
```

The default allowlist covers PATH, Windows process-bootstrap variables,
temporary-directory variables, and locale variables. Unrelated parent
credentials are not inherited. Invocation variables override inherited values,
duplicate invocation names are rejected, and neither values nor complete
environment mappings appear in representations or results.

`ToolRunnerConfig(inherit_environment=True)` is an explicit compatibility
escape hatch. It is not the default. Runner configuration is immutable and
constructor-injected; there is no mutable global runner or configuration.

## Capture limits and stdin

`ToolRunnerConfig` independently limits retained stdout, stderr, and accepted
stdin bytes. Output keeps the deterministic leading byte segment, safely
handles incomplete UTF-8, and sets `truncated` when either stream exceeds its
limit. Empty output remains empty. Oversized stdin returns a sanitized `ERROR`
without starting a process.

The current `subprocess.run` implementation applies output retention limits
immediately after process capture. Therefore retained results are bounded, but
peak child-output memory is not truly streaming-bounded. Streaming capture is
deferred technical debt and must be implemented before treating these limits
as a hard process-memory boundary.

## Adapter responsibility

The framework deliberately does not force tool outcomes into capability
statuses. A future adapter may choose, based on its domain contract:

```text
Tool SUCCESS + valid output  -> Capability SUCCESS
Tool SUCCESS + partial parse -> Capability PARTIAL
Tool FAILURE                 -> Capability FAILURE or PARTIAL
Tool TIMEOUT                 -> Capability PARTIAL, FAILURE, or ERROR
Tool NOT_FOUND               -> Capability ERROR or configuration FAILURE
Tool ERROR                   -> Capability ERROR
```

Adapters must sanitize capability-facing messages and must not copy full tool
output into errors or logs.

`SubfinderSubdomainProvider` is the reference implementation of this boundary:
it builds a narrow immutable invocation, consumes bounded JSONL output, and
maps tool outcomes into a domain-level `SubdomainDiscoveryResult`. Neither the
generic runner nor the capability knows how Subfinder output is shaped.

`HttpxProbeProvider` follows the same boundary for HTTP and HTTPS service
discovery. Resolved hosts are encoded as deterministic stdin, and normalized
HTTP endpoint evidence is mapped back to approved responsive host identities.
The generic runner performs no URL parsing or scope decisions.

## Deterministic testing

`FakeToolRunner` queues immutable `ToolExecutionResult` values by `ToolId` and
records safe `ToolInvocation` objects. Its snapshot API returns tuples, queued
collections are not exposed, and unexpected invocations fail explicitly. It
does not import or call subprocess.

Portable local-runner tests use `sys.executable`; they require no network or
installed security tooling. Future adapter tests should prefer the fake.

Subfinder unit and planned-execution tests use `FakeToolRunner`; ordinary test
runs therefore require neither a Subfinder binary nor network access.
HTTPX tests use the same fake boundary and likewise require no installed
binary, network, credentials, target files, or platform shell.
