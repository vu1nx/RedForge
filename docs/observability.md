# Structured Observability

RedForge exposes provider-neutral, execution-scoped diagnostic events without
changing scan semantics:

```text
ApplicationComposition
        |
        v
DiagnosticEventSink
        |
        +-- application lifecycle summaries
        +-- preflight summary
        +-- capability lifecycle events
        +-- limit/deadline policy events
```

The default `NullDiagnosticEventSink` is silent. Hosts may inject one sink per
orchestrator; there is no global logger, current-scan singleton, background
thread, batching, persistence, file logging, or remote telemetry.

## Event schema

Every `DiagnosticEvent` is frozen, slotted, and carries
`schema_version = 1`. This version is independent from the package,
configuration, and CLI JSON-output schema versions. Events contain a fixed
typed event identity, one of `DEBUG`, `INFO`, `WARNING`, or `ERROR`, a short
fixed message, and a closed immutable `DiagnosticFields` model.

Current event categories cover:

- scan preparation, preflight, build, execution, and result creation;
- capability start and `SUCCESS`, `PARTIAL`, `FAILURE`, or `ERROR` completion;
- state-limit and deadline policy violations.

There are no timestamps, durations, random IDs, dynamic event names, arbitrary
mappings, recursive serializers, or exception objects. Status diagnostics
reflect runtime status; they never reinterpret it. Acceptance is a separate
field.

## Safe fields and failure policy

The closed field set permits only bounded strings, non-negative integers,
booleans, nulls, and one bounded immutable sequence of typed safe PARTIAL
reason codes. Identity and summary fields include capability ID, runtime
status, acceptance, history count, preflight counts, state key, and
observed/allowed limits.

Terminal `capability_partial` events may include `partial_reasons` when a
capability supplied the approved typed SDK metadata contract. The runtime
accepts only the existing `TechnologyDetectionPartialReason` values, removes
duplicates, bounds the input count, and never copies arbitrary result metadata.
Current safe values are `execution_timeout`, `malformed_records_skipped`,
`unassociated_records_skipped`, and `output_truncated`. A PARTIAL result
without approved reasons retains the original event shape. Reasons are
diagnostic only; runtime status remains authoritative.

Technology detection is currently the only capability with an approved typed
PARTIAL-reason contract. A future capability must define and receive review
for its own bounded typed contract before runtime may expose its reasons.

Events never contain discovered subdomains, hosts, endpoints, technologies,
vulnerabilities, risk evidence, Context state, command arguments, executable
paths, working directories, environment values, stdout, stderr, credentials,
provider objects, provider exception text, tracebacks, or internal reprs.
Invalid raw targets are not diagnostic events. The current integration also
omits canonical targets to minimize exposure.

`emit_safely()` suppresses ordinary sink exceptions at the observability
boundary. It does not retry or emit a recursive failure event, and diagnostics
cannot change readiness, runtime status, publication, acceptance, or exit
codes. `KeyboardInterrupt` and `SystemExit` are not swallowed.

## Standard-library logging adapter

`PythonLoggingDiagnosticSink` receives an already configured
`logging.Logger`. It does not call `basicConfig`, mutate the root logger, add
handlers, or create file/network handlers. It maps typed severities explicitly
and writes one compact deterministic JSON object per accepted logging record:

```json
{"schema_version":1,"event_type":"capability_completed","severity":"INFO","message":"Capability completed","fields":{"capability_id":"http_probe","runtime_status":"SUCCESS"}}
```

Keys and fields have deterministic order, `allow_nan=False`, and no generic
fallback serializer, exception info, stack info, or multiline values.
Typed reason tuples are serialized explicitly as deterministic JSON string
arrays:

```json
{"schema_version":1,"event_type":"capability_partial","severity":"WARNING","message":"Capability completed partially","fields":{"capability_id":"technology_detection","runtime_status":"PARTIAL","partial_reasons":["malformed_records_skipped"]}}
```

The controlled Kali reconnaissance validation produced this exact safe reason
shape for technology detection. It made the legitimate PARTIAL outcome
explainable without exposing the authorized target or any discovered evidence.
See [Kali Reconnaissance Smoke Validation](kali-smoke-validation.md).

## Configuration and CLI

TOML schema version 1 supports:

```toml
[observability]
level = "off"
```

Accepted values are `debug`, `info`, `warning`, `error`, and `off`. The default
is `off`. There is no logger name, file path, remote endpoint, rotation, color,
or arbitrary Python logging configuration.

The CLI override is explicit:

```bash
redforge scan authorized.example --log-level info
```

Precedence remains explicit CLI value, then TOML, then the silent default.
When enabled, diagnostic JSON records go only to stderr. Human or JSON scan
outcomes retain their existing stdout contract; in particular,
`--output json` still produces exactly one machine outcome on stdout.

Importing observability, composition, configuration, or CLI modules configures
no logger and emits nothing. CLI logger construction occurs only for an
executed command with observability enabled.

Dry run has no runtime lifecycle and therefore emits no scan-execution or
capability events. Its human or JSON inspection document contains only typed
manifest identities and the existing sanitized readiness summary. It never
promotes executable paths, command arguments, environment data, parser
evidence, stdout, or stderr into diagnostics. See [Dry Run](dry-run.md).
