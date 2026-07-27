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
booleans, and nulls for identities and summaries such as capability ID,
runtime status, acceptance, history count, preflight counts, state key, and
observed/allowed limits.

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
