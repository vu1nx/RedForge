# Deterministic JSON Output

RedForge exposes schema-versioned machine output through:

```text
redforge scan authorized.example --output json
```

Human output remains the default. JSON mode writes exactly one compact,
newline-terminated JSON document to stdout for every handled outcome. Stderr
remains empty, and the process exit code is repeated in `exit_code`. Argparse
syntax failures that occur before a valid output mode is established retain
the human stderr behavior.

When [structured observability](observability.md) is explicitly enabled,
diagnostic JSON records use stderr. The final machine outcome remains exactly
one document on stdout and retains this schema unchanged. Consumers that need
only the outcome may ignore or redirect stderr.

## Schema version and fields

`schema_version` is the integer `1`. It versions this machine-output contract
and is independent from the RedForge package version. It changes only for an
intentional incompatible schema revision.

Every document contains these keys in this order:

```text
schema_version
outcome
exit_code
target
preset
runtime_status
accepted
capabilities_executed
preflight
policy_violation
error
```

Inapplicable fields are present as `null`; `capabilities_executed` is zero
before runtime. Nested preflight objects always contain `ready`,
`checks_total`, `checks_failed`, and `failures`. Policy objects always contain
`type`, `reason_code`, `state_key`, `observed`, and `allowed`.

Stable outcomes are `completed`, `not_ready`, `invalid_input`, `interrupted`,
and `internal_error`. Runtime and readiness status strings preserve their
existing enum representation. Presets and reason codes use lower snake case.
An executed but rejected scan is still `completed`; `accepted` and
`runtime_status` describe its result.

## Examples

Accepted success:

```json
{"schema_version":1,"outcome":"completed","exit_code":0,"target":"authorized.example","preset":"reconnaissance","runtime_status":"success","accepted":true,"capabilities_executed":5,"preflight":{"ready":true,"checks_total":9,"checks_failed":0,"failures":[]},"policy_violation":null,"error":null}
```

Rejected partial:

```json
{"schema_version":1,"outcome":"completed","exit_code":4,"target":"authorized.example","preset":"reconnaissance","runtime_status":"partial","accepted":false,"capabilities_executed":5,"preflight":{"ready":true,"checks_total":9,"checks_failed":0,"failures":[]},"policy_violation":null,"error":null}
```

Preflight failure:

```json
{"schema_version":1,"outcome":"not_ready","exit_code":3,"target":"authorized.example","preset":"reconnaissance","runtime_status":null,"accepted":null,"capabilities_executed":0,"preflight":{"ready":false,"checks_total":1,"checks_failed":1,"failures":[{"subject_type":"tool_executable","subject_id":"subfinder","status":"unavailable","reason_code":"executable_unavailable","message":"required executable is unavailable"}]},"policy_violation":null,"error":null}
```

State-limit failure:

```json
{"schema_version":1,"outcome":"completed","exit_code":4,"target":"authorized.example","preset":"reconnaissance","runtime_status":"failure","accepted":false,"capabilities_executed":5,"preflight":{"ready":true,"checks_total":9,"checks_failed":0,"failures":[]},"policy_violation":{"type":"state_limit","reason_code":"state_limit_exceeded","state_key":"TECHNOLOGIES","observed":101,"allowed":100},"error":null}
```

Invalid input:

```json
{"schema_version":1,"outcome":"invalid_input","exit_code":2,"target":null,"preset":"reconnaissance","runtime_status":null,"accepted":null,"capabilities_executed":0,"preflight":null,"policy_violation":null,"error":{"reason_code":"invalid_target","message":"invalid scan target"}}
```

## Reasons, policy, and forward compatibility

Readiness failures reuse accepted readiness reason codes such as
`factory_missing`, `tool_definition_missing`, `executable_unavailable`,
`provider_absent`, and `probe_failed`. Other current CLI reason codes are
`invalid_target`, `composition_failed`, `state_limit_exceeded`,
`deadline_exceeded`, `interrupted`, and `internal_error`.
Typed configuration failures add stable
`configuration_file_unavailable`, `configuration_parse_failed`,
`configuration_version_missing`, `configuration_version_unsupported`,
`configuration_field_unknown`, `configuration_value_invalid`, and
`configuration_profile_incompatible` codes. When `--output json` is explicit,
configuration failure produces one sanitized `invalid_input` document on
stdout; target, preset, runtime status, preflight, and policy fields remain
null.

State-limit policy includes only its canonical state-key name and bounded
counts. Deadline policy includes only `type: "deadline"` and
`reason_code: "deadline_exceeded"`; its remaining fixed fields are null.

Consumers should require a supported `schema_version` and tolerate future
additive enum values. Within version 1, equal typed outcomes produce
byte-identical output: key and failure order are deterministic, no timestamp
or random identifier is emitted, and JSON numbers reject NaN and Infinity.

The document is a control-plane summary. It never recursively serializes
`ScanResult`, Context, execution history, evidence collections, provider or
adapter objects, tool output, argv, environment values, exception details, or
filesystem paths. RedForge provides no JSON Lines, JSON file output, report
export, streaming, ownership verification, retry, or resume behavior. TOML
configuration and this output schema have independent schema versions;
configuration contents are never serialized into this document. Diagnostic
events use a third independent schema and are never nested into this result.
