# Scan Limits

RedForge enforces `ScanLimits` at the neutral runtime publication boundary. The
application translates validated configuration into one immutable
`StateLimitPolicy` per scan; the runtime receives only that neutral policy and
never receives `ScanConfig`.

## Canonical collection mapping

| ScanLimits field | Canonical state | Count |
| --- | --- | --- |
| `max_subdomains` | `SUBDOMAINS` | `SubdomainDiscoveryResult.hostnames` |
| `max_hosts` | `HOSTS` | `HostResolution.hosts` |
| `max_alive_hosts` | `ALIVE_HOSTS` | tuple elements |
| `max_http_endpoints` | `HTTP_ENDPOINTS` | tuple elements |
| `max_crawl_endpoints` | `ENDPOINTS` | tuple elements |
| `max_technologies` | `TECHNOLOGIES` | tuple elements |

Only these validated canonical state types are measured. Scalars and
intelligence read models are not collection-limited because `ScanLimits`
defines no corresponding fields. A value equal to its maximum is accepted;
one element over is rejected. No deep count, serialization, arbitrary `len()`,
or iteration over unknown objects is performed.

Scan limits reject oversized canonical publications.

They do not translate directly into arbitrary tool command-line flags.

## Publication timing and atomicity

For each capability, the runtime:

1. checks the monotonic deadline;
2. executes the capability once;
3. validates its result and complete publication contract;
4. validates every canonical state value;
5. checks the deadline again;
6. validates collection limits for the complete batch;
7. publishes the batch atomically.

If any output is oversized, none of that capability's outputs enter Context.
This includes the HTTP probe's paired `ALIVE_HOSTS` and `HTTP_ENDPOINTS`
publication. Valid upstream Context remains, one typed sanitized `FAILURE`
history entry is recorded, and downstream execution stops. RedForge never
truncates to a first-N subset, retries, selects an alternate capability, or
mutates returned evidence.

The typed `StateLimitViolation` contains only the canonical state key, observed
count, and allowed count. Diagnostics do not contain the collection, target,
provider, tool, command, environment, stdout, stderr, or filesystem path.

## Deadline semantics

`overall_timeout_seconds` is converted once to an absolute deadline using a
monotonic clock. The deadline is checked before and after each capability.
Reaching the deadline (`current >= deadline`) is a sanitized `FAILURE`.

A deadline prevents future publication and downstream execution.

It does not forcibly terminate a capability that is already running.

If time expires while a capability runs, that call completes normally, but its
returned publication is rejected by the post-step check. No threads, signals,
async tasks, background workers, or duplicate subprocess timeouts are used.
Existing provider and ToolRunner timeouts remain responsible for bounding their
own active operations.

Pipeline construction currently precedes the first runtime deadline check.
Consequently an expired deadline prevents the first capability invocation but
does not prevent construction of the already-planned pipeline. The terminal
history entry is marked as unexecuted and carries a typed `DeadlineViolation`.

## Status and compatibility

Both collection-limit and deadline violations map to runtime `FAILURE`.
Existing precedence remains:

```text
ERROR > FAILURE > PARTIAL > SUCCESS
```

Therefore an earlier `PARTIAL` followed by a policy violation ends in
`FAILURE`, while a normal provider `ERROR` stops before later policy
evaluation. `ScanResult.accepted` is always false for a policy `FAILURE`,
regardless of `allow_partial_results`.

Manual and direct Pipeline execution supplies no policy by default and retains
the existing unlimited behavior. Planner, PipelineBuilder, capabilities,
adapters, and ToolRunner do not inspect application limits.

## Remaining limitations

The deadline is cooperative only at sequential capability boundaries. It cannot
cancel Python or external work already executing, does not implement async
cancellation, and does not avoid pipeline construction when already expired.
There are no limits for intelligence read models because no accepted
`ScanLimits` fields define them.

The [minimal CLI](cli.md) always uses the validated `ScanLimits` defaults and
does not expose flags for increasing or bypassing them. Limit violations are
rendered from typed metadata without publishing rejected evidence.
Its [JSON contract](json-output.md) represents state limits using only the
state key and observed/allowed counts, and represents deadlines without
timestamps or monotonic clock values.
