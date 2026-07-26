# Execution Contract

TASK-0016 defines how RedForge preserves capability outcomes at the sequential
pipeline boundary.

## Status and continuation

Pipeline status is the most severe outcome observed, using this precedence:

```text
ERROR > FAILURE > PARTIAL > SUCCESS
```

`SUCCESS` and `PARTIAL` continue execution. `FAILURE` and `ERROR` stop execution.
A later success cannot erase an earlier partial outcome.

Capability validation and pipeline aggregation have separate responsibilities.
Each capability validates its own required inputs and returns the appropriate
status. The pipeline preserves, combines, and applies that status; declarative
prerequisite registration is not part of this milestone.

## Execution history and state

`PipelineResult.executions` is an immutable tuple with exactly one
`CapabilityExecution` for every capability that actually ran, in execution
order. Each entry retains the capability name and original `Result`, including
status, data, errors, and metadata. `last_result` remains the result of the last
capability that actually executed and is not used as aggregate pipeline status.

State publication follows the usability contract:

- `SUCCESS` and `PARTIAL` publish every validated explicit state publication,
  or one normalized legacy data value for a single-output contract;
- `FAILURE` and `ERROR` data remain available in execution history but are not
  published;
- previously published state remains intact when execution stops.

Publication validation is atomic. Duplicate keys, undeclared keys, malformed
collections, ambiguous legacy data for a multi-output contract, and conflicting
explicit/legacy output become sanitized `ERROR` results without changing
Context. One capability execution still creates one history entry regardless
of publication count. See [State Publication](state-publication.md).

## Defensive boundary

Unexpected capability exceptions are converted to sanitized `ERROR` results.
Raw exception messages, tracebacks, filesystem paths, and secrets are not
included. Invalid return objects are also converted to sanitized `ERROR`
results. Both outcomes are recorded in history and stop execution without
publishing state.

Capability names must be unique within a pipeline. Adding a second capability
with the same name raises `ValueError`, preventing ambiguous state and history
identities.

Host Resolution applies this contract to discovered-name prerequisites:
missing input returns `FAILURE`, an invalid input shape returns `ERROR`, and
usable incomplete resolution returns `PARTIAL`. The pipeline publishes
successful or partial `HostResolution` output and prevents HTTP probing after a
resolution failure or error. Capability-owned validation remains separate from
pipeline-owned status aggregation.

External capabilities receive typed results through injected ports. Expected
sanitized adapter failures become `FAILURE` or item-level `PARTIAL`; invalid
port returns and unexpected defects become `ERROR`. Failure/error adapter data
is retained only in execution history and is not published as valid state.

The [Execution Planner integration](execution-planner.md) preserves this
authority. `PipelineBuilder` translates validated immutable plan steps into a
normal pipeline but does not execute it. `PlannedExecution` supplies the
caller's existing `Context` to that pipeline, so present state—including valid
empty typed values—can satisfy planning dependencies and remains available to
runtime capabilities.

An empty pipeline over an existing context returns `SUCCESS`, no executions,
and `last_result=None`. For non-empty plans, history contains only capabilities
that actually ran. A `PARTIAL` result publishes usable data and permits the
next planned step; `FAILURE` or `ERROR` stops the remaining plan under the same
sequential policy as manually constructed pipelines.

Planned steps and configured runtime instances are associated through typed
`CapabilityId` values from [Capability Registry v2](capability-registry.md).
Execution history retains existing serialized names and records the typed ID
for planned or explicitly configured executions.

External process outcomes are deliberately separate from capability `Result`
values. A tool adapter consumes `ToolExecutionResult`, parses domain output,
and chooses the appropriate capability status. This preserves existing
`PARTIAL`, `FAILURE`, `ERROR`, publication, and execution-history semantics.
See [External Tool Execution](tool-execution.md).

For passive subdomain discovery, complete and partial usable provider results
publish one immutable `SUBDOMAINS` value atomically. A successful empty
enumeration publishes `()`. Provider failure, unavailable execution, and
operational error publish nothing; the existing sequential stop rules apply.
One Subfinder invocation remains one `subdomain_discovery` history entry. See
[Subfinder Passive Recon Integration](subfinder-integration.md).

HTTP probing follows the same publication boundary. The HTTPX provider returns
typed endpoint evidence to `HttpProbeCapability`, which derives responsive
`Host` identities from it. Complete and usable partial results publish one
atomic batch containing immutable `ALIVE_HOSTS` and `HTTP_ENDPOINTS` tuples; a
successful empty probe publishes `()` for both. A partial result without
endpoint evidence becomes failure. Failure, unavailable execution, and
operational error publish neither state. One HTTPX invocation remains one
`http_probe` execution-history entry. See
[HTTPX Web Probe Integration](httpx-integration.md).
