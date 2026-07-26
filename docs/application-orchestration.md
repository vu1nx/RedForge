# Application Scan Orchestration

`ScanOrchestrator` is RedForge's first provider-neutral, one-shot application
execution service:

```text
ScanConfig
    |
    v
prepare_scan()
    |
    v
ExecutionPlan
    |
    v
Preflight
    |
    v
PipelineBuilder
    |
    v
PlannedExecution
    |
    v
Context
    |
    v
Pipeline runtime
    |
    v
ScanResult
```

The service does not parse raw input. It receives a validated `ScanConfig`, a
capability-definition registry, and a separately configured lazy factory
registry. Applications may inject authorized production providers or
deterministic offline fakes. The orchestrator imports no concrete adapter,
ToolRunner, executable, network transport, filesystem API, or CLI framework.
The [minimal CLI](cli.md) is a higher application adapter that performs raw
argument parsing and explicit production composition before calling this
unchanged service.
Its optional [JSON renderer](json-output.md) extracts only stable public
application summaries; the orchestrator remains unaware of output formats and
does not import CLI serializers.

## Execution sequence

One `run()` call:

1. calls `prepare_scan()` once;
2. rejects required disabled capabilities before factory construction;
3. derives and checks readiness requirements from planned factory metadata;
4. raises `ScanPreflightError` before Context creation when not ready;
5. creates one initial Context from the canonical `ScanTarget`;
6. passes the prepared plan to `PlannedExecution`;
7. builds one fresh Pipeline through `PipelineBuilder`;
8. executes that Pipeline once through the existing sequential runtime;
9. evaluates application acceptance once;
10. returns one immutable `ScanResult` retaining the ready preflight result.

There is no repeated planning, dynamic replanning, fallback provider, retry,
or hidden capability insertion.

## Dependency injection and build failures

`ScanOrchestrator` receives `CapabilityRegistry` and
`CapabilityFactoryRegistry`. Construction validates their structural alignment
but does not call factories. Factories stay lazy until the prepared pipeline is
built.

Missing factories, invalid factory results, and capability identity mismatches
retain the existing typed direct-Builder behavior. Orchestrated scans detect
missing factories and declared binding mismatches earlier through preflight.
They raise a typed `ScanPreflightError`, execute no factory, create no Context,
and do not produce a partial `ScanResult`. Programmer errors are not broadly
caught or mislabeled as scan failures.

Tool definitions, executable availability, and provider configuration are
checked through injected registries and probes. Preflight never executes a
capability, tool, scan request, or target operation. See
[Preflight Readiness](preflight-readiness.md).

No convenience constructor silently creates live NVD access or default network
providers. Offline tests inject typed fake subdomain, resolver, HTTP, crawler,
technology, and vulnerability providers through the normal factory contracts.

## ScanResult and acceptance

`ScanResult` is frozen and slotted. It contains:

- the normalized `ScanConfig`;
- immutable `ExecutionPlan`;
- immutable `PipelineResult`;
- application `accepted` decision.

It exposes final Context, original runtime status, and immutable execution
history as read-only properties. Its concise representation excludes target
data, Context evidence, diagnostics, process output, argv, environment,
executables, providers, runners, registries, pipelines, and report objects.

Runtime status describes execution.

`ScanResult.accepted` describes application policy.

```text
SUCCESS -> accepted
PARTIAL -> accepted only when allow_partial_results is true
FAILURE -> rejected
ERROR   -> rejected
```

Acceptance never rewrites status, changes publication, retries work, or mutates
Context. Normal runtime `FAILURE` and sanitized `ERROR` outcomes return a
`ScanResult`; only pre-execution configuration or build defects raise.

## Empty, partial, and stopping outcomes

A clean empty discovery still executes the deterministic structural plan.
Existing capabilities skip providers when their input collections are empty,
publish canonical empty states, and complete with `SUCCESS`.

Usable `PARTIAL` evidence continues through downstream intelligence exactly as
before. The same runtime Context and history result whether application policy
accepts or rejects that partial outcome.

An intermediate `FAILURE` or `ERROR` preserves upstream state, publishes no
placeholder failing output, stops downstream steps, and returns the unchanged
runtime history with `accepted=False`.

## Limit boundary

The orchestrator translates `ScanConfig.limits` once into an immutable neutral
runtime policy. The runtime validates a complete typed publication batch, checks
its configured collection counts, and accepts or rejects the batch before
Context mutation. It also checks an absolute monotonic deadline before and after
each capability.

An oversized or late publication becomes a typed sanitized `FAILURE`, so
`accepted` is false. Upstream Context remains available, the rejected
capability publishes nothing, and downstream capabilities do not execute.
Direct Pipeline use without a policy remains unlimited.

Scan limits reject oversized canonical publications.

They do not translate directly into arbitrary tool command-line flags.

A deadline prevents future publication and downstream execution.

It does not forcibly terminate a capability that is already running.

The builder constructs the planned pipeline before the runtime's first
deadline check. An already-expired deadline therefore prevents capability
execution, but does not avoid construction of planned lazy factory results.
See [Scan Limits](scan-limits.md).

## Current non-goals

This service is library-level one-shot orchestration only. It adds no CLI,
interactive prompts, configuration-file or environment loading, persistence,
queues, scheduling, resume, caching, reports, filesystem output, automatic tool
installation, or legal authorization verification.
