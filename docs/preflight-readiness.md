# Preflight Readiness

Scan preflight is target-plan scoped. `redforge doctor` reuses the accepted
static executable readiness boundary but coordinates a separate target-free
diagnostic. It derives requirements from composition metadata, does not prepare
a scan, and reports full-assessment provider absence separately. See
[RedForge Doctor](doctor.md).

Preflight proves that the selected composition appears ready to start.

It does not prove that the target is reachable or that execution will succeed.

```text
ScanConfig
    |
    v
PreparedScan
    |
    v
Preflight
    |-- factories
    |-- tool definitions
    |-- executables
    `-- providers
    |
    v
PipelineBuilder
    |
    v
Runtime
```

## Purpose and boundary

`ScanPreflight` receives an immutable `PreparedScan`, the lazy
`CapabilityFactoryRegistry`, and an explicit `ReadinessRegistry`. It makes one
deterministic pass over planned capability IDs. It creates no Context, Pipeline,
capability, provider, or invocation and performs no scan, DNS request, target
probe, vulnerability lookup, subprocess execution, or dynamic replanning.

Preflight does not establish legal authorization, target reachability,
vulnerability, tool success, or scan completion. These are outside readiness.

## Requirement derivation

Each lazy `CapabilityFactoryDefinition` declares only:

- its typed capability identity;
- its callable factory, which preflight never invokes;
- immutable tool/provider readiness requirements.

Only descriptors referenced by the prepared plan are checked, in plan order.
Repeated tool or provider requirements are deduplicated locally for that
invocation. No cache survives across scans, and no `ToolId` or provider role is
stored in `ExecutionPlan`.

Reconnaissance checks its five-capability closure only. Full assessment checks
the complete nine-capability closure, including four external tool requirements
when tool-backed adapters are selected and vulnerability-provider
configuration.

## Checks and statuses

Every planned capability first receives a factory or binding check. A missing
factory is `UNAVAILABLE`; a declared identity mismatch is `INCOMPATIBLE`.
Direct `PipelineBuilder` use retains its existing typed errors.

A tool requirement produces:

1. a `TOOL_DEFINITION` check against `ToolRegistry`;
2. when the definition exists, a `TOOL_EXECUTABLE` check through the injected
   `ToolReadinessProbe`.

The concrete `ToolRunnerReadinessProbe` uses only `ToolRunner.is_available()`.
It does not run help, version, or scan commands. Missing executables are
`UNAVAILABLE`; expected probe boundary failures are sanitized `ERROR` results.
Tool version compatibility remains future work because current tool definitions
declare no supported-version constraint.

Static scan preflight intentionally remains execution-free. Doctor and runtime
additionally use the infrastructure executable resolver for definitions with
identity metadata. For canonical `httpx`, this target-free check distinguishes
Kali's ProjectDiscovery `httpx-toolkit` from an unrelated Python `httpx`
executable before target-facing runtime execution.

Executable readiness does not prove that a tool's full startup path will
succeed. It only resolves Katana, and Katana v1.6.1 also exits from a
separately invoked version path before initializing user-scoped configuration,
while a crawl initializes that configuration. The runner therefore preserves
the platform home variable in its minimal allowlisted child environment;
readiness still exposes neither its value nor an executable path.

A provider requirement records whether composition supplied the provider role.
Absence is `MISCONFIGURED`. An optional `ProviderReadinessProbe` may validate
static configuration or binding compatibility without a target. No credential
value, environment variable, raw exception, or provider representation enters
the result. Live remote health probes are not part of the default contract.

Full-assessment production composition supplies the NVD CVSS, FIRST EPSS, and
CISA KEV enrichment roles. Their readiness is structural only: no DNS or HTTP
request is made. A custom factory composition that omits one of these roles
still receives `provider_absent` when an explicit enrichment plan requires it.
Reconnaissance and existing full-risk plans do not acquire these checks merely
because the providers are available.

Statuses are independent from runtime status:

```text
READY
UNAVAILABLE
MISCONFIGURED
INCOMPATIBLE
ERROR
```

All checks must be `READY`. Independent failures are aggregated using immutable
tuples and fixed typed reasons.

## Orchestrator behavior

The application sequence is:

```text
prepare once
-> preflight once
-> build once
-> create Context once
-> execute once
-> evaluate acceptance once
```

When preflight is not ready, `ScanOrchestrator` raises
`ScanPreflightError(result)`. No factory is called, no Context is created, no
runtime status is fabricated, and no `ScanResult` is returned. A successful
`ScanResult` retains the immutable ready `PreflightResult` for auditability.

Preflight does not inspect `ScanLimits` or execute deadline checks. Runtime
publication limits and monotonic deadlines remain unchanged and begin only
after readiness succeeds.

## Offline composition and compatibility

Tests and offline applications inject deterministic tool and provider probes.
No real PATH, executable, subprocess, network, or target is required.
The immutable [application composition](application-composition.md) profile
owns this wiring and accepts explicit runner, provider, tool-probe, and
provider-probe substitutions without a service locator or deep monkeypatching.
Planner, direct PipelineBuilder, direct Pipeline, manual pipelines, adapters,
ToolRegistry, and ToolRunner remain independently usable without preflight.
The [minimal CLI](cli.md) treats a non-ready result as an expected
pre-execution condition, prints only typed sanitized reasons, returns exit code
3, and never invokes a capability.
Selecting `full_assessment` through
[typed configuration](configuration.md) remains valid configuration; when no
vulnerability provider is supplied, this preflight boundary reports
`provider_absent` rather than configuration validation inventing a provider.
In JSON mode it publishes the same deterministic failed checks as a bounded
`preflight` summary on stdout, with null runtime fields and no executable path,
environment, raw exception, or Context. See
[Deterministic JSON Output](json-output.md).

Structured observability emits one preflight start event followed by one
completed or failed summary containing only readiness, total-check, and
failed-check counts. It does not emit each ready check or any executable path,
provider exception, or configuration value. A readiness failure produces no
build, execution, capability, or runtime-status event. See
[Structured Observability](observability.md).

The [dry-run command](dry-run.md) exposes this same preflight result without
building a pipeline or creating `Context`. Requirements come only from factory
metadata attached to capabilities in the prepared plan. For reconnaissance,
that means four deduplicated executable checks—`subfinder`, `httpx`, `katana`,
and `whatweb`—and no full-assessment vulnerability-provider check. Readiness
resolves availability only; it does not execute a version command or contact a
target.
