# End-to-End Pipeline

Environment diagnosis precedes but is not part of this pipeline.
`redforge doctor` creates no target, plan, Context, capability, publication, or
history entry. Kali is the primary external-tool platform. The reconnaissance
closure through `technology_detection` has completed controlled validation;
the downstream intelligence closure remains covered by offline deterministic
tests. See [Kali Reconnaissance Smoke Validation](kali-smoke-validation.md).

RedForge's current library runtime can plan, construct, and execute every
implemented capability from one target context to immutable risk read models:

```text
Context.target_id
        |
subdomain_discovery -> SUBDOMAINS
        |
host_resolution -> HOSTS
        |
http_probe -> ALIVE_HOSTS + HTTP_ENDPOINTS
        |                 |
        |                 +-> vulnerability_detection -> VULNERABILITIES
        |                     -> finding_correlation -> CANONICAL_FINDINGS
        |                     -> vulnerability_enrichment -> ENRICHED_VULNERABILITIES
        |
web_crawl -> ENDPOINTS
        |
technology_detection -> TECHNOLOGIES
        |
asset_intelligence -> ASSET_INTELLIGENCE
        |
vulnerability_intelligence -> VULNERABILITY_INTELLIGENCE
        |
knowledge_graph -> KNOWLEDGE_GRAPH
        |
risk_intelligence -> RISK_INTELLIGENCE
```

`Context.target_id` is the single initial target contract. It is not invented
by the planner or builder and is not an executable argument model. Applications
are responsible for authorization before execution; provider adapters perform
their established scope and input validation.

The application-facing [Scan Configuration](scan-configuration.md) now provides
the validated path into this boundary:

```text
explicit TOML + CLI target/overrides
        -> typed configuration
        -> ScanTarget
        -> ScanScope
        -> ScanConfig
        -> PreparedScan
        -> ScanOrchestrator
        -> ExecutionPlan
        -> Preflight readiness
        -> initial Context
        -> Pipeline runtime
        -> ScanResult
```

Syntactic acceptance by `ScanTarget` and application approval in `ScanScope`
do not prove ownership or legal permission. The caller remains responsible for
authorization.

Execution planning is capability- and state-driven.

External tool identities do not appear in execution plans.

## Composition and closure

`CapabilityRegistry` holds immutable definitions only.
`CapabilityFactoryRegistry` holds one lazy factory for each default
capability IDs. `ExecutionPlanner` expands a requested state through unique
producers, and `PipelineBuilder` creates one fresh capability for each plan
step. `PlannedExecution` delegates the resulting pipeline to the existing
sequential runtime.

Asset Intelligence explicitly requires the subdomain, host, responsive-host,
crawler-endpoint, and technology states it correlates. These inputs share the
same reconnaissance closure and do not cause duplicate capability execution.

Requesting `RISK_INTELLIGENCE` from an empty state produces this deterministic
closure:

```text
subdomain_discovery
host_resolution
http_probe
web_crawl
technology_detection
asset_intelligence
vulnerability_intelligence
knowledge_graph
risk_intelligence
```

That existing risk closure is intentionally unchanged. Requesting
`ENRICHED_VULNERABILITIES` instead derives the separate detection closure:

```text
subdomain_discovery
host_resolution
http_probe
vulnerability_detection
finding_correlation
vulnerability_enrichment
```

The default tool registry independently contains `subfinder`, `httpx`,
`katana`, `whatweb`, and the architecture-only `nuclei` definition. Those
identities select replaceable adapters; they are
not capabilities. Registry, factory, planner, and builder construction performs
no process execution, availability probe, or network access.

## State contracts

The canonical runtime values are:

| State | Producer | Immutable value |
| --- | --- | --- |
| `SUBDOMAINS` | `subdomain_discovery` | `SubdomainDiscoveryResult` with tuple findings |
| `HOSTS` | `host_resolution` | `HostResolution` |
| `ALIVE_HOSTS` | `http_probe` | tuple of `Host` |
| `HTTP_ENDPOINTS` | `http_probe` | tuple of `HttpProbeEndpoint` |
| `VULNERABILITIES` | `vulnerability_detection` | `FindingRecordCollection` |
| `CANONICAL_FINDINGS` | `finding_correlation` | `CanonicalFindingCollection` |
| `ENRICHED_VULNERABILITIES` | `vulnerability_enrichment` | `EnrichedCanonicalFindingCollection` |
| `ENDPOINTS` | `web_crawl` | tuple of `Endpoint` |
| `TECHNOLOGIES` | `technology_detection` | tuple of `Technology` |
| `ASSET_INTELLIGENCE` | `asset_intelligence` | `AssetIntelligence` |
| `VULNERABILITY_INTELLIGENCE` | `vulnerability_intelligence` | `VulnerabilityIntelligence` |
| `KNOWLEDGE_GRAPH` | `knowledge_graph` | `KnowledgeGraph` |
| `RISK_INTELLIGENCE` | `risk_intelligence` | `RiskIntelligence` |

Every value is validated before publication. `http_probe` is one plan step,
one provider call, and one history entry even though it provides two states.
Both values are validated before either is committed to Context.

## Runtime outcomes

Runtime precedence is:

```text
ERROR > FAILURE > PARTIAL > SUCCESS
```

`SUCCESS` publishes and continues. `PARTIAL` publishes usable evidence,
continues, and remains visible in the aggregate result. `FAILURE` and `ERROR`
publish nothing for the failing capability and stop the remaining plan.
History is an immutable ordered tuple with one typed `CapabilityId` entry per
attempted capability; skipped steps create no entries.

A clean empty subdomain result still runs the structural plan, but every later
external provider is skipped because it has no input work. The runtime
publishes canonical empty host, endpoint, technology, vulnerability, graph, and
risk values and returns `SUCCESS`. This is a deterministic no-findings result,
not an infrastructure failure.

## Deterministic testing and current boundary

The complete test composition injects in-memory providers for subdomains, DNS,
HTTP probing, crawling, technology detection, and vulnerability data. It uses
the production registry, planner, builder, facade, runtime, and intelligence
capabilities, and produces a deterministic risk assessment without network,
subprocess, external binaries, credentials, or live targets.

RedForge remains a library runtime beneath a thin [minimal CLI](cli.md). The
[application orchestrator](application-orchestration.md) owns one-shot
execution of a validated config through this runtime. The
[typed configuration](configuration.md) layer owns strict TOML parsing and
pure translation; the CLI owns argv overrides and result rendering, while
`ApplicationComposition` owns all wiring.
An execution-scoped [diagnostic sink](observability.md) may observe bounded
phase, capability-status, and policy summaries. It never receives Context
state or evidence, and sink failure cannot affect this pipeline.
Human output is the default; deterministic
[schema-versioned JSON](json-output.md) is an alternate bounded renderer over
the same typed application outcome.
Authorization decisions remain the operator's responsibility. Configuration
files never contain the target, provider credentials, executable paths, or
provider bindings. Long-running orchestration, scheduling, persistence,
retries, parallel execution, dynamic replanning, limit-driven tool flags,
forceful cancellation, and report export remain outside the boundary.
Canonical publication limits
and safe step-boundary deadlines are described in
[Scan Limits](scan-limits.md).

Before Context creation, application
[preflight](preflight-readiness.md) checks only the factories, tool
definitions, executables, and provider roles derived from the prepared plan.
It does not probe the target or predict runtime success.

An execution-free [dry run](dry-run.md) stops after this preflight boundary.
Its [toolchain manifest](toolchain.md) describes the same five-capability
reconnaissance closure and four external tools without constructing the
pipeline, creating `Context`, resolving hosts, executing tools, or publishing
state. The first controlled authorized real-tool smoke run remains a separate
operation from dry run and has now completed successfully at the infrastructure
level. Its final status was an explainable `PARTIAL`, not a clean `SUCCESS`.
