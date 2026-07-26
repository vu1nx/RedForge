# Execution Planning and Runtime Integration

RedForge separates structural planning, capability construction, and execution:

```text
Goals + Context
      |
      v
ExecutionPlanner
      |
      v
ExecutionPlan
      |
      v
PipelineBuilder
      |
      v
Pipeline
      |
      v
PipelineResult
```

The planner does not execute capabilities.
The builder does not execute capabilities.
The existing Pipeline runtime remains the execution authority.

## Planner

`CapabilityDefinition` declares one typed `CapabilityId`, immutable
required/provided state tuples, display metadata, contract version, and tags.
`CapabilityRegistry` stores definitions only; it never stores factories,
capabilities, adapters, or configuration. `CapabilityDescriptor` remains a
narrow legacy alias. See [Capability Registry v2](capability-registry.md).

`ExecutionPlanner` expands goals through unique producers and returns an
immutable, deterministic topological `ExecutionPlan`. Missing and ambiguous
producers and requested dependency cycles are rejected. Independent ready
steps use capability name as their tie-breaker. An already-available goal
produces an empty plan.

Planning validates structural satisfiability. It cannot predict runtime status.
A declared producer can make a downstream step structurally valid even though
the run may later stop.

## Factories and builder

`CapabilityFactoryRegistry` is a separate runtime construction registry. Each
typed capability ID has one explicit callable factory. Public IDs are immutable
and sorted; duplicates, unknown definitions, and missing factories are
rejected. Every invocation must produce a fresh `Capability` aligned with its
registered identity. Invalid objects, identity mismatches, and factory
exceptions fail before runtime execution, with sanitized integration errors.

Factories may close over explicit typed ports. `CapabilityDependencies`
supports the default `SubdomainProvider`, `HostResolver`,
`HttpProbeProvider`, `WebCrawler`, `TechnologyDetector`, and
`VulnerabilityProvider` injection points. Omitted ports retain the current
production constructors. Construction performs no network or subprocess
operation.

`PipelineBuilder` defensively checks a plan against its canonical descriptor
registry, factory registry, dependency order, and immutable output contracts.
Each contract contains the complete tuple from definition `provides`, including
multi-output descriptors. The builder creates one capability per step—not one
per output—in exact plan order and returns a fresh, unexecuted `Pipeline`.
Repeated builds do not reuse capability instances. Custom descriptor and
factory registries are supported without name branching inside the builder.

## Planned execution

`PlannedExecution` exposes three observable boundaries:

```python
plan = execution.plan(goals=goals, context=context)
pipeline = execution.build(plan)
result = execution.execute(plan=plan, context=context)
```

`run(goals=..., initial_context=...)` is the corresponding convenience method.
`plan()` derives availability from canonical keys actually present in
`Context.state`; value truthiness is irrelevant. A legitimate empty typed value
therefore counts as available. Planning does not mutate the context.

`execute()` builds a fresh pipeline and passes the caller's existing `Context`
to `Pipeline.run`. Existing state is retained and downstream capabilities see
newly published state in the same context. An empty plan returns `SUCCESS`,
empty execution history, `last_result=None`, and the original context.

At runtime, `SUCCESS` and `PARTIAL` publish data and continue. `FAILURE` and
`ERROR` do not publish data and stop remaining planned steps. Aggregate status
and one-entry-per-executed-capability history remain owned by `Pipeline`.
Planner steps that never execute are absent from history. There is no dynamic
replanning.

The planner treats all declared `provides` keys as structurally available after
a planned step. Runtime [state publication](state-publication.md) validates the
actual explicit subset. It does not dynamically change or re-plan the immutable
plan when a capability publishes fewer keys.

Capabilities may consume useful context state beyond their declared required
inputs. Asset Intelligence currently does this for optional enrichment state.
Optional state does not trigger producer insertion.

## Default graph

```text
subdomain_discovery -> SUBDOMAINS
SUBDOMAINS -> host_resolution -> HOSTS
HOSTS -> http_probe -> ALIVE_HOSTS
                  `-> HTTP_ENDPOINTS
ALIVE_HOSTS -> web_crawl -> ENDPOINTS
ENDPOINTS -> technology_detection -> TECHNOLOGIES

asset_intelligence -> ASSET_INTELLIGENCE
ASSET_INTELLIGENCE -> vulnerability_intelligence
    -> VULNERABILITY_INTELLIGENCE
ASSET_INTELLIGENCE + VULNERABILITY_INTELLIGENCE
    -> knowledge_graph -> KNOWLEDGE_GRAPH
KNOWLEDGE_GRAPH -> risk_intelligence -> RISK_INTELLIGENCE
```

`ALIVE_HOSTS` and `HTTP_ENDPOINTS` share the single `http_probe` producer.
Planning either or both outputs creates one capability step. `ENDPOINTS`
remains crawler path/resource evidence, so the crawl and technology-detection
dependency chain is unchanged.

Katana is only the default provider behind `web_crawl`. It is not a capability
or plan step. Replacing the provider does not change the graph, and
technology detection continues to depend on crawler `ENDPOINTS`.

`create_default_planned_execution()` assembles the default descriptor registry,
planner, factory registry, builder, and facade. Tests can supply
`CapabilityDependencies` with fake ports; no live network, DNS, or external
binary is needed.

Execution is sequential. Parallel branches, retries, fallback providers,
dynamic replanning, optional dependency syntax, persistence, and resume are
future concerns.
