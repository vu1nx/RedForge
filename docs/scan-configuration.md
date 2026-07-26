# Scan Configuration

RedForge exposes a provider-neutral application boundary for accepting scan
intent before any capability, provider, network operation, or process is
constructed:

```text
Raw application input
        |
        v
ScanTarget
        |
        v
ScanScope
        |
        v
ScanConfig
        |
        v
Plan preparation
        |
        v
ExecutionPlan + initial Context
```

`ScanConfig` contains application intent and authorization policy.

It does not contain tool identities, executable options, providers, or runtime
state.

## Target and authorization boundary

`ScanTarget` currently supports exactly one DNS root domain. Construction
lowercases and IDNA-normalizes the name, removes one trailing root dot, and
validates DNS label and total-length rules. URLs, schemes, credentials, ports,
paths, queries, fragments, wildcards, IP addresses, whitespace, and control
characters are rejected.

`ScanScope` authorizes the exact root and label-boundary subdomains. For
`example.com`, `api.example.com` is in scope while `notexample.com` and
`example.com.attacker.test` are not. Matching performs no DNS lookup or network
access.

Application acceptance has a deliberately narrow meaning:

> ScanConfig proves that the application has accepted a target as authorized
> input. It does not independently prove legal ownership or permission.

The caller remains responsible for obtaining authorization. RedForge performs
no WHOIS, DNS challenge, HTTP challenge, certificate inference, or external
authorization check.

## Endpoint scope

`ScanScope.contains_endpoint()` accepts only HTTP or HTTPS `Endpoint` values
whose canonical DNS hostname is the root or a true subdomain. Ports, paths, and
queries cannot widen scope. Credentials, unrelated redirects represented as
new endpoints, suffix-confusion names, IPv4, IPv6, and unsupported protocols
are rejected for this DNS-only policy.

This application policy complements existing adapter filtering. Subfinder,
HTTPX, Katana, and WhatWeb retain their exact provider-specific output
validation and do not import `ScanScope`.

## Requested outputs and presets

Requested outputs are a non-empty, deterministic tuple of typed
`PipelineStateKey` values. Application-facing outputs are:

- `ENDPOINTS`;
- `TECHNOLOGIES`;
- `ASSET_INTELLIGENCE`;
- `VULNERABILITY_INTELLIGENCE`;
- `KNOWLEDGE_GRAPH`;
- `RISK_INTELLIGENCE`.

Intermediate host and probe states are intentionally not accepted as
application scan products. Duplicate and string state keys are rejected.
Dependencies are never hidden in the preset:

- `ScanConfig.for_reconnaissance(target)` requests `TECHNOLOGIES`;
- `ScanConfig.for_full_assessment(target)` requests `RISK_INTELLIGENCE`.

`ExecutionPlanner` derives the capability closure in both cases.

## Capability policy

`disabled_capabilities` is an immutable, ordered tuple of typed
`CapabilityId` values. During `prepare_scan()`:

1. the complete requested plan is derived from the supplied definition
   registry;
2. any required disabled capability raises `DisabledCapabilityError`;
3. unrelated disabled definitions are removed into a new local registry;
4. the requested output is planned again against that filtered metadata.

Failure occurs before factories, capabilities, providers, Context mutation, or
tool execution. There is no alternate-provider selection, implicit
re-enabling, or dynamic replanning.

## Limits and partial-result policy

`ScanLimits` contains bounded positive application limits for subdomains,
hosts, responsive hosts, HTTP endpoints, crawler endpoints, technology
evidence, and overall elapsed execution time. Defaults are conservative and
hard maxima reject excessive values.

These values constrain future orchestration and evidence admission. Existing
adapters retain their independently accepted safety bounds. This milestone
does not duplicate adapter flags or add inconsistent slicing to capabilities.

`allow_partial_results` records whether the application may accept a final
`PARTIAL` result. It is a future post-execution orchestration decision and does
not alter runtime status precedence or publication.

## Preparation and Context seeding

```python
from redforge.application import (
    ScanConfig,
    create_initial_context,
    prepare_scan,
)
from redforge.planning import create_default_registry

config = ScanConfig.for_reconnaissance("example.com")
prepared = prepare_scan(
    config=config,
    registry=create_default_registry(),
)
context = create_initial_context(config)
```

`PreparedScan` contains the normalized configuration, immutable
`ExecutionPlan`, and allowed capability IDs. It contains no registry, factory,
capability instance, provider, runner, pipeline, or Context.

`create_initial_context()` copies only the canonical DNS target into
`Context.target_id`. Limits, requested outputs, disabled capabilities, and tool
configuration are not stored in Context.

## Current boundary

There is no CLI, interactive input, configuration-file loader,
environment-variable loader, orchestration service, persistence, retry,
caching, report export, provider installation, or real scan execution in this
contract. Future orchestration may enforce application evidence limits and
evaluate the partial-result policy while continuing to use the unchanged
planner, builder, runtime, and adapters.
