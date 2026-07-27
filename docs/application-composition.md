# Application Composition

`ApplicationComposition` is RedForge's explicit immutable composition root. It
turns one deterministic profile and optional provider-neutral substitutions
into a fresh, ready-to-use `ScanOrchestrator`:

```text
CompositionProfile
        +
explicit port substitutions
        |
        v
ApplicationComposition
        |
        +-- CapabilityRegistry
        +-- profile-scoped CapabilityFactoryRegistry
        +-- required ToolRegistry definitions
        +-- ReadinessRegistry and probes
        +-- execution-scoped DiagnosticEventSink
        |
        v
ScanOrchestrator
```

Composition owns object wiring only. Target validation, preparation, planning,
preflight decisions, capability execution, state publication, limits,
acceptance, and rendering remain in their existing layers.

## Profiles

Profiles are explicit `CompositionProfile` enum values. A validated
[typed configuration](configuration.md) may select the profile, but composition
never parses files. There is no auto-detection, environment lookup,
configuration-file discovery, or mutable global default.

`reconnaissance` registers only:

```text
subdomain_discovery
host_resolution
http_probe
web_crawl
technology_detection
```

`full_assessment` adds:

```text
asset_intelligence
vulnerability_intelligence
knowledge_graph
risk_intelligence
```

The full profile deliberately does not create a vulnerability provider.
Composition still succeeds; a full scan's accepted preflight reports the
missing provider configuration as not ready before Context creation or
capability construction.

## Construction and isolation

```python
from redforge.composition import (
    ApplicationComposition,
    CompositionProfile,
)

composition = ApplicationComposition(
    CompositionProfile.RECONNAISSANCE
)
orchestrator = composition.create_orchestrator()
```

Each `create_orchestrator()` call creates fresh registries and readiness
coordination. Capability factories remain lazy, and importing the composition
package constructs no runner, adapter, registry, provider, or probe and performs
no PATH inspection, subprocess execution, or network access.

An optional provider-neutral `DiagnosticEventSink` is wired into the
orchestrator and runtime for that composition only. The default null sink is
silent. Composition does not configure Python logging or retain global
cross-scan diagnostic state. See [Structured Observability](observability.md).

The default local profile resolves a `LocalSubprocessToolRunner` only while
creating an orchestrator that actually requires tool-backed providers. It does
not execute a tool or inspect availability at construction time; accepted
preflight performs the static readiness checks later.

## Offline substitution

Tests and other application hosts may supply immutable
`CompositionProviders`, a `ToolRunner`, a tool-readiness probe, explicit
provider implementations, and deterministic provider-readiness probes:

```python
composition = ApplicationComposition(
    CompositionProfile.FULL_ASSESSMENT,
    providers=offline_providers,
    tool_runner=offline_tool_runner,
    tool_readiness_probe=offline_tool_probe,
    provider_readiness_probes=offline_provider_probes,
)
```

No deep monkeypatching, service locator, dependency-injection container, fake
production fallback, or global registration is required. The CLI selects a
profile and receives only the resulting application orchestrator; it does not
construct or receive concrete adapters.

## Current boundary

This framework does not load TOML, credentials, environment values, plugins,
or provider modules dynamically. The configuration layer returns only the
typed profile and application inputs; it does not construct this composition
root. Composition provides no persistence, reports, retry, resume, scheduling,
concurrency, caching, or long-lived container lifetime. Explicit provider
binding remains the responsibility of the application host.
