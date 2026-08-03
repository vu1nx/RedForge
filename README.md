# RedForge

A production-ready Python framework.

## Installation

```bash
pip install redforge
```

## Development

```bash
# Install in development mode
pip install -e .

# Run tests
pytest

# Run linting
ruff check .

# Run type checking
pyright
```

## Execution Contract

The sequential runtime preserves aggregate capability status, immutable
execution history, usable state propagation, and sanitized error boundaries.
See [Execution Contract](docs/execution-contract.md) for status precedence,
continuation rules, and defensive runtime behavior.

## Planned Execution

RedForge can deterministically plan goals, build fresh capability instances
through explicit factories, and execute them through the existing sequential
runtime. See [Execution Planning and Runtime Integration](docs/execution-planner.md).

```python
from redforge.planning import (
    ExecutionPlanner,
    PipelineBuilder,
    PlannedExecution,
    create_default_factory_registry,
    create_default_registry,
)
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.context import Context

# `dependencies` is supplied by the application with authorized providers,
# or with deterministic fakes in tests.
definitions = create_default_registry()
factories = create_default_factory_registry(dependencies=dependencies)
planner = ExecutionPlanner(definitions)
builder = PipelineBuilder(
    descriptor_registry=definitions,
    factory_registry=factories,
)
execution = PlannedExecution(planner=planner, builder=builder)

context = Context(target_id="authorized.example")
plan = execution.plan(
    goals=(PipelineStateKey.RISK_INTELLIGENCE,),
    context=context,
)
pipeline = execution.build(plan)
result = pipeline.run(context)

final_risk = result.context.get(PipelineStateKey.RISK_INTELLIGENCE)
history = result.executions
```

Construction performs no external I/O. Inject `CapabilityDependencies` with
authorized typed providers for real runs or fake typed ports for deterministic
tests. RedForge does not install external tools automatically. See the
[End-to-End Pipeline](docs/end-to-end-pipeline.md) for the complete state graph,
empty-result behavior, and failure boundaries.

## Toolchain Inspection

Before any separately authorized real-tool run, inspect the actual
reconnaissance plan and static readiness without creating runtime state:

```text
redforge scan authorized.example --dry-run
redforge scan authorized.example --dry-run --output json
```

Dry run validates the target and configuration, derives the plan and immutable
toolchain manifest, and performs non-executing readiness checks. It does not
create a `Context`, execute a capability or external tool, resolve DNS, access
a network target, or publish state. The reconnaissance closure requires
`subfinder`, `httpx`, `katana`, and `whatweb`; RedForge does not install or
update them. See [Reconnaissance Toolchain](docs/toolchain.md) and
[Dry Run](docs/dry-run.md).

## Scan Configuration

Applications can validate one explicitly authorized DNS-root target and prepare
state-driven planner input without constructing capabilities or executing
providers:

```python
from redforge.application import (
    ScanConfig,
    create_initial_context,
    prepare_scan,
)
from redforge.planning import create_default_registry

# Documentation-only placeholder: the caller remains responsible for permission.
config = ScanConfig.for_full_assessment("authorized.example")
prepared = prepare_scan(
    config=config,
    registry=create_default_registry(),
)
context = create_initial_context(config)

assert prepared.plan.goals == config.requested_outputs
assert context.target_id == "authorized.example"
```

`ScanConfig` contains application intent and authorization policy. It does not
contain tool identities, executable options, providers, or runtime state.
See [Scan Configuration](docs/scan-configuration.md).

## Application Orchestration

`ScanOrchestrator` connects validated application intent to the existing
planner, factory, builder, Context, and runtime contracts:

```python
from redforge.application import (
    ReadinessRegistry,
    ScanConfig,
    ScanLimits,
    ScanOrchestrator,
    ScanPreflightError,
)
from redforge.planning import create_default_registry
from redforge.sdk import ToolRegistry

# The caller supplies factories configured with authorized production
# providers or deterministic offline fakes.
orchestrator = ScanOrchestrator(
    capability_registry=create_default_registry(),
    factory_registry=factories,
    readiness_registry=ReadinessRegistry(
        tool_registry=ToolRegistry(caller_tool_definitions),
        tool_probe=caller_tool_readiness_probe,
        provider_probes=caller_provider_readiness_probes,
    ),
)
try:
    result = orchestrator.run(
        ScanConfig.for_full_assessment(
            "authorized.example",
            limits=ScanLimits(
                max_subdomains=1_000,
                max_crawl_endpoints=10_000,
                overall_timeout_seconds=1_800,
            ),
        )
    )
except ScanPreflightError as error:
    readiness_checks = error.result.checks
    raise

runtime_status = result.runtime_status
accepted_by_policy = result.accepted
limit_or_deadline_failure = result.policy_violation
```

The example does not verify legal permission and does not provide hidden
network or tool composition. See
[Application Scan Orchestration](docs/application-orchestration.md) and
[Scan Limits](docs/scan-limits.md). Composition readiness is documented in
[Preflight Readiness](docs/preflight-readiness.md).

## Application Composition

Application hosts now select an explicit immutable composition profile and
receive a ready-to-use `ScanOrchestrator`:

```python
from redforge.composition import (
    ApplicationComposition,
    CompositionProfile,
)

orchestrator = ApplicationComposition(
    CompositionProfile.RECONNAISSANCE
).create_orchestrator()
```

The reconnaissance profile contains only its five required capabilities. The
full-assessment profile contains the complete graph but deliberately supplies
no hidden vulnerability provider, so readiness reports that missing
configuration honestly. The CLI delegates all registry, factory, runner, and
probe wiring to this framework. See
[Application Composition](docs/application-composition.md).

## Capability Registry

Typed capability definitions are the shared source for planning metadata and
planned runtime output contracts. Factories remain separate and lazy.

```python
from redforge.planning import (
    CapabilityDefinition,
    CapabilityFactoryRegistry,
    CapabilityId,
    CapabilityRegistry,
)
from redforge.sdk import PipelineStateKey

custom_id = CapabilityId("custom_discovery")
definition = CapabilityDefinition(
    capability_id=custom_id,
    display_name="Custom Discovery",
    description="Discovers custom asset records.",
    version="1.0",
    provides=(PipelineStateKey.SUBDOMAINS,),
    tags=("passive", "recon"),
)
definitions = CapabilityRegistry((definition,))
factories = CapabilityFactoryRegistry()
factories.register(custom_id, CustomDiscoveryCapability)
```

`CustomDiscoveryCapability` is an application-defined `Capability` whose
stable `name` is `custom_discovery`. See
[Capability Registry v2](docs/capability-registry.md) for queries, default
definitions, factory alignment, and legacy migration.

## External Tool Execution

The external-tool framework provides a typed runner boundary with literal argv,
explicit timeouts, bounded captured output, and a minimal environment policy
for new provider integrations. Capabilities and planners do not invoke
subprocesses.

```python
import sys

from redforge.adapters import LocalSubprocessToolRunner
from redforge.sdk import ToolDefinition, ToolId, ToolInvocation

definition = ToolDefinition(
    tool_id=ToolId("example_tool"),
    display_name="Example Tool",
    description="Portable external process example.",
    executable=sys.executable,
    default_timeout_seconds=10,
)
invocation = ToolInvocation(
    tool_id=definition.tool_id,
    arguments=("-c", "print('hello')"),
)
result = LocalSubprocessToolRunner().run(definition, invocation)
```

Arguments remain separate process values; the local runner never invokes a
shell. See [External Tool Execution](docs/tool-execution.md) for environment,
diagnostic, truncation, adapter-mapping, and testing policies.

### Subfinder passive discovery

Subfinder is the default replaceable provider for the
`subdomain_discovery` capability. It uses the tool-runner boundary; it is not a
capability identity or an additional planner step.

```python
from redforge.adapters import (
    SUBFINDER_TOOL,
    LocalSubprocessToolRunner,
    SubfinderConfig,
    SubfinderSubdomainProvider,
)

provider = SubfinderSubdomainProvider(
    runner=LocalSubprocessToolRunner(),
    definition=SUBFINDER_TOOL,
    config=SubfinderConfig(),
)
result = provider.discover("authorized.example")
```

This example uses a documentation-only placeholder target. RedForge does not
install Subfinder or configure its provider credentials. See
[Subfinder Passive Recon Integration](docs/subfinder-integration.md).

### HTTPX web-service probing

HTTPX is the default replaceable provider for the `http_probe` capability. It
consumes resolved hosts through bounded stdin and returns normalized HTTP
response evidence without becoming a capability identity or planner step.

```python
from ipaddress import IPv4Address

from redforge.adapters import (
    HTTPX_TOOL,
    HttpxConfig,
    HttpxProbeProvider,
    LocalSubprocessToolRunner,
)
from redforge.domain.host import Host

provider = HttpxProbeProvider(
    runner=LocalSubprocessToolRunner(),
    definition=HTTPX_TOOL,
    config=HttpxConfig(),
)
resolved_hosts = (
    Host(
        hostname="api.authorized.example",
        address=IPv4Address("192.0.2.10"),
    ),
)
result = provider.probe(resolved_hosts)
```

The domain and address are documentation-only placeholders. RedForge does not
install HTTPX or add credentials, headers, cookies, or proxy configuration.
See [HTTPX Web Probe Integration](docs/httpx-integration.md).

The `http_probe` capability atomically publishes both responsive hosts and
typed service evidence. The crawler's `ENDPOINTS` state remains a separate
contract for discovered paths and resources.

```python
from redforge.sdk import PipelineStateKey

pipeline_result = pipeline.run(context)
alive_hosts = pipeline_result.context.get(PipelineStateKey.ALIVE_HOSTS)
http_endpoints = pipeline_result.context.get(
    PipelineStateKey.HTTP_ENDPOINTS
)
```

Both values are immutable tuples. Endpoint bodies and raw headers are not
retained.

### Katana web crawling

Katana is the default replaceable provider for the `web_crawl` capability. It
uses the same external-tool runner boundary as Subfinder and HTTPX and remains
separate from the capability identity and execution plan.

```python
from redforge.adapters import (
    KATANA_TOOL,
    KatanaConfig,
    KatanaWebCrawlProvider,
    LocalSubprocessToolRunner,
)
from redforge.domain import Host

provider = KatanaWebCrawlProvider(
    runner=LocalSubprocessToolRunner(),
    definition=KATANA_TOOL,
    config=KatanaConfig(),
)
result = provider.crawl((Host(hostname="app.authorized.example"),))
```

The target is a documentation-only placeholder. RedForge does not install
Katana or configure credentials. See
[Katana Web Crawl Integration](docs/katana-integration.md).

### WhatWeb technology detection

WhatWeb is the default replaceable provider for the `technology_detection`
capability. The capability consumes crawler `ENDPOINTS`; WhatWeb remains a
separate tool identity and never appears in an execution plan.

```python
from redforge.adapters import (
    WHATWEB_TOOL,
    LocalSubprocessToolRunner,
    WhatWebConfig,
    WhatWebTechnologyDetectionProvider,
)
from redforge.domain import Endpoint

provider = WhatWebTechnologyDetectionProvider(
    runner=LocalSubprocessToolRunner(),
    definition=WHATWEB_TOOL,
    config=WhatWebConfig(),
)
result = provider.detect(
    (Endpoint("app.authorized.example", 443, "https", "/"),)
)
```

The endpoint is a documentation-only placeholder. RedForge does not install
WhatWeb, probe its version during composition, or configure authentication.
See [WhatWeb Technology Detection Integration](docs/technology-detection-integration.md).

## Multi-Output State

A capability may publish several typed state values from one execution. The
runtime validates the complete batch against its declared output contract and
updates Context atomically. One execution remains one history entry.

```python
from redforge.sdk import PipelineStateKey, Result, StatePublication, Status

result = Result[None](
    status=Status.SUCCESS,
    data=None,
    publications=(
        StatePublication(PipelineStateKey.HOSTS, resolved_hosts),
        StatePublication(PipelineStateKey.SUBDOMAINS, discovered_names),
    ),
)
```

Existing single-output capabilities may continue using `Result.data`. See
[State Publication](docs/state-publication.md) for explicit publications,
legacy normalization, subsets, and atomic rejection behavior.

## Adapter Boundaries

External capabilities depend on focused typed ports and consume immutable,
domain-safe adapter results. Concrete adapters own transport/provider parsing
and sanitize external failures. See
[Adapter Boundaries](docs/adapter-boundaries.md).

## Host Resolution

TASK-0017 normalizes discovered hostname strings and resolves them into
immutable, deterministic IPv4/IPv6 Host identities before HTTP probing. See
[Host Resolution](docs/host-resolution.md) for input validation, resolver
abstraction, status semantics, and current DNS limitations.

## Vulnerability Intelligence

TASK-0013 correlates asset-associated technology observations with NVD CPE and
CVE API 2.0 data using conservative exact matching. See
[Vulnerability Intelligence](docs/vulnerability-intelligence.md) for API-key
configuration, NVD attribution and limits, matching behavior, and current
limitations.

## Security Knowledge Graph

TASK-0014 transforms explicit Asset and Vulnerability Intelligence
relationships into a deterministic immutable graph snapshot. See
[Security Knowledge Graph](docs/knowledge-graph.md) for identity semantics,
relationship policy, and current non-goals.

## Risk Intelligence

TASK-0015 transforms explicit Asset-to-Technology-to-Vulnerability graph paths
into deterministic, explainable investigation priorities. It does not infer
compromise or predict exploitability. Priority uses CVSS or qualitative severity
fallback without double counting; evidence confidence, data completeness, and
endpoint presence remain separate and never change priority. See
[Risk Intelligence](docs/risk-intelligence.md) for the scoring contract,
uncertainty handling, identity semantics, and limitations.

## Minimal CLI

The application-facing CLI validates a canonical DNS target, applies a
reconnaissance or full preset, performs readiness preflight, and delegates one
run to the existing application orchestrator:

```text
redforge scan authorized.example
redforge scan authorized.example --preset full --allow-partial-results
redforge scan authorized.example --config redforge.toml
redforge scan authorized.example --log-level info
python -m redforge.cli scan --help
```

Only scan systems you are explicitly authorized to assess. One explicit
schema-versioned TOML document may select typed scan, composition, limit, and
output values; the target remains CLI-only. Explicit CLI values override file
values, which override application defaults. There is no environment override
or implicit file discovery. See
[Typed Configuration](docs/configuration.md) and
[Minimal CLI](docs/cli.md).

An isolated [Controlled Local Smoke Test](docs/local-smoke-test.md) profile
preserves one exact loopback HTTP origin, uses network-free seed discovery and
static resolution, and fail-closes HTTPX, Katana, and WhatWeb to that origin.
It remains separate from production Subfinder-backed reconnaissance.

Structured lifecycle diagnostics are silent by default. An explicit log level
emits bounded JSON events to stderr without changing the human summary or the
single JSON outcome on stdout. Diagnostics contain no evidence, process
output, environment values, executable paths, credentials, or exception text.
See [Structured Observability](docs/observability.md).

Human output is the default. Automation can request one versioned, sanitized
JSON summary on stdout:

```text
redforge scan authorized.example --output json
```

The exit code remains authoritative. JSON output does not contain evidence and
does not create a report file. See
[Deterministic JSON Output](docs/json-output.md) for schema version 1.

## Platform readiness

Kali Linux is the primary supported external-tool execution platform. Other
Linux distributions are best effort, Windows supports development and offline
validation, and macOS currently has library-level compatibility. See
[Kali Linux Platform Policy](docs/kali-platform.md).

```text
redforge doctor
redforge doctor --profile reconnaissance
redforge doctor --profile full_assessment
redforge doctor --output json
```

Doctor accepts no target and performs no scan, DNS lookup, network request,
installation, or remediation. See [RedForge Doctor](docs/doctor.md).

## License

MIT License - see [LICENSE](LICENSE) for details.
