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
from redforge.domain.knowledge_graph import KnowledgeGraph
from redforge.planning import create_default_planned_execution
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.context import Context

context = Context(
    target_id="example.com",
    state={PipelineStateKey.KNOWLEDGE_GRAPH: KnowledgeGraph()},
)
execution = create_default_planned_execution()
plan = execution.plan(
    goals=(PipelineStateKey.RISK_INTELLIGENCE,),
    context=context,
)
result = execution.execute(plan=plan, context=context)

assert plan.required_capabilities == ("risk_intelligence",)
assert result.executed_capabilities == ("risk_intelligence",)
```

Construction performs no external I/O. Inject `CapabilityDependencies` with
fake typed ports for deterministic tests.

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
result = provider.discover("example.com")
```

This example uses a documentation-only placeholder target. RedForge does not
install Subfinder or configure its provider credentials. See
[Subfinder Passive Recon Integration](docs/subfinder-integration.md).

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

## License

MIT License - see [LICENSE](LICENSE) for details.
