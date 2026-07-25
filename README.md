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
