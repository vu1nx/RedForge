# State Publication

One RedForge capability execution may publish zero, one, or multiple typed
pipeline state values:

```text
CapabilityResult
      |
      v
StatePublication[]
      |
      v
Validation
      |
  +---+---+
  |       |
STATE X STATE Y
  |       |
  +---+---+
      |
      v
Pipeline Context
```

The planner declares which state keys a capability may provide.
The runtime validates which state keys the capability actually publishes.

## Explicit publications

`StatePublication` is a frozen, slotted value containing a canonical
`PipelineStateKey` and its value. `Result.publications` is an immutable tuple.
Caller iterables are copied to a tuple, malformed elements and duplicate keys
are rejected, and publication order is preserved.

Canonical correlation and enrichment use the same boundary:
`CANONICAL_FINDINGS` accepts only `CanonicalFindingCollection`, while
`ENRICHED_VULNERABILITIES` accepts only
`EnrichedCanonicalFindingCollection`. Raw lists, tuples, dictionaries, and
provider response objects are invalid state values.

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

Explicit publications are checked against the pipeline's immutable output
contract. For planned execution this contract comes directly from the
Capability Registry v2 definition. Every published key must be declared, but a
result may publish a subset. Missing declared keys are not populated with
placeholders and do not change the capability-selected status.

The complete publication batch is validated before `Context` changes. Duplicate
keys, undeclared keys, malformed publications, or a conflict between explicit
publications and non-`None` legacy `data` produce one sanitized runtime `ERROR`.
Nothing from that capability is published and downstream execution stops.

## Status and history

`SUCCESS` and `PARTIAL` explicit publications are applied atomically and
execution continues. `FAILURE` and `ERROR` must not contain explicit
publications; if they do, the result is invalid and becomes a sanitized runtime
`ERROR`. Legacy diagnostic `data` on stopping results remains non-published for
compatibility.

Execution history remains capability-based. A capability that publishes three
states still creates one `CapabilityExecution`, and `last_result` is its full
result. Publication count does not affect status aggregation.

## Legacy compatibility

Existing capabilities continue returning `Result(status=..., data=value)`.
When the capability has exactly one declared output, the runtime normalizes
that data to one publication. A legacy result for a multi-output contract is
ambiguous and fails safely; the runtime never selects the first declared key.
`None` without explicit publications means no state publication.

Manual pipelines may configure typed identity and multi-output declarations
without using the planner:

```python
from redforge.planning import CapabilityId

pipeline.add(
    capability,
    capability_id=CapabilityId("custom_capability"),
    provides=(
        PipelineStateKey.HOSTS,
        PipelineStateKey.SUBDOMAINS,
    ),
)
```

The older `output_keys={"name": key}` constructor argument remains available
for single-output callers. Unconfigured custom legacy capabilities retain the
previous capability-name fallback.

## Context batches

`Context.publish()` and `Context.publish_many()` validate before mutation.
Empty batches are valid. Duplicate keys within one batch are rejected
atomically. Publishing a key that existed before the execution replaces its
value, preserving the runtime's previous latest-output-wins behavior.
