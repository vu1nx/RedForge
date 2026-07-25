# Capability Registry v2

Capability Registry v2 is the canonical source of stable capability identity
and implementation-independent execution metadata.

```text
CapabilityDefinition Registry
        |
        +--> ExecutionPlanner
        |
        +--> PipelineBuilder
        |
        +--> Runtime Output Contract

CapabilityFactory Registry
        |
        +--> Runtime Instances
```

Definitions describe what a capability is allowed to require and provide.
Factories describe how a runtime implementation is constructed.

## Typed identity

`CapabilityId` is a frozen, slotted, ordered value object. Its serialized
`value` is lowercase snake case, such as `http_probe`. Built-in constants
preserve every existing capability name, while applications can create
validated custom IDs:

```python
from redforge.planning import CapabilityId

custom_id = CapabilityId("custom_discovery")
```

Identity is independent of implementation class name, display label, adapter,
or external-tool version. String input remains accepted at migration
boundaries, but plans, registries, factories, and planned pipelines normalize
it immediately to `CapabilityId`.

## Definitions

`CapabilityDefinition` is immutable and contains:

- `capability_id`
- deterministically ordered `requires` and `provides`
- `display_name`
- `description`
- contract `version`
- normalized immutable `tags`

Version `1.0` describes the RedForge capability contract. It is not an
external-tool or Python-package version and does not participate in dependency
resolution. Tags are descriptive query metadata; they do not influence
planning, ordering, or execution.

The built-in definitions live in one immutable tuple. The default definition
registry, planner, builder, and legacy manual output-contract view all derive
from that tuple, avoiding a second hand-maintained output mapping.

`CapabilityDescriptor` remains a compatibility alias. Its legacy `name=`
constructor and canonical string state keys are strictly normalized. New code
should use `CapabilityDefinition` and typed IDs.

## Definition registry

`CapabilityRegistry` is mutation-controlled during setup and never exposes its
internal mapping. Its read APIs return deterministic tuples:

```python
definitions.get(custom_id)       # definition or None
definitions.require(custom_id)   # definition or focused error
definitions.contains(custom_id)
definitions.all()
definitions.ids()
definitions.by_tag("recon")
definitions.producers_for(PipelineStateKey.HOSTS)
```

Multiple producers remain representable. The planner retains its existing
responsibility to reject ambiguous dependency expansion; the registry does not
select a preferred producer.

## Factories

`CapabilityFactoryRegistry` is deliberately separate. It maps typed IDs to lazy
callables and produces a fresh runtime capability per build. Definitions never
contain factories, adapters, or runtime objects.

`validate_against()` rejects factory identities absent from the definition
registry. Instance identity is validated against the registered ID during
creation, before pipeline execution. Factory exceptions and invalid objects
remain sanitized.

## Planner, builder, and runtime

`ExecutionStep.capability_id` is typed. Plans contain no factory, capability,
Context, or adapter. The builder resolves each step through both registries,
checks its complete static definition, creates one instance, and passes
`definition.provides` to the pipeline as the runtime output contract.
Multi-output definitions still create one plan step and one capability
execution.

Planned and explicitly configured manual pipelines associate runtime instances
with typed IDs. Runtime does not derive planned identity from a class name.
Execution history retains the human-compatible capability name and also records
the typed ID when explicitly configured.

## Manual compatibility

New manual integrations can configure identity and outputs without constructing
a planner:

```python
pipeline.add(
    capability,
    capability_id=custom_id,
    provides=(PipelineStateKey.SUBDOMAINS,),
)
```

The previous `output_keys` constructor remains available. An unconfigured
legacy manual capability may still publish `Result.data` under its `.name`;
this deprecated fallback is isolated in the runtime normalization boundary.
Planned pipelines and explicitly configured manual pipelines never depend on
it.

## Capability identity versus tool identity

Capabilities model security responsibilities. Tools are replaceable execution
providers. `CapabilityDefinition` therefore never contains an executable,
`ToolDefinition`, or runner. A future adapter may select one or several
registered `ToolId` values while continuing to implement the same capability
contract. See [External Tool Execution](tool-execution.md).
