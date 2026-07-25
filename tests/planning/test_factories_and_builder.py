"""Factory registry and defensive plan-to-pipeline builder tests."""

from collections.abc import Callable
from typing import Any

import pytest  # type: ignore[reportMissingImports]

from redforge.planning import (
    CapabilityDefinition,
    CapabilityDescriptor,
    CapabilityDescriptorMismatchError,
    CapabilityFactoryRegistry,
    CapabilityId,
    CapabilityRegistry,
    ExecutionPlanner,
    InvalidCapabilityFactoryError,
    MissingCapabilityFactoryError,
    PipelineBuilder,
    create_default_factory_registry,
    create_default_registry,
)
from redforge.runtime.pipeline_state import (
    CAPABILITY_OUTPUT_CONTRACTS,
    PipelineStateKey,
)
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, StatePublication, Status


class FakeCapability(Capability):
    """Small runtime capability with observable execution."""

    def __init__(
        self,
        name: str,
        data: object = None,
        calls: list[str] | None = None,
    ) -> None:
        self._name = name
        self._data = data
        self._calls = calls

    @property
    def name(self) -> str:
        return self._name

    def execute(self, context: Context) -> Result[Any]:  # noqa: ARG002
        if self._calls is not None:
            self._calls.append(self.name)
        return Result(status=Status.SUCCESS, data=self._data)


class MultiOutputCapability(Capability):
    """Publish two declared state values from one execution."""

    def __init__(self, instances: list["MultiOutputCapability"]) -> None:
        self.execute_calls = 0
        instances.append(self)

    @property
    def name(self) -> str:
        return "multi"

    def execute(self, context: Context) -> Result[None]:  # noqa: ARG002
        self.execute_calls += 1
        return Result(
            status=Status.SUCCESS,
            data=None,
            publications=(
                StatePublication(PipelineStateKey.HOSTS, ("host",)),
                StatePublication(PipelineStateKey.SUBDOMAINS, ("a.example",)),
            ),
        )


def _chain_registry() -> CapabilityRegistry:
    registry = CapabilityRegistry()
    registry.register(
        CapabilityDescriptor(
            name="a",
            provides=(PipelineStateKey.SUBDOMAINS,),
        )
    )
    registry.register(
        CapabilityDescriptor(
            name="b",
            requires=(PipelineStateKey.SUBDOMAINS,),
            provides=(PipelineStateKey.HOSTS,),
        )
    )
    registry.register(
        CapabilityDescriptor(
            name="c",
            requires=(PipelineStateKey.HOSTS,),
            provides=(PipelineStateKey.ALIVE_HOSTS,),
        )
    )
    return registry


def _chain_plan() -> tuple[CapabilityRegistry, object]:
    registry = _chain_registry()
    plan = ExecutionPlanner(registry).plan(goals=(PipelineStateKey.ALIVE_HOSTS,))
    return registry, plan


def test_factory_registry_has_deterministic_immutable_names() -> None:
    registry = CapabilityFactoryRegistry()
    registry.register("z", lambda: FakeCapability("z"))
    registry.register("a", lambda: FakeCapability("a"))

    assert registry.names == ("a", "z")
    assert registry.ids == (CapabilityId("a"), CapabilityId("z"))
    assert isinstance(registry.names, tuple)


def test_factory_registry_rejects_duplicates() -> None:
    registry = CapabilityFactoryRegistry()
    registry.register("same", lambda: FakeCapability("same"))

    with pytest.raises(InvalidCapabilityFactoryError):
        registry.register("same", lambda: FakeCapability("same"))


def test_factory_registry_is_lazy_and_returns_fresh_instances() -> None:
    registry = CapabilityFactoryRegistry()
    created: list[FakeCapability] = []

    def create() -> Capability:
        capability = FakeCapability("custom")
        created.append(capability)
        return capability

    registry.register(CapabilityId("custom"), create)

    assert registry.has(CapabilityId("custom"))
    assert created == []
    first = registry.create(CapabilityId("custom"))
    second = registry.create(CapabilityId("custom"))
    assert first is not second
    assert created == [first, second]


def test_factory_registry_rejects_non_callable_factory() -> None:
    registry = CapabilityFactoryRegistry()

    with pytest.raises(InvalidCapabilityFactoryError):
        registry.register("invalid", object())  # type: ignore[arg-type]


def test_factory_registry_unknown_lookup_is_focused() -> None:
    registry = CapabilityFactoryRegistry()

    with pytest.raises(MissingCapabilityFactoryError):
        registry.create(CapabilityId("missing"))


@pytest.mark.parametrize(
    "factory",
    [
        lambda: None,
        lambda: dict[str, object](),
        lambda: "invalid",
        lambda: object(),
    ],
)
def test_factory_registry_rejects_invalid_returns(
    factory: Callable[[], object],
) -> None:
    registry = CapabilityFactoryRegistry()
    registry.register("invalid", factory)  # type: ignore[arg-type]

    with pytest.raises(InvalidCapabilityFactoryError) as raised:
        registry.create("invalid")

    assert "object at" not in str(raised.value)


def test_factory_registry_rejects_wrong_capability_name() -> None:
    registry = CapabilityFactoryRegistry()
    registry.register("expected", lambda: FakeCapability("actual"))

    with pytest.raises(CapabilityDescriptorMismatchError) as raised:
        registry.create("expected")

    assert raised.value.capability_name == "expected"
    assert "actual" not in str(raised.value)


def test_factory_exception_is_sanitized() -> None:
    def fail() -> Capability:
        raise RuntimeError("secret-token C:\\private\\factory")

    registry = CapabilityFactoryRegistry()
    registry.register("unsafe", fail)

    with pytest.raises(InvalidCapabilityFactoryError) as raised:
        registry.create("unsafe")

    rendered = str(raised.value)
    assert rendered == "Capability factory for 'unsafe' failed"
    assert "secret-token" not in rendered
    assert "private" not in rendered


def test_custom_chain_plans_builds_and_executes_in_order() -> None:
    descriptors, plan_value = _chain_plan()
    plan = plan_value  # retain an untyped boundary for runtime validation coverage
    calls: list[str] = []
    factories = CapabilityFactoryRegistry()
    for name, data in (
        ("a", ("a.example",)),
        ("b", ("host",)),
        ("c", ("alive",)),
    ):
        factories.register(
            name,
            lambda name=name, data=data: FakeCapability(name, data, calls),
        )

    pipeline = PipelineBuilder(
        descriptor_registry=descriptors,
        factory_registry=factories,
    ).build(plan)  # type: ignore[arg-type]
    result = pipeline.run("example.com")

    assert calls == ["a", "b", "c"]
    assert result.executed_capabilities == ("a", "b", "c")
    assert result.status == Status.SUCCESS
    assert result.context.state[PipelineStateKey.SUBDOMAINS] == ("a.example",)
    assert result.context.state[PipelineStateKey.HOSTS] == ("host",)
    assert result.context.state[PipelineStateKey.ALIVE_HOSTS] == ("alive",)


@pytest.mark.parametrize("missing", ["a", "b", "c"])
def test_builder_rejects_missing_factory_before_returning_pipeline(
    missing: str,
) -> None:
    descriptors, plan = _chain_plan()
    factories = CapabilityFactoryRegistry()
    for name in ("a", "b", "c"):
        if name != missing:
            factories.register(name, lambda name=name: FakeCapability(name))
    builder = PipelineBuilder(
        descriptor_registry=descriptors,
        factory_registry=factories,
    )

    with pytest.raises(MissingCapabilityFactoryError) as raised:
        builder.build(plan)  # type: ignore[arg-type]

    assert raised.value.capability_name == missing


def test_builder_rejects_plan_from_incompatible_descriptor_registry() -> None:
    source, plan = _chain_plan()
    del source
    incompatible = _chain_registry()
    descriptor = incompatible.get("c")
    assert descriptor is not None
    incompatible = CapabilityRegistry()
    incompatible.register(
        CapabilityDescriptor(
            name="a",
            provides=(PipelineStateKey.SUBDOMAINS,),
        )
    )
    incompatible.register(
        CapabilityDescriptor(
            name="b",
            requires=(PipelineStateKey.SUBDOMAINS,),
            provides=(PipelineStateKey.HOSTS,),
        )
    )
    incompatible.register(
        CapabilityDescriptor(
            name=descriptor.name,
            requires=(PipelineStateKey.SUBDOMAINS,),
            provides=descriptor.provides,
        )
    )
    factories = CapabilityFactoryRegistry()
    for name in ("a", "b", "c"):
        factories.register(name, lambda name=name: FakeCapability(name))

    with pytest.raises(CapabilityDescriptorMismatchError):
        PipelineBuilder(
            descriptor_registry=incompatible,
            factory_registry=factories,
        ).build(plan)  # type: ignore[arg-type]


def test_every_default_descriptor_factory_and_runtime_mapping_align() -> None:
    descriptors = create_default_registry()
    factories = create_default_factory_registry()

    assert factories.names == tuple(descriptor.name for descriptor in descriptors.descriptors)
    for descriptor in descriptors.descriptors:
        capability = factories.create(descriptor.capability_id)
        assert capability.name == descriptor.name
        assert (
            descriptor.provides
            == CAPABILITY_OUTPUT_CONTRACTS[descriptor.capability_id]
        )


def test_repeated_builds_create_distinct_capability_instances() -> None:
    descriptors = CapabilityRegistry()
    descriptors.register(
        CapabilityDescriptor(
            name="fresh",
            provides=(PipelineStateKey.HOSTS,),
        )
    )
    created: list[FakeCapability] = []
    factories = CapabilityFactoryRegistry()

    def create() -> Capability:
        capability = FakeCapability("fresh")
        created.append(capability)
        return capability

    factories.register("fresh", create)
    builder = PipelineBuilder(
        descriptor_registry=descriptors,
        factory_registry=factories,
    )
    plan = ExecutionPlanner(descriptors).plan(goals=(PipelineStateKey.HOSTS,))

    first = builder.build(plan)
    second = builder.build(plan)

    assert first is not second
    assert len(created) == 2
    assert created[0] is not created[1]


def test_builder_accepts_multi_output_descriptor_and_builds_fresh_instances() -> None:
    descriptors = CapabilityRegistry()
    descriptors.register(
        CapabilityDescriptor(
            name="multi",
            provides=(
                PipelineStateKey.SUBDOMAINS,
                PipelineStateKey.HOSTS,
            ),
        )
    )
    instances: list[MultiOutputCapability] = []
    factories = CapabilityFactoryRegistry()
    factories.register("multi", lambda: MultiOutputCapability(instances))
    builder = PipelineBuilder(
        descriptor_registry=descriptors,
        factory_registry=factories,
    )
    plan = ExecutionPlanner(descriptors).plan(
        goals=(PipelineStateKey.HOSTS, PipelineStateKey.SUBDOMAINS)
    )

    first = builder.build(plan).run("example.com")
    second = builder.build(plan).run("example.com")

    assert len(instances) == 2
    assert instances[0] is not instances[1]
    assert instances[0].execute_calls == instances[1].execute_calls == 1
    assert first.executed_capabilities == second.executed_capabilities == ("multi",)
    assert first.context.get(PipelineStateKey.HOSTS) == ("host",)
    assert first.context.get(PipelineStateKey.SUBDOMAINS) == ("a.example",)
    assert first.executions[0].capability_id == CapabilityId("multi")


def test_factory_registry_rejects_unknown_definition_alignment() -> None:
    definitions = CapabilityRegistry(
        (
            CapabilityDefinition(
                capability_id="known",
                display_name="Known",
                description="Known contract.",
                version="1.0",
                provides=(PipelineStateKey.HOSTS,),
            ),
        )
    )
    factories = CapabilityFactoryRegistry()
    factories.register("unknown", lambda: FakeCapability("unknown"))

    with pytest.raises(CapabilityDescriptorMismatchError):
        factories.validate_against(definitions)
