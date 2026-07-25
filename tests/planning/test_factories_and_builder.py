"""Factory registry and defensive plan-to-pipeline builder tests."""

from collections.abc import Callable
from typing import Any

import pytest  # type: ignore[reportMissingImports]

from redforge.planning import (
    CapabilityDescriptor,
    CapabilityDescriptorMismatchError,
    CapabilityFactoryRegistry,
    CapabilityRegistry,
    ExecutionPlanner,
    InvalidCapabilityFactoryError,
    MissingCapabilityFactoryError,
    PipelineBuilder,
    create_default_factory_registry,
    create_default_registry,
)
from redforge.runtime.pipeline_state import (
    CAPABILITY_OUTPUT_KEYS,
    PipelineStateKey,
)
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


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
    plan = ExecutionPlanner(registry).plan(
        goals=(PipelineStateKey.ALIVE_HOSTS,)
    )
    return registry, plan


def test_factory_registry_has_deterministic_immutable_names() -> None:
    registry = CapabilityFactoryRegistry()
    registry.register("z", lambda: FakeCapability("z"))
    registry.register("a", lambda: FakeCapability("a"))

    assert registry.names == ("a", "z")
    assert isinstance(registry.names, tuple)


def test_factory_registry_rejects_duplicates() -> None:
    registry = CapabilityFactoryRegistry()
    registry.register("same", lambda: FakeCapability("same"))

    with pytest.raises(InvalidCapabilityFactoryError):
        registry.register("same", lambda: FakeCapability("same"))


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

    assert factories.names == tuple(
        descriptor.name for descriptor in descriptors.descriptors
    )
    for descriptor in descriptors.descriptors:
        capability = factories.create(descriptor.name)
        assert capability.name == descriptor.name
        assert descriptor.provides == (
            CAPABILITY_OUTPUT_KEYS[descriptor.name],
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
