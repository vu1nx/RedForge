"""Lightweight import-boundary regression tests."""

import ast
from pathlib import Path

_SOURCE_ROOT = Path(__file__).parents[1] / "src" / "redforge"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    return imported


def test_domain_does_not_import_adapters_runtime_or_external_transports() -> None:
    forbidden = ("redforge.adapters", "redforge.runtime", "socket", "urllib", "httpx")
    for path in (_SOURCE_ROOT / "domain").glob("*.py"):
        imports = _imports(path)
        assert not any(
            name == prefix or name.startswith(f"{prefix}.")
            for name in imports
            for prefix in forbidden
        ), path


def test_capabilities_do_not_import_transport_libraries_or_socket() -> None:
    forbidden = ("socket", "urllib.request", "urllib.error", "httpx", "requests")
    for path in (_SOURCE_ROOT / "capabilities").glob("*.py"):
        imports = _imports(path)
        assert not any(
            name == prefix or name.startswith(f"{prefix}.")
            for name in imports
            for prefix in forbidden
        ), path


def test_vulnerability_capability_does_not_reference_nvd_payload_keys() -> None:
    source = (_SOURCE_ROOT / "capabilities" / "vulnerability_intelligence.py").read_text(
        encoding="utf-8"
    )
    for provider_key in (
        "vulnerabilities",
        "startIndex",
        "resultsPerPage",
        "totalResults",
        "cvssMetricV31",
    ):
        assert f'"{provider_key}"' not in source


def test_planner_core_is_pure_and_does_not_import_execution_boundaries() -> None:
    forbidden = (
        "redforge.adapters",
        "redforge.capabilities",
        "redforge.runtime.pipeline",
        "socket",
        "urllib",
        "httpx",
        "requests",
    )
    for filename in (
        "models.py",
        "registry.py",
        "default_registry.py",
        "planner.py",
    ):
        path = _SOURCE_ROOT / "planning" / filename
        imports = _imports(path)
        assert not any(
            name == prefix or name.startswith(f"{prefix}.")
            for name in imports
            for prefix in forbidden
        ), path


def test_domain_does_not_import_planning_or_runtime() -> None:
    for path in (_SOURCE_ROOT / "domain").glob("*.py"):
        assert not any(
            name == prefix or name.startswith(f"{prefix}.")
            for name in _imports(path)
            for prefix in ("redforge.planning", "redforge.runtime")
        ), path


def test_execution_planner_has_no_execution_or_pipeline_builder_methods() -> None:
    from redforge.planning import ExecutionPlanner

    assert not hasattr(ExecutionPlanner, "execute")
    assert not hasattr(ExecutionPlanner, "run")
    assert not hasattr(ExecutionPlanner, "build_pipeline")


def test_builder_has_no_external_transports_or_capability_name_branching() -> None:
    path = _SOURCE_ROOT / "planning" / "builder.py"
    imports = _imports(path)
    forbidden = ("socket", "subprocess", "urllib", "httpx", "requests")
    assert not any(
        name == prefix or name.startswith(f"{prefix}.") for name in imports for prefix in forbidden
    )
    source = path.read_text(encoding="utf-8")
    assert "if step.capability_name ==" not in source
    assert "elif step.capability_name ==" not in source


def test_descriptor_and_factory_registries_remain_separate() -> None:
    from redforge.planning import (
        CapabilityDescriptor,
        CapabilityFactoryRegistry,
        CapabilityRegistry,
    )

    descriptor_registry = CapabilityRegistry()
    descriptor_registry.register(CapabilityDescriptor(name="a", provides=("hosts",)))
    factory_registry = CapabilityFactoryRegistry()

    assert descriptor_registry.descriptors == (CapabilityDescriptor(name="a", provides=("hosts",)),)
    assert factory_registry.names == ()
    assert not hasattr(descriptor_registry, "create")
    assert not hasattr(factory_registry, "descriptors")


def test_execution_plan_has_no_runtime_capability_fields() -> None:
    from dataclasses import fields

    from redforge.planning import ExecutionPlan

    assert tuple(field.name for field in fields(ExecutionPlan)) == (
        "goals",
        "available_state",
        "steps",
    )


def test_planning_modules_do_not_import_network_implementations() -> None:
    forbidden = ("socket", "subprocess", "urllib", "httpx", "requests")
    for path in (_SOURCE_ROOT / "planning").glob("*.py"):
        imports = _imports(path)
        assert not any(
            name == prefix or name.startswith(f"{prefix}.")
            for name in imports
            for prefix in forbidden
        ), path


def test_factory_module_has_no_global_mutable_registry_singleton() -> None:
    path = _SOURCE_ROOT / "planning" / "factories.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    module_assignments = (
        node for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))
    )
    for assignment in module_assignments:
        value = assignment.value
        assert not (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "CapabilityFactoryRegistry"
        )


def test_execution_facade_does_not_invoke_capabilities_directly() -> None:
    path = _SOURCE_ROOT / "planning" / "execution.py"
    source = path.read_text(encoding="utf-8")
    assert ".execute(context)" not in source
    assert ".run(context)" in source


def test_publication_model_has_no_adapter_or_network_dependencies() -> None:
    path = _SOURCE_ROOT / "sdk" / "result.py"
    imports = _imports(path)
    forbidden = (
        "redforge.adapters",
        "redforge.planning",
        "socket",
        "subprocess",
        "urllib",
        "httpx",
        "requests",
    )
    assert not any(
        name == prefix or name.startswith(f"{prefix}.") for name in imports for prefix in forbidden
    )


def test_context_does_not_import_planning_or_runtime_pipeline() -> None:
    imports = _imports(_SOURCE_ROOT / "sdk" / "context.py")
    assert not any(
        name == prefix or name.startswith(f"{prefix}.")
        for name in imports
        for prefix in ("redforge.planning", "redforge.runtime.pipeline")
    )


def test_runtime_publication_normalization_is_centralized() -> None:
    path = _SOURCE_ROOT / "runtime" / "pipeline.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    functions = {
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "_normalize_capability_result" in functions
    assert "StatePublication(" not in (_SOURCE_ROOT / "planning" / "execution.py").read_text(
        encoding="utf-8"
    )


def test_default_output_contract_registry_is_immutable() -> None:
    from types import MappingProxyType

    from redforge.runtime.pipeline_state import CAPABILITY_OUTPUT_CONTRACTS

    assert isinstance(CAPABILITY_OUTPUT_CONTRACTS, MappingProxyType)


def test_execution_history_is_capability_based_not_publication_based() -> None:
    from dataclasses import fields

    from redforge.runtime.pipeline import CapabilityExecution

    assert tuple(field.name for field in fields(CapabilityExecution)) == (
        "capability_name",
        "result",
    )
