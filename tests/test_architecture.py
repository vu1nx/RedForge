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
        "capability_id",
    )


def test_capability_definitions_have_no_runtime_or_adapter_dependencies() -> None:
    for filename in (
        "capability_id.py",
        "capability_definition.py",
        "default_capabilities.py",
    ):
        path = _SOURCE_ROOT / "sdk" / filename
        imports = _imports(path)
        forbidden = (
            "redforge.adapters",
            "redforge.capabilities",
            "redforge.runtime.pipeline",
            "redforge.planning.factories",
            "socket",
            "subprocess",
            "urllib",
        )
        assert not any(
            name == prefix or name.startswith(f"{prefix}.")
            for name in imports
            for prefix in forbidden
        ), path


def test_definitions_do_not_contain_factories_or_runtime_instances() -> None:
    from dataclasses import fields

    from redforge.planning import CapabilityDefinition

    assert tuple(field.name for field in fields(CapabilityDefinition)) == (
        "capability_id",
        "requires",
        "provides",
        "display_name",
        "description",
        "version",
        "tags",
    )


def test_default_registry_and_runtime_contracts_share_definitions() -> None:
    pipeline_state = (
        _SOURCE_ROOT / "runtime" / "pipeline_state.py"
    ).read_text(encoding="utf-8")
    default_registry = (
        _SOURCE_ROOT / "planning" / "default_registry.py"
    ).read_text(encoding="utf-8")

    assert "DEFAULT_CAPABILITY_DEFINITIONS" in pipeline_state
    assert "DEFAULT_CAPABILITY_DEFINITIONS" in default_registry
    assert "CapabilityDefinition(" not in default_registry


def test_tags_and_versions_do_not_affect_planning_or_execution() -> None:
    planner = (_SOURCE_ROOT / "planning" / "planner.py").read_text(
        encoding="utf-8"
    )
    builder = (_SOURCE_ROOT / "planning" / "builder.py").read_text(
        encoding="utf-8"
    )
    pipeline = (_SOURCE_ROOT / "runtime" / "pipeline.py").read_text(
        encoding="utf-8"
    )

    for source in (planner, builder, pipeline):
        assert ".tags" not in source
        assert ".version" not in source


def test_runtime_does_not_infer_planned_identity_from_class_name() -> None:
    source = (_SOURCE_ROOT / "runtime" / "pipeline.py").read_text(
        encoding="utf-8"
    )

    assert "__class__" not in source
    assert "type(capability).__name__" not in source


def test_capabilities_domain_and_planning_do_not_import_subprocess() -> None:
    for package in ("capabilities", "domain", "planning"):
        for path in (_SOURCE_ROOT / package).glob("*.py"):
            assert "subprocess" not in _imports(path), path


def test_tool_contracts_do_not_import_concrete_runner_or_runtime() -> None:
    for filename in ("tool.py", "tool_registry.py"):
        imports = _imports(_SOURCE_ROOT / "sdk" / filename)
        forbidden = (
            "subprocess",
            "redforge.adapters",
            "redforge.runtime",
            "redforge.capabilities",
            "redforge.planning",
        )
        assert not any(
            name == prefix or name.startswith(f"{prefix}.")
            for name in imports
            for prefix in forbidden
        ), filename


def test_capability_definitions_do_not_reference_tool_definitions() -> None:
    source = (
        _SOURCE_ROOT / "sdk" / "capability_definition.py"
    ).read_text(encoding="utf-8")
    assert "ToolDefinition" not in source
    assert "ToolId" not in source


def test_local_tool_runner_is_shell_free_and_tool_agnostic() -> None:
    path = _SOURCE_ROOT / "adapters" / "tool_runner.py"
    source = path.read_text(encoding="utf-8")

    assert "shell=False" in source
    assert "shell=True" not in source
    assert "os.system" not in source
    assert "subprocess" in _imports(path)
    for tool_name in (
        "subfinder",
        "amass",
        "assetfinder",
        "findomain",
        "naabu",
        "nmap",
        "masscan",
        "httpx",
        "katana",
        "nuclei",
    ):
        assert tool_name not in source.lower()


def test_source_has_no_shell_true_or_os_system() -> None:
    for path in _SOURCE_ROOT.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "shell=True" not in source, path
        assert "os.system(" not in source, path


def test_tool_registry_contains_definitions_only() -> None:
    from redforge.sdk import ToolDefinition, ToolRegistry

    definition = ToolDefinition(
        "example",
        "Example",
        "Example external provider.",
        "example",
    )
    registry = ToolRegistry((definition,))

    assert registry.all() == (definition,)
    assert not hasattr(registry, "runner")
    assert not hasattr(registry, "run")


def test_no_global_mutable_tool_registry_or_runner() -> None:
    paths = (
        _SOURCE_ROOT / "sdk" / "tool_registry.py",
        _SOURCE_ROOT / "adapters" / "tool_runner.py",
    )
    forbidden_constructors = {
        "ToolRegistry",
        "LocalSubprocessToolRunner",
        "ToolRunnerConfig",
    }
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assignments = (
            node
            for node in tree.body
            if isinstance(node, (ast.Assign, ast.AnnAssign))
        )
        for assignment in assignments:
            value = assignment.value
            assert not (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id in forbidden_constructors
            )


def test_fake_tool_runner_has_no_subprocess_dependency() -> None:
    imports = _imports(_SOURCE_ROOT / "testing" / "tool_runner.py")
    assert "subprocess" not in imports


def test_subdomain_capability_is_tool_and_provider_implementation_agnostic() -> None:
    path = _SOURCE_ROOT / "capabilities" / "subdomain_discovery.py"
    imports = _imports(path)
    source = path.read_text(encoding="utf-8")

    assert "subprocess" not in imports
    assert "redforge.adapters" not in imports
    assert "redforge.sdk.tool" not in imports
    assert "Subfinder" not in source
    assert "ToolRunner" not in source


def test_subfinder_adapter_uses_only_the_tool_runner_port() -> None:
    path = _SOURCE_ROOT / "adapters" / "subfinder.py"
    imports = _imports(path)
    source = path.read_text(encoding="utf-8")

    assert "redforge.sdk.tool" in imports
    assert "subprocess" not in imports
    assert "redforge.adapters.tool_runner" not in imports
    assert "redforge.runtime" not in imports
    assert "redforge.runtime.pipeline" not in imports
    assert "redforge.sdk.context" not in imports
    assert "LocalSubprocessToolRunner" not in source
    assert "StatePublication" not in source
    assert "shell=True" not in source
    assert "os.system(" not in source


def test_planner_and_builder_have_no_subfinder_specific_behavior() -> None:
    for filename in ("planner.py", "builder.py"):
        source = (_SOURCE_ROOT / "planning" / filename).read_text(
            encoding="utf-8"
        )
        assert "subfinder" not in source.lower()


def test_tool_definition_has_no_capability_definition_dependency() -> None:
    source = (_SOURCE_ROOT / "sdk" / "tool.py").read_text(encoding="utf-8")
    assert "CapabilityDefinition" not in source
    assert "CapabilityId" not in source


def test_subfinder_composition_has_no_global_runner_or_registry() -> None:
    paths = (
        _SOURCE_ROOT / "adapters" / "default_tools.py",
        _SOURCE_ROOT / "planning" / "factories.py",
    )
    forbidden_constructors = {"ToolRegistry", "LocalSubprocessToolRunner"}
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assignments = (
            node
            for node in tree.body
            if isinstance(node, (ast.Assign, ast.AnnAssign))
        )
        for assignment in assignments:
            value = assignment.value
            assert not (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id in forbidden_constructors
            )


def test_subfinder_adapter_has_no_install_or_update_operation() -> None:
    source = (_SOURCE_ROOT / "adapters" / "subfinder.py").read_text(
        encoding="utf-8"
    )

    assert '"-disable-update-check"' in source
    for forbidden_argument in ('"-update"', '"-up"', '"-install"', '"-o"', '"-oD"'):
        assert forbidden_argument not in source


def test_http_probe_capability_is_tool_implementation_agnostic() -> None:
    path = _SOURCE_ROOT / "capabilities" / "http_probe.py"
    imports = _imports(path)
    source = path.read_text(encoding="utf-8")

    assert "subprocess" not in imports
    assert "redforge.adapters" not in imports
    assert "redforge.sdk.tool" not in imports
    assert "HTTPX" not in source
    assert "ToolRunner" not in source


def test_httpx_adapter_uses_only_the_tool_runner_port() -> None:
    path = _SOURCE_ROOT / "adapters" / "httpx.py"
    imports = _imports(path)
    source = path.read_text(encoding="utf-8")

    assert "redforge.sdk.tool" in imports
    assert "subprocess" not in imports
    assert "redforge.adapters.tool_runner" not in imports
    assert "redforge.runtime" not in imports
    assert "redforge.runtime.pipeline" not in imports
    assert "redforge.sdk.context" not in imports
    assert "LocalSubprocessToolRunner" not in source
    assert "StatePublication" not in source
    assert "shell=True" not in source
    assert "os.system(" not in source
    assert "extra_args" not in source
    assert "command_string" not in source


def test_httpx_is_absent_from_planner_and_builder() -> None:
    for filename in ("planner.py", "builder.py"):
        source = (_SOURCE_ROOT / "planning" / filename).read_text(
            encoding="utf-8"
        )
        assert "httpx" not in source.lower()


def test_http_probe_evidence_remains_one_atomic_capability_contract() -> None:
    from redforge.planning import CapabilityId, create_default_registry
    from redforge.sdk import PipelineStateKey

    definition = create_default_registry().require(CapabilityId("http_probe"))
    assert definition.requires == (PipelineStateKey.HOSTS,)
    assert definition.provides == (
        PipelineStateKey.ALIVE_HOSTS,
        PipelineStateKey.HTTP_ENDPOINTS,
    )
    assert PipelineStateKey.HTTP_ENDPOINTS != PipelineStateKey.ENDPOINTS

    capability_source = (
        _SOURCE_ROOT / "capabilities" / "http_probe.py"
    ).read_text(encoding="utf-8")
    assert capability_source.count("self._provider.probe(hosts)") == 1
    assert "context.publish" not in capability_source
    assert "StatePublication(PipelineStateKey.ALIVE_HOSTS" in capability_source
    assert (
        "StatePublication(PipelineStateKey.HTTP_ENDPOINTS"
        in capability_source
    )

    for filename in ("planner.py", "builder.py"):
        source = (_SOURCE_ROOT / "planning" / filename).read_text(
            encoding="utf-8"
        )
        assert "HTTP_ENDPOINTS" not in source
        assert "HttpProbeEndpoint" not in source


def test_direct_subprocess_imports_are_limited_to_runner_and_known_debt() -> None:
    importing = {
        path.name
        for path in (_SOURCE_ROOT / "adapters").glob("*.py")
        if "subprocess" in _imports(path)
    }
    assert importing == {
        "tool_runner.py",
    }


def test_katana_provider_and_web_crawl_capability_preserve_boundaries() -> None:
    capability_path = _SOURCE_ROOT / "capabilities" / "web_crawl.py"
    capability_imports = _imports(capability_path)
    capability_source = capability_path.read_text(encoding="utf-8")
    assert "redforge.sdk.web_crawl" in capability_imports
    assert "redforge.adapters" not in capability_imports
    assert "redforge.sdk.tool" not in capability_imports
    assert "subprocess" not in capability_imports
    assert "Katana" not in capability_source
    assert "context.publish" not in capability_source

    adapter_path = _SOURCE_ROOT / "adapters" / "katana.py"
    adapter_imports = _imports(adapter_path)
    adapter_source = adapter_path.read_text(encoding="utf-8")
    assert "redforge.sdk.tool" in adapter_imports
    assert "subprocess" not in adapter_imports
    assert "shutil" not in adapter_imports
    assert "redforge.runtime" not in adapter_imports
    assert "redforge.sdk.context" not in adapter_imports
    assert "StatePublication" not in adapter_source
    assert "LocalSubprocessToolRunner" not in adapter_source
    assert "shell=True" not in adapter_source
    assert "os.system(" not in adapter_source
    assert "extra_args" not in adapter_source

    for filename in ("planner.py", "builder.py"):
        source = (_SOURCE_ROOT / "planning" / filename).read_text(
            encoding="utf-8"
        )
        assert "katana" not in source.lower()


def test_whatweb_provider_and_technology_capability_preserve_boundaries() -> None:
    capability_path = _SOURCE_ROOT / "capabilities" / "technology_detection.py"
    capability_imports = _imports(capability_path)
    capability_source = capability_path.read_text(encoding="utf-8")
    assert "redforge.sdk.technology_detection" in capability_imports
    assert "redforge.adapters" not in capability_imports
    assert "redforge.sdk.tool" not in capability_imports
    assert "subprocess" not in capability_imports
    assert "WhatWeb" not in capability_source
    assert "context.publish" not in capability_source

    adapter_path = _SOURCE_ROOT / "adapters" / "technology_detection.py"
    adapter_imports = _imports(adapter_path)
    adapter_source = adapter_path.read_text(encoding="utf-8")
    assert "redforge.sdk.tool" in adapter_imports
    assert "subprocess" not in adapter_imports
    assert "shutil" not in adapter_imports
    assert "redforge.runtime" not in adapter_imports
    assert "redforge.sdk.context" not in adapter_imports
    assert "StatePublication" not in adapter_source
    assert "LocalSubprocessToolRunner" not in adapter_source
    assert "shell=True" not in adapter_source
    assert "os.system(" not in adapter_source
    assert "extra_args" not in adapter_source

    for filename in ("planner.py", "builder.py"):
        source = (_SOURCE_ROOT / "planning" / filename).read_text(
            encoding="utf-8"
        )
        assert "whatweb" not in source.lower()


def test_httpx_adapter_has_no_unsafe_or_expansive_probe_flags() -> None:
    source = (_SOURCE_ROOT / "adapters" / "httpx.py").read_text(
        encoding="utf-8"
    )

    assert '"-disable-update-check"' in source
    for forbidden_argument in (
        '"-update"',
        '"-unsafe"',
        '"-header"',
        '"-body"',
        '"-screenshot"',
        '"-tech-detect"',
        '"-output"',
        '"-path"',
        '"-ports"',
    ):
        assert forbidden_argument not in source


def test_default_capability_graph_has_complete_factory_and_producer_coverage() -> None:
    from redforge.planning import (
        create_default_factory_registry,
        create_default_registry,
    )
    from redforge.sdk import PipelineStateKey

    definitions = create_default_registry()
    factories = create_default_factory_registry()

    assert definitions.ids() == factories.ids
    assert all(
        len(definitions.producers_for(key)) == 1 for key in PipelineStateKey
    )


def test_default_capability_and_tool_identities_are_disjoint() -> None:
    from redforge.adapters import create_default_tool_registry
    from redforge.planning import create_default_registry

    capability_values = {item.value for item in create_default_registry().ids()}
    tool_values = {
        item.value for item in create_default_tool_registry().ids()
    }

    assert capability_values.isdisjoint(tool_values)
