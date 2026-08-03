"""Lightweight import-boundary regression tests."""

import ast
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).parents[1]
_SOURCE_ROOT = _REPOSITORY_ROOT / "src" / "redforge"


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
        "executed",
        "policy_violation",
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


def test_scan_config_is_confined_to_the_application_boundary() -> None:
    forbidden_packages = ("capabilities", "adapters", "runtime")
    for package in forbidden_packages:
        for path in (_SOURCE_ROOT / package).glob("*.py"):
            assert not any(
                name == "redforge.application"
                or name.startswith("redforge.application.")
                for name in _imports(path)
            ), path

    for path in (
        _SOURCE_ROOT / "planning" / "planner.py",
        _SOURCE_ROOT / "planning" / "builder.py",
        _SOURCE_ROOT / "sdk" / "tool.py",
    ):
        assert not any(
            name == "redforge.application"
            or name.startswith("redforge.application.")
            for name in _imports(path)
        ), path


def test_planner_and_builder_do_not_inspect_targets_or_scope() -> None:
    for filename in ("planner.py", "builder.py"):
        source = (_SOURCE_ROOT / "planning" / filename).read_text(
            encoding="utf-8"
        )
        assert "target_id" not in source
        assert "ScanTarget" not in source
        assert "ScanScope" not in source


def test_application_scan_config_has_no_adapter_tool_or_runtime_execution_imports() -> None:
    imports = _imports(_SOURCE_ROOT / "application" / "scan_config.py")
    forbidden = (
        "redforge.adapters",
        "redforge.capabilities",
        "redforge.runtime.pipeline",
        "redforge.sdk.tool",
        "subprocess",
        "socket",
        "urllib",
    )

    assert not any(
        name == prefix or name.startswith(f"{prefix}.")
        for name in imports
        for prefix in forbidden
    )


def test_scan_config_models_contain_no_tool_runtime_or_secret_fields() -> None:
    from dataclasses import fields

    from redforge.application import PreparedScan, ScanConfig, ScanLimits
    from redforge.domain import ScanScope, ScanTarget

    names = {
        item.name
        for model in (ScanTarget, ScanScope, ScanLimits, ScanConfig, PreparedScan)
        for item in fields(model)
    }
    forbidden = {
        "tool_id",
        "executable",
        "arguments",
        "argv",
        "provider",
        "runner",
        "context",
        "password",
        "credentials",
        "cookie",
        "authorization_header",
        "proxy",
        "plugin",
        "output_path",
        "metadata",
    }

    assert names.isdisjoint(forbidden)


def test_cli_framework_and_configuration_format_dependencies_are_confined() -> None:
    forbidden_imports = {
        "click",
        "typer",
        "rich",
        "yaml",
        "dotenv",
    }
    for path in _SOURCE_ROOT.rglob("*.py"):
        assert _imports(path).isdisjoint(forbidden_imports), path
        if path != _SOURCE_ROOT / "configuration" / "loader.py":
            assert "tomllib" not in _imports(path), path
        if path != _SOURCE_ROOT / "cli" / "main.py":
            assert "argparse" not in _imports(path), path


def test_scan_orchestrator_has_no_adapter_tool_or_external_io_dependencies() -> None:
    path = _SOURCE_ROOT / "application" / "orchestration.py"
    imports = _imports(path)
    forbidden = (
        "redforge.capabilities",
        "redforge.sdk.tool",
        "subprocess",
        "socket",
        "urllib",
        "os",
    )
    adapter_imports = {
        name
        for name in imports
        if name == "redforge.adapters"
        or name.startswith("redforge.adapters.")
    }
    assert adapter_imports <= {"redforge.adapters.observability"}

    assert not any(
        name == prefix or name.startswith(f"{prefix}.")
        for name in imports
        for prefix in forbidden
    )


def test_lower_layers_do_not_import_application_orchestration() -> None:
    for package in ("capabilities", "adapters", "planning", "runtime", "sdk"):
        for path in (_SOURCE_ROOT / package).rglob("*.py"):
            assert "redforge.application.orchestration" not in _imports(path), path


def test_scan_orchestrator_has_no_tool_cli_environment_or_report_branching() -> None:
    source = (
        _SOURCE_ROOT / "application" / "orchestration.py"
    ).read_text(encoding="utf-8").lower()
    for forbidden in (
        "toolrunner",
        "toolid",
        "subfinder",
        "httpx",
        "katana",
        "whatweb",
        "argparse",
        "typer",
        "click",
        "os.environ",
        "getenv",
        "open(",
        "report",
        "json",
    ):
        assert forbidden not in source


def test_scan_result_has_no_raw_process_or_mutable_composition_fields() -> None:
    from dataclasses import fields

    from redforge.application import ScanResult

    names = {item.name for item in fields(ScanResult)}
    assert names == {
        "config",
        "plan",
        "preflight",
        "pipeline_result",
        "accepted",
    }
    assert names.isdisjoint(
        {
            "stdout",
            "stderr",
            "argv",
            "environment",
            "executable",
            "tool_runner",
            "pipeline",
            "registry",
            "provider",
            "report_writer",
        }
    )


def test_scan_limits_remain_confined_to_application_translation() -> None:
    for package in ("capabilities", "adapters", "planning", "runtime", "sdk"):
        for path in (_SOURCE_ROOT / package).rglob("*.py"):
            imports = _imports(path)
            assert "redforge.application.scan_config" not in imports, path
            assert "redforge.application.scan_limits" not in imports, path
            assert "redforge.application" not in imports, path


def test_runtime_execution_policy_is_tool_and_provider_neutral() -> None:
    source = (
        _SOURCE_ROOT / "runtime" / "execution_policy.py"
    ).read_text(encoding="utf-8").lower()
    for forbidden in (
        "toolrunner",
        "toolid",
        "subfinder",
        "httpx",
        "katana",
        "whatweb",
        "subprocess",
        "thread",
        "signal",
        "async",
        "scanconfig",
        "scanlimits",
    ):
        assert forbidden not in source


def test_limit_enforcement_has_no_evidence_slicing_or_unsafe_timeout() -> None:
    inspected = (
        _SOURCE_ROOT / "runtime" / "execution_policy.py",
        _SOURCE_ROOT / "runtime" / "pipeline.py",
        _SOURCE_ROOT / "application" / "scan_limits.py",
        _SOURCE_ROOT / "application" / "orchestration.py",
    )
    for path in inspected:
        source = path.read_text(encoding="utf-8").lower()
        assert "[:limit]" not in source
        assert "[: limit]" not in source
        assert "threading" not in source
        assert "concurrent.futures" not in source
        assert "signal." not in source
        assert "asyncio" not in source


def test_context_does_not_store_scan_limits_or_deadlines() -> None:
    from dataclasses import fields

    from redforge.sdk import Context

    assert {item.name for item in fields(Context)}.isdisjoint(
        {"limits", "scan_limits", "deadline", "execution_policy"}
    )


def test_runtime_and_capabilities_do_not_import_preflight() -> None:
    for package in ("runtime", "capabilities"):
        for path in (_SOURCE_ROOT / package).rglob("*.py"):
            assert not any(
                name == "redforge.application.preflight"
                or name.startswith("redforge.application.preflight.")
                for name in _imports(path)
            ), path


def test_generic_preflight_has_no_execution_target_or_adapter_dependencies() -> None:
    path = _SOURCE_ROOT / "application" / "preflight.py"
    imports = _imports(path)
    forbidden_imports = (
        "redforge.adapters",
        "redforge.runtime",
        "redforge.sdk.context",
        "subprocess",
        "socket",
        "urllib",
        "os",
        "pathlib",
    )
    assert not any(
        name == prefix or name.startswith(f"{prefix}.")
        for name in imports
        for prefix in forbidden_imports
    )
    source = path.read_text(encoding="utf-8").lower()
    for forbidden in (
        "target_id",
        "scan_target",
        ".create(",
        "pipeline(",
        ".execute(",
        "os.environ",
        "getenv",
        "subfinder",
        "httpx",
        "katana",
        "whatweb",
        "credential",
        "authorization",
        "stdout",
        "stderr",
    ):
        assert forbidden not in source


def test_execution_plan_remains_free_of_tool_and_readiness_fields() -> None:
    from dataclasses import fields

    from redforge.planning import ExecutionPlan, ExecutionStep

    names = {
        item.name for model in (ExecutionPlan, ExecutionStep) for item in fields(model)
    }
    assert names.isdisjoint(
        {
            "tool_id",
            "tool_definition",
            "provider",
            "readiness",
            "requirements",
            "preflight",
        }
    )


def test_cli_core_has_no_capability_adapter_tool_or_state_dependencies() -> None:
    path = _SOURCE_ROOT / "cli" / "main.py"
    imports = _imports(path)
    forbidden = (
        "redforge.capabilities",
        "redforge.sdk.context",
        "redforge.sdk.state",
        "redforge.sdk.tool",
        "subprocess",
        "socket",
        "urllib",
        "os",
    )
    assert not any(
        name == prefix or name.startswith(f"{prefix}.")
        for name in imports
        for prefix in forbidden
    )
    source = path.read_text(encoding="utf-8").lower()
    for forbidden_text in (
        "pipelinestatekey",
        "toolrunner",
        "shutil.which",
        "os.environ",
        "getenv",
        "subdomain_discovery",
        "host_resolution",
        "http_probe",
        "web_crawl",
        "technology_detection",
        "risk_intelligence",
        "open(",
    ):
        assert forbidden_text not in source


def test_lower_layers_do_not_import_configuration() -> None:
    for package in (
        "application",
        "runtime",
        "planning",
        "adapters",
        "capabilities",
        "domain",
        "sdk",
    ):
        for path in (_SOURCE_ROOT / package).rglob("*.py"):
            imports = _imports(path)
            assert not any(
                name == "redforge.configuration"
                or name.startswith("redforge.configuration.")
                for name in imports
            ), path


def test_configuration_layer_has_no_runtime_or_external_io_dependencies() -> None:
    forbidden_imports = (
        "redforge.adapters",
        "redforge.capabilities",
        "redforge.cli",
        "redforge.planning",
        "redforge.runtime",
        "subprocess",
        "socket",
        "urllib",
        "http",
        "requests",
        "yaml",
        "dotenv",
        "importlib",
    )
    forbidden_source = (
        "applicationcomposition",
        "compositionproviders",
        "os.environ",
        "getenv",
        "subprocess",
        "socket.",
        "urlopen",
        "requests.",
        "write_text(",
        "write_bytes(",
        "open(",
        "entry_point",
        "plugin",
    )
    for path in (_SOURCE_ROOT / "configuration").rglob("*.py"):
        imports = _imports(path)
        assert not any(
            name == prefix or name.startswith(f"{prefix}.")
            for name in imports
            for prefix in forbidden_imports
        ), path
        source = path.read_text(encoding="utf-8").lower()
        for forbidden in forbidden_source:
            assert forbidden not in source, path


def test_composition_does_not_parse_configuration_files() -> None:
    for path in (_SOURCE_ROOT / "composition").rglob("*.py"):
        imports = _imports(path)
        assert "tomllib" not in imports, path
        assert not any(
            name == "redforge.configuration"
            or name.startswith("redforge.configuration.")
            for name in imports
        ), path


def test_cli_consumes_typed_configuration_without_toml_decoding() -> None:
    path = _SOURCE_ROOT / "cli" / "main.py"
    imports = _imports(path)
    source = path.read_text(encoding="utf-8").lower()

    assert "tomllib" not in imports
    assert "dict[str, object]" not in source
    assert "_build_configuration" not in source


def test_lower_layers_do_not_import_cli() -> None:
    for package in (
        "application",
        "planning",
        "runtime",
        "capabilities",
        "adapters",
        "sdk",
    ):
        for path in (_SOURCE_ROOT / package).rglob("*.py"):
            assert not any(
                name == "redforge.cli"
                or name.startswith("redforge.cli.")
                for name in _imports(path)
            ), path


def test_application_composition_is_separate_from_cli_and_has_no_hidden_provider() -> None:
    main_source = (_SOURCE_ROOT / "cli" / "main.py").read_text(
        encoding="utf-8"
    )
    composition_source = (
        _SOURCE_ROOT / "composition" / "application.py"
    ).read_text(encoding="utf-8")

    assert "redforge.adapters.observability" in main_source
    assert "LocalSubprocessToolRunner" not in main_source
    assert "NvdAdapter" not in composition_source
    assert "redforge.composition" in main_source
    assert not (_SOURCE_ROOT / "cli" / "composition.py").exists()
    for forbidden in (
        "os.environ",
        "getenv",
        "dotenv",
        "service_locator",
        "plugin",
        "ScanConfig",
        "PipelineStateKey",
        ".execute(",
        "risk_score",
    ):
        assert forbidden not in composition_source


def test_cli_imports_have_no_top_level_calls_or_process_exit() -> None:
    for relative_path in (
        "cli/__init__.py",
        "cli/main.py",
        "cli/json_output.py",
        "composition/__init__.py",
        "composition/application.py",
    ):
        path = _SOURCE_ROOT / relative_path
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for statement in tree.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.Expr)):
                assert not any(
                    isinstance(node, ast.Call) for node in ast.walk(statement)
                ), path

    wrapper = (_SOURCE_ROOT / "cli" / "__main__.py").read_text(
        encoding="utf-8"
    )
    assert 'if __name__ == "__main__":' in wrapper
    assert "sys.exit(main())" in wrapper
    assert "sys.exit" not in (
        _SOURCE_ROOT / "cli" / "main.py"
    ).read_text(encoding="utf-8")


def test_cli_concrete_adapter_usage_is_confined_to_diagnostic_logging() -> None:
    for path in (_SOURCE_ROOT / "cli").glob("*.py"):
        imports = _imports(path)
        adapter_imports = {
            name
            for name in imports
            if name == "redforge.adapters"
            or name.startswith("redforge.adapters.")
        }
        assert adapter_imports <= {"redforge.adapters.observability"}, path
        source = path.read_text(encoding="utf-8")
        for forbidden in (
            "LocalSubprocessToolRunner(",
            "ToolRegistry(",
            "CapabilityRegistry(",
            "CapabilityFactoryRegistry(",
            "ReadinessRegistry(",
            "ToolRunnerReadinessProbe(",
            "create_default_factory_registry(",
            "create_default_registry(",
        ):
            assert forbidden not in source, path


def test_observability_core_is_provider_neutral_and_side_effect_free() -> None:
    forbidden_imports = (
        "redforge.adapters",
        "redforge.application",
        "redforge.capabilities",
        "redforge.cli",
        "redforge.configuration",
        "redforge.planning",
        "redforge.runtime",
        "logging",
        "subprocess",
        "socket",
        "urllib",
        "http",
        "requests",
        "pathlib",
        "os",
    )
    forbidden_source = (
        "basicconfig",
        "getlogger",
        "os.environ",
        "getenv",
        "stdout",
        "stderr",
        "executable_path",
        "command",
        "traceback",
        "format_exc",
        "default=str",
        "__dict__",
        "asdict",
        "write_text",
        "write_bytes",
        "open(",
        "context",
    )
    for path in (_SOURCE_ROOT / "observability").rglob("*.py"):
        imports = _imports(path)
        assert not any(
            name == prefix or name.startswith(f"{prefix}.")
            for name in imports
            for prefix in forbidden_imports
        ), path
        source = path.read_text(encoding="utf-8").lower()
        for forbidden in forbidden_source:
            assert forbidden not in source, path


def test_python_logging_configuration_is_confined_and_local() -> None:
    allowed = {
        _SOURCE_ROOT / "adapters" / "observability.py",
        _SOURCE_ROOT / "cli" / "main.py",
    }
    for path in _SOURCE_ROOT.rglob("*.py"):
        imports = _imports(path)
        if "logging" in imports:
            assert path in allowed
        source = path.read_text(encoding="utf-8")
        for forbidden in (
            "logging.basicConfig",
            "logging.getLogger()",
            "FileHandler(",
            "SocketHandler(",
            "HTTPHandler(",
            "SysLogHandler(",
        ):
            assert forbidden not in source, path


def test_diagnostic_logging_adapter_serializes_only_closed_event_contract() -> None:
    path = _SOURCE_ROOT / "adapters" / "observability.py"
    imports = _imports(path)
    source = path.read_text(encoding="utf-8").lower()

    assert "redforge.sdk.context" not in imports
    assert "redforge.runtime" not in imports
    assert "redforge.application" not in imports
    for forbidden in (
        "default=str",
        "__dict__",
        "asdict",
        "traceback",
        "format_exc",
        "repr(",
        "context",
        "stdout",
        "stderr",
        "environment",
        "executable_path",
        "filehandler",
        "sockethandler",
        "httphandler",
        "sysloghandler",
    ):
        assert forbidden not in source


def test_result_json_renderer_is_independent_from_diagnostic_events() -> None:
    path = _SOURCE_ROOT / "cli" / "json_output.py"
    imports = _imports(path)

    assert not any(
        name == "redforge.observability"
        or name.startswith("redforge.observability.")
        for name in imports
    )


def test_cli_console_script_metadata_targets_public_main() -> None:
    metadata = (_REPOSITORY_ROOT / "pyproject.toml").read_text(
        encoding="utf-8"
    )

    assert '[project.scripts]\nredforge = "redforge.cli:main"' in metadata


def test_cli_json_renderer_has_no_adapter_tool_context_or_io_dependencies() -> None:
    path = _SOURCE_ROOT / "cli" / "json_output.py"
    imports = _imports(path)
    forbidden = (
        "redforge.adapters",
        "redforge.capabilities",
        "redforge.sdk.context",
        "redforge.sdk.tool",
        "subprocess",
        "pathlib",
        "os",
        "time",
        "datetime",
        "random",
        "uuid",
    )
    assert not any(
        name == prefix or name.startswith(f"{prefix}.")
        for name in imports
        for prefix in forbidden
    )

    source = path.read_text(encoding="utf-8").lower()
    for forbidden_text in (
        "default=str",
        "asdict",
        "__dict__",
        "traceback",
        "format_exc",
        "repr(exc)",
        "context.",
        "final_context",
        "execution_history",
        "stdout",
        "stderr",
        "argv",
        "environment",
        "executable_path",
        "open(",
        "write_text",
        "write_bytes",
        "timestamp",
    ):
        assert forbidden_text not in source


def test_real_tool_adapters_delegate_process_execution_to_tool_runner() -> None:
    adapter_paths = tuple(
        _SOURCE_ROOT / "adapters" / name
        for name in (
            "subfinder.py",
            "httpx.py",
            "katana.py",
            "technology_detection.py",
        )
    )
    for path in adapter_paths:
        imports = _imports(path)
        source = path.read_text(encoding="utf-8")
        assert "subprocess" not in imports, path
        assert "os" not in imports, path
        assert "shell=True" not in source, path
        assert "os.system" not in source, path
        assert "Popen(" not in source, path
        assert "ToolRunner" in source, path
        assert ".run(self._definition, invocation)" in source, path


def test_cli_application_and_runtime_do_not_know_tool_commands() -> None:
    forbidden = (
        "subfinder",
        "httpx",
        "katana",
        "whatweb",
        "shell=true",
        "toolinvocation(",
        "subprocess",
    )
    for package in ("cli", "application", "runtime"):
        for path in (_SOURCE_ROOT / package).rglob("*.py"):
            source = path.read_text(encoding="utf-8").lower()
            for value in forbidden:
                assert value not in source, path


def test_scan_inspection_cannot_construct_or_execute_runtime() -> None:
    path = _SOURCE_ROOT / "application" / "inspection.py"
    imports = _imports(path)
    source = path.read_text(encoding="utf-8")

    for forbidden_import in (
        "redforge.sdk.context",
        "redforge.runtime",
        "redforge.planning.builder",
        "redforge.planning.execution",
        "redforge.adapters",
    ):
        assert not any(
            name == forbidden_import
            or name.startswith(f"{forbidden_import}.")
            for name in imports
        )
    for forbidden_source in (
        "Context(",
        "PipelineBuilder(",
        "PlannedExecution(",
        "create_initial_context(",
        ".create(",
    ):
        assert forbidden_source not in source
    assert "definition.requirements" in source


def test_no_tool_installation_automation_is_present() -> None:
    forbidden = (
        "subprocess.run([\"pip\"",
        "subprocess.run([\"winget\"",
        "subprocess.run([\"choco\"",
        "subprocess.run([\"apt\"",
        "os.system(",
        "--install-tools",
    )
    for path in _SOURCE_ROOT.rglob("*.py"):
        source = path.read_text(encoding="utf-8").lower()
        for value in forbidden:
            assert value not in source, path


def test_local_smoke_seed_adapters_are_transport_free() -> None:
    path = _SOURCE_ROOT / "adapters" / "local_smoke.py"
    imports = _imports(path)
    forbidden = (
        "subprocess",
        "socket",
        "urllib",
        "requests",
        "httpx",
        "redforge.adapters.tool_runner",
    )

    assert not any(
        name == prefix or name.startswith(f"{prefix}.")
        for name in imports
        for prefix in forbidden
    )


def test_doctor_is_isolated_from_domain_planning_runtime_and_capabilities() -> None:
    for package in ("domain", "planning", "runtime", "capabilities"):
        for path in (_SOURCE_ROOT / package).rglob("*.py"):
            imports = _imports(path)
            assert not any(
                name == "redforge.doctor"
                or name.startswith("redforge.doctor.")
                or name == "redforge.application.doctor"
                for name in imports
            ), path


def test_application_doctor_is_provider_neutral_and_target_free() -> None:
    path = _SOURCE_ROOT / "application" / "doctor.py"
    imports = _imports(path)
    source = path.read_text(encoding="utf-8")

    assert not any(
        name == "redforge.adapters"
        or name.startswith("redforge.adapters.")
        for name in imports
    )
    for forbidden in (
        "Context(",
        "ScanConfig(",
        "ExecutionPlan(",
        "Pipeline(",
        "ToolInvocation(",
        "subprocess",
        "socket",
        "urllib",
        "requests",
        "os.environ",
        "getenv",
    ):
        assert forbidden not in source


def test_doctor_adapters_do_not_import_cli_or_network_transports() -> None:
    for filename in ("platform.py", "readiness.py"):
        path = _SOURCE_ROOT / "adapters" / filename
        imports = _imports(path)
        for forbidden in (
            "redforge.cli",
            "subprocess",
            "socket",
            "urllib",
            "requests",
        ):
            assert not any(
                name == forbidden or name.startswith(f"{forbidden}.")
                for name in imports
            ), path


def test_doctor_json_uses_explicit_serialization_only() -> None:
    source = (
        _SOURCE_ROOT / "cli" / "doctor_output.py"
    ).read_text(encoding="utf-8")

    for forbidden in ("default=str", "__dict__", "asdict", "Context"):
        assert forbidden not in source
