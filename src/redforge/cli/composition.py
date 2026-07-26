"""Explicit production composition root for the minimal CLI."""

from redforge.adapters import (
    LocalSubprocessToolRunner,
    ToolRunnerReadinessProbe,
    create_default_tool_registry,
)
from redforge.application import ReadinessRegistry, ScanOrchestrator
from redforge.planning import (
    CapabilityDependencies,
    create_default_factory_registry,
    create_default_registry,
)


def create_cli_orchestrator() -> ScanOrchestrator:
    """Compose local reconnaissance tools without a hidden vulnerability provider."""
    runner = LocalSubprocessToolRunner()
    return ScanOrchestrator(
        capability_registry=create_default_registry(),
        factory_registry=create_default_factory_registry(
            dependencies=CapabilityDependencies(tool_runner=runner)
        ),
        readiness_registry=ReadinessRegistry(
            tool_registry=create_default_tool_registry(),
            tool_probe=ToolRunnerReadinessProbe(runner),
        ),
    )
