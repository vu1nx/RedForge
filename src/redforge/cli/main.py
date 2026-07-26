"""Thin command-line adapter over RedForge application contracts."""

import argparse
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import NoReturn, Protocol, TextIO, TypeGuard, cast

from redforge.application import (
    PreflightResult,
    ReadinessStatus,
    ScanConfig,
    ScanConfigurationError,
    ScanOrchestrator,
    ScanPreflightError,
    ScanResult,
)
from redforge.cli.json_output import (
    JsonOutcomeType,
    JsonReasonCode,
    JsonScanOutcome,
    build_completed_json_outcome,
    build_error_json_outcome,
    build_preflight_json_outcome,
    render_json_outcome,
)
from redforge.planning import PipelineBuildError
from redforge.runtime import DeadlineViolation, StateLimitViolation


class ExitCode(IntEnum):
    """Stable initial process exit contract."""

    ACCEPTED = 0
    INVALID_INPUT = 2
    NOT_READY = 3
    NOT_ACCEPTED = 4
    INTERNAL_ERROR = 5
    INTERRUPTED = 130


class ScanPreset(StrEnum):
    """Application scan preset exposed by the first CLI."""

    RECONNAISSANCE = "reconnaissance"
    FULL = "full"


class OutputFormat(StrEnum):
    """Stable terminal representation selected explicitly by the operator."""

    HUMAN = "human"
    JSON = "json"


class HelpScope(StrEnum):
    """Parser help page requested without process termination."""

    ROOT = "root"
    SCAN = "scan"


@dataclass(frozen=True, slots=True)
class CliOptions:
    """Typed parser output without argparse internals."""

    target: str | None
    preset: ScanPreset = ScanPreset.RECONNAISSANCE
    output_format: OutputFormat = OutputFormat.HUMAN
    allow_partial_results: bool = False
    help_scope: HelpScope | None = None


class CliUsageError(ValueError):
    """Expected non-exiting parser failure."""

    def __init__(
        self,
        message: str,
        *,
        output_format: OutputFormat | None = None,
        preset: ScanPreset | None = None,
    ) -> None:
        super().__init__(message)
        self.output_format = output_format
        self.preset = preset


class ScanExecutor(Protocol):
    """Narrow application service consumed by the command adapter."""

    def run(self, config: ScanConfig) -> ScanResult:
        """Execute one validated scan."""
        ...


type OrchestratorFactory = Callable[[], ScanExecutor]


class _NonExitingParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise CliUsageError(message)


def _configure_scan_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "target",
        nargs="?",
        help="Authorized DNS root to assess; URLs, IPs, and wildcards are invalid.",
    )
    parser.add_argument(
        "--preset",
        choices=tuple(item.value for item in ScanPreset),
        default=ScanPreset.RECONNAISSANCE.value,
        help="Scan preset: reconnaissance (default) or full.",
    )
    parser.add_argument(
        "--output",
        choices=tuple(item.value for item in OutputFormat),
        default=OutputFormat.HUMAN.value,
        help="Output format: human (default) or versioned JSON.",
    )
    parser.add_argument(
        "--allow-partial-results",
        action="store_true",
        help="Accept a PARTIAL runtime result; no retry is performed.",
    )
    parser.add_argument(
        "-h",
        "--help",
        action="store_true",
        dest="help_requested",
        help="Show this help message.",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build a fresh parser without reading argv or performing composition."""
    parser = _NonExitingParser(
        prog="redforge",
        add_help=False,
        description="RedForge application scan control.",
        epilog=(
            "Only scan systems you are explicitly authorized to assess. "
            "Exit 0 means accepted; 2 invalid input; 3 not ready; "
            "4 executed but not accepted; 5 internal failure; "
            "130 interrupted."
        ),
    )
    parser.add_argument(
        "-h",
        "--help",
        action="store_true",
        dest="root_help",
        help="Show this help message.",
    )
    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser(
        "scan",
        add_help=False,
        help="Run one authorized application scan.",
        description="Prepare, preflight, and execute one authorized scan.",
        epilog="Only scan systems you are explicitly authorized to assess.",
    )
    _configure_scan_parser(scan)
    return parser


def _build_scan_help_parser() -> argparse.ArgumentParser:
    parser = _NonExitingParser(
        prog="redforge scan",
        add_help=False,
        description="Prepare, preflight, and execute one authorized scan.",
        epilog=(
            "Limits use validated application defaults and reject oversized "
            "canonical publications. Only scan systems you are explicitly "
            "authorized to assess. Exit codes: 0 accepted, 2 invalid input, "
            "3 not ready, 4 completed but not accepted, 5 internal error, "
            "130 interrupted."
        ),
    )
    _configure_scan_parser(parser)
    return parser


def parse_cli_args(
    argv: Sequence[str] | None = None,
) -> CliOptions:
    """Parse argv once into immutable typed CLI options."""
    parser = build_parser()
    namespace = parser.parse_args(
        list(argv) if argv is not None else None
    )
    if cast(bool, namespace.root_help):
        return CliOptions(target=None, help_scope=HelpScope.ROOT)
    command = cast(str | None, namespace.command)
    if command != "scan":
        raise CliUsageError("the scan command is required")
    if cast(bool, namespace.help_requested):
        return CliOptions(target=None, help_scope=HelpScope.SCAN)
    target = cast(str | None, namespace.target)
    if target is None:
        raise CliUsageError(
            "scan target is required",
            output_format=OutputFormat(cast(str, namespace.output)),
            preset=ScanPreset(cast(str, namespace.preset)),
        )
    return CliOptions(
        target=target,
        preset=ScanPreset(cast(str, namespace.preset)),
        output_format=OutputFormat(cast(str, namespace.output)),
        allow_partial_results=cast(
            bool,
            namespace.allow_partial_results,
        ),
    )


def create_scan_config(options: CliOptions) -> ScanConfig:
    """Map typed CLI options through canonical application constructors."""
    if options.target is None:
        raise CliUsageError("scan target is required")
    constructor = (
        ScanConfig.for_reconnaissance
        if options.preset is ScanPreset.RECONNAISSANCE
        else ScanConfig.for_full_assessment
    )
    return constructor(
        options.target,
        allow_partial_results=options.allow_partial_results,
    )


def render_scan_result(
    result: ScanResult,
    *,
    preset: ScanPreset,
) -> str:
    """Render one concise result without Context evidence or raw diagnostics."""
    lines = [
        "Scan completed",
        f"Target: {result.config.scope.root.value}",
        f"Preset: {preset.value}",
        f"Status: {result.runtime_status.name}",
        f"Accepted: {'yes' if result.accepted else 'no'}",
        f"Capabilities executed: {len(result.pipeline_result.executed_capabilities)}",
    ]
    violation = result.policy_violation
    if isinstance(violation, StateLimitViolation):
        lines.append(
            "Policy violation: "
            f"{violation.state_key.name} "
            f"observed={violation.observed} "
            f"allowed={violation.allowed}"
        )
    elif isinstance(violation, DeadlineViolation):
        lines.append("Policy violation: execution deadline exceeded")
    return "\n".join(lines)


def render_preflight_result(result: PreflightResult) -> str:
    """Render only sanitized non-ready checks in deterministic result order."""
    lines = ["Scan could not start", "Readiness checks failed:"]
    for check in result.checks:
        if check.status is ReadinessStatus.READY:
            continue
        subject = check.subject
        if subject.tool_id is not None:
            identity = subject.tool_id.value
        elif subject.capability_id is not None:
            identity = subject.capability_id.value
        else:
            role = subject.provider_role
            if role is None:
                raise ValueError("readiness subject has no identity")
            identity = role.value
        reason = check.reason
        if reason is None:
            raise ValueError("non-ready check has no reason")
        lines.append(
            f"- {subject.kind.value.replace('_', ' ')} "
            f"{check.status.value}: {identity} ({reason.value})"
        )
    return "\n".join(lines)


def run_scan_command(
    config: ScanConfig,
    *,
    orchestrator_factory: OrchestratorFactory,
) -> ScanResult:
    """Invoke one injected orchestrator once with validated configuration."""
    orchestrator = orchestrator_factory()
    return orchestrator.run(config)


def main(
    argv: Sequence[str] | None = None,
    *,
    orchestrator_factory: OrchestratorFactory | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the reusable CLI boundary and return a stable integer exit code."""
    output = stdout if stdout is not None else sys.stdout
    errors = stderr if stderr is not None else sys.stderr
    factory = (
        orchestrator_factory
        if orchestrator_factory is not None
        else _default_orchestrator_factory
    )
    options: CliOptions | None = None
    config: ScanConfig | None = None
    try:
        options = parse_cli_args(argv)
        if options.help_scope is HelpScope.ROOT:
            output.write(f"{build_parser().format_help()}\n")
            return int(ExitCode.ACCEPTED)
        if options.help_scope is HelpScope.SCAN:
            output.write(f"{_build_scan_help_parser().format_help()}\n")
            return int(ExitCode.ACCEPTED)
        config = create_scan_config(options)
        result = run_scan_command(
            config,
            orchestrator_factory=factory,
        )
        exit_code = (
            ExitCode.ACCEPTED
            if result.accepted
            else ExitCode.NOT_ACCEPTED
        )
        if options.output_format is OutputFormat.JSON:
            _write_json(
                output,
                build_completed_json_outcome(
                    result,
                    preset=options.preset.value,
                    exit_code=int(exit_code),
                ),
            )
            return int(exit_code)
        output.write(
            f"{render_scan_result(result, preset=options.preset)}\n"
        )
        return int(exit_code)
    except CliUsageError as error:
        if error.output_format is OutputFormat.JSON:
            _write_json(
                output,
                build_error_json_outcome(
                    outcome=JsonOutcomeType.INVALID_INPUT,
                    exit_code=int(ExitCode.INVALID_INPUT),
                    reason_code=JsonReasonCode.INVALID_TARGET,
                    message="invalid scan target",
                    preset=(
                        error.preset.value
                        if error.preset is not None
                        else None
                    ),
                ),
            )
            return int(ExitCode.INVALID_INPUT)
        errors.write(f"Invalid command: {error}\n")
        return int(ExitCode.INVALID_INPUT)
    except ScanConfigurationError:
        if _json_selected(options):
            _write_json(
                output,
                build_error_json_outcome(
                    outcome=JsonOutcomeType.INVALID_INPUT,
                    exit_code=int(ExitCode.INVALID_INPUT),
                    reason_code=JsonReasonCode.INVALID_TARGET,
                    message="invalid scan target",
                    preset=options.preset.value,
                ),
            )
            return int(ExitCode.INVALID_INPUT)
        errors.write("Invalid input: scan target or options are invalid\n")
        return int(ExitCode.INVALID_INPUT)
    except ScanPreflightError as error:
        if _json_selected(options) and config is not None:
            _write_json(
                output,
                build_preflight_json_outcome(
                    error.result,
                    exit_code=int(ExitCode.NOT_READY),
                    target=config.scope.root.value,
                    preset=options.preset.value,
                ),
            )
            return int(ExitCode.NOT_READY)
        errors.write(f"{render_preflight_result(error.result)}\n")
        return int(ExitCode.NOT_READY)
    except PipelineBuildError:
        if _json_selected(options) and config is not None:
            _write_json(
                output,
                build_error_json_outcome(
                    outcome=JsonOutcomeType.NOT_READY,
                    exit_code=int(ExitCode.NOT_READY),
                    reason_code=JsonReasonCode.COMPOSITION_FAILED,
                    message="scan composition is unavailable",
                    target=config.scope.root.value,
                    preset=options.preset.value,
                ),
            )
            return int(ExitCode.NOT_READY)
        errors.write("Scan could not start\nComposition is invalid\n")
        return int(ExitCode.NOT_READY)
    except KeyboardInterrupt:
        if _json_selected(options):
            _write_json(
                output,
                build_error_json_outcome(
                    outcome=JsonOutcomeType.INTERRUPTED,
                    exit_code=int(ExitCode.INTERRUPTED),
                    reason_code=JsonReasonCode.INTERRUPTED,
                    message="scan was interrupted",
                ),
            )
            return int(ExitCode.INTERRUPTED)
        errors.write("Scan interrupted\n")
        return int(ExitCode.INTERRUPTED)
    except Exception:
        if _json_selected(options):
            _write_json(
                output,
                build_error_json_outcome(
                    outcome=JsonOutcomeType.INTERNAL_ERROR,
                    exit_code=int(ExitCode.INTERNAL_ERROR),
                    reason_code=JsonReasonCode.INTERNAL_ERROR,
                    message="an unexpected internal error occurred",
                ),
            )
            return int(ExitCode.INTERNAL_ERROR)
        errors.write("RedForge encountered an unexpected internal failure\n")
        return int(ExitCode.INTERNAL_ERROR)

def _json_selected(
    options: CliOptions | None,
) -> TypeGuard[CliOptions]:
    return (
        options is not None
        and options.output_format is OutputFormat.JSON
    )


def _write_json(output: TextIO, outcome: JsonScanOutcome) -> None:
    output.write(f"{render_json_outcome(outcome)}\n")


def _default_orchestrator_factory() -> ScanOrchestrator:
    """Import and construct production composition only when a scan is run."""
    from redforge.cli.composition import create_cli_orchestrator

    return create_cli_orchestrator()
