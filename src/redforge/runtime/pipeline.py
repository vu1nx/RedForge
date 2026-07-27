"""Sequential pipeline for capability execution."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, TypeGuard, cast

from redforge.domain.target import Target
from redforge.observability import (
    DiagnosticEvent,
    DiagnosticEventSink,
    DiagnosticEventType,
    DiagnosticFields,
    DiagnosticSeverity,
    NullDiagnosticEventSink,
    emit_safely,
)
from redforge.runtime.execution_policy import (
    DeadlinePhase,
    DeadlineViolation,
    ExecutionDeadlineExceeded,
    ExecutionPolicy,
    ExecutionPolicyViolation,
    StateLimitExceeded,
    StateLimitViolation,
)
from redforge.runtime.pipeline_state import CAPABILITY_OUTPUT_CONTRACTS
from redforge.sdk.capability import Capability
from redforge.sdk.capability_id import CapabilityId, normalize_capability_id
from redforge.sdk.context import Context
from redforge.sdk.result import Result, StatePublication, Status
from redforge.sdk.state import PipelineStateKey, validate_pipeline_state_value

_STATUS_PRECEDENCE: dict[Status, int] = {
    Status.SUCCESS: 0,
    Status.PARTIAL: 1,
    Status.FAILURE: 2,
    Status.ERROR: 3,
}


def combine_status(current: Status, observed: Status) -> Status:
    """Return the more severe of two capability outcomes."""
    return current if _STATUS_PRECEDENCE[current] >= _STATUS_PRECEDENCE[observed] else observed


def _is_valid_result(value: object) -> TypeGuard[Result[Any]]:
    """Return whether a capability value satisfies the runtime Result contract."""
    return isinstance(value, Result) and isinstance(cast(object, value.status), Status)


@dataclass(frozen=True, slots=True)
class _NormalizedPublications:
    """Validated atomic publications for one capability execution."""

    explicit: tuple[StatePublication, ...] = ()
    legacy: tuple[str, object] | None = None


def _normalize_capability_result(
    *,
    capability_name: str,
    result: Result[Any],
    declared_outputs: tuple[PipelineStateKey, ...] | None,
) -> _NormalizedPublications:
    """Validate explicit publications or normalize one legacy data value."""
    publications_value = cast(object, result.publications)
    if not isinstance(publications_value, tuple) or not all(
        isinstance(item, StatePublication) for item in cast(tuple[object, ...], publications_value)
    ):
        raise ValueError("invalid publication collection")
    publications = cast(tuple[StatePublication, ...], publications_value)
    keys = tuple(publication.key for publication in publications)
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate state publications")

    if result.status in {Status.FAILURE, Status.ERROR}:
        if publications:
            raise ValueError("stopping result contains publications")
        return _NormalizedPublications()

    if publications:
        if result.data is not None:
            raise ValueError("explicit publications conflict with legacy data")
        if declared_outputs is None:
            raise ValueError("explicit publications require an output contract")
        declared = set(declared_outputs)
        if any(publication.key not in declared for publication in publications):
            raise ValueError("undeclared state publication")
        return _NormalizedPublications(explicit=publications)

    if result.data is None:
        return _NormalizedPublications()
    if declared_outputs is None:
        return _NormalizedPublications(legacy=(capability_name, result.data))
    if len(declared_outputs) != 1:
        raise ValueError("legacy data is ambiguous for multiple outputs")
    return _NormalizedPublications(explicit=(StatePublication(declared_outputs[0], result.data),))


def _invalid_result(capability_name: str) -> Result[Any]:
    """Return a sanitized invalid-result error."""
    return Result(
        status=Status.ERROR,
        data=None,
        errors=[f"Capability '{capability_name}' returned an invalid result"],
        metadata={"error_kind": "invalid_capability_result"},
    )


@dataclass(frozen=True, slots=True)
class CapabilityExecution:
    """One capability result preserved in pipeline execution order."""

    capability_name: str
    """Stable registered capability name."""

    result: Result[Any]
    """Original capability result, including diagnostics and metadata."""

    capability_id: CapabilityId | None = None
    """Typed identity when execution was explicitly configured or planned."""

    executed: bool = True
    """Whether the capability implementation was invoked."""

    policy_violation: ExecutionPolicyViolation | None = None
    """Typed sanitized policy failure associated with this history entry."""


@dataclass(frozen=True, slots=True)
class _PipelineEntry:
    """Runtime implementation associated with optional typed identity."""

    capability: Capability
    capability_id: CapabilityId | None = None


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Immutable result of a pipeline execution."""

    status: Status
    """Final status of the pipeline execution."""

    executed_capabilities: tuple[str, ...]
    """Names of capabilities that were executed."""

    context: Context
    """Final context after pipeline execution."""

    last_result: Result[Any] | None
    """Result from the last executed capability."""

    execution_order: tuple[str, ...]
    """Registered capability execution order."""

    executions: tuple[CapabilityExecution, ...]
    """Immutable history containing one entry per executed capability."""


class Pipeline:
    """Lightweight sequential orchestrator for capability execution.

    Capabilities are executed in registration order. Each capability receives
    the same Context instance, and usable SUCCESS or PARTIAL output is stored in
    Context.state for downstream capabilities.
    """

    def __init__(
        self,
        *,
        output_contracts: (
            Mapping[CapabilityId, tuple[PipelineStateKey, ...]]
            | Mapping[str, tuple[PipelineStateKey, ...]]
            | None
        ) = None,
        output_keys: Mapping[str, str] | None = None,
    ) -> None:
        """Initialize a pipeline with isolated declared output contracts.

        ``output_keys`` preserves the previous single-output configuration API.
        """
        if output_contracts is not None and output_keys is not None:
            raise ValueError("use output_contracts or output_keys, not both")
        self._entries: list[_PipelineEntry] = []
        configured: (
            Mapping[CapabilityId, tuple[PipelineStateKey, ...]]
            | Mapping[str, tuple[PipelineStateKey, ...]]
        )
        if output_contracts is not None:
            configured = output_contracts
        elif output_keys is not None:
            configured = {
                normalize_capability_id(name): (PipelineStateKey(key),)
                for name, key in output_keys.items()
            }
        else:
            configured = CAPABILITY_OUTPUT_CONTRACTS
        self._output_contracts = self._validate_output_contracts(configured)

    @staticmethod
    def _validate_output_contracts(
        contracts: Mapping[
            CapabilityId, tuple[PipelineStateKey, ...]
        ]
        | Mapping[str, tuple[PipelineStateKey, ...]],
    ) -> dict[CapabilityId, tuple[PipelineStateKey, ...]]:
        validated: dict[CapabilityId, tuple[PipelineStateKey, ...]] = {}
        for capability_id, keys in contracts.items():
            try:
                identity = normalize_capability_id(capability_id)
            except (TypeError, ValueError):
                raise ValueError("output contract capability ID is invalid") from None
            keys_value = cast(object, keys)
            if not isinstance(keys_value, tuple) or not keys_value:
                raise ValueError("output contract must contain state keys")
            if not all(
                isinstance(key, PipelineStateKey) for key in cast(tuple[object, ...], keys_value)
            ):
                raise TypeError("output contract keys must be PipelineStateKey values")
            typed_keys = cast(tuple[PipelineStateKey, ...], keys_value)
            if len(typed_keys) != len(set(typed_keys)):
                raise ValueError("output contract contains duplicate state keys")
            validated[identity] = tuple(sorted(typed_keys))
        return validated

    def add(
        self,
        capability: Capability,
        *,
        capability_id: CapabilityId | str | None = None,
        provides: tuple[PipelineStateKey, ...] | None = None,
    ) -> None:
        """Register a capability for sequential execution.

        Args:
            capability: Capability instance to append to the pipeline.
            capability_id: Optional explicit stable runtime identity.
            provides: Optional explicit manual output contract.
        """
        identity = (
            normalize_capability_id(capability_id)
            if capability_id is not None
            else None
        )
        if identity is not None:
            try:
                implementation_id = normalize_capability_id(capability.name)
            except (TypeError, ValueError):
                raise ValueError("runtime capability identity is invalid") from None
            if implementation_id != identity:
                raise ValueError("runtime capability identity does not match")
        if provides is not None:
            if identity is None:
                raise ValueError("manual output contracts require capability_id")
            validated = self._validate_output_contracts(
                {identity: provides}
            )[identity]
            existing = self._output_contracts.get(identity)
            if existing is not None and existing != validated:
                raise ValueError("manual output contract does not match")
            self._output_contracts[identity] = validated
        if any(
            (
                identity is not None
                and item.capability_id is not None
                and item.capability_id == identity
            )
            or item.capability.name == capability.name
            for item in self._entries
        ):
            raise ValueError(f"duplicate capability name: '{capability.name}'")
        self._entries.append(_PipelineEntry(capability, identity))

    def run(
        self,
        target: Target | str | Context,
        *,
        policy: ExecutionPolicy | None = None,
        diagnostic_sink: DiagnosticEventSink | None = None,
    ) -> PipelineResult:
        """Execute registered capabilities sequentially.

        Args:
            target: Target identifier, Target domain object, or existing Context.

        Returns:
            PipelineResult containing final status, context, and execution details.
        """
        if isinstance(target, Context):
            context = target
        else:
            target_id = target.identifier if isinstance(target, Target) else target
            context = Context(target_id=target_id)
        state = context.state
        sink = (
            diagnostic_sink
            if diagnostic_sink is not None
            else NullDiagnosticEventSink()
        )
        execution_order = tuple(
            entry.capability.name for entry in self._entries
        )

        if not self._entries:
            return PipelineResult(
                status=Status.SUCCESS,
                executed_capabilities=(),
                context=context,
                last_result=None,
                execution_order=execution_order,
                executions=(),
            )

        executions: list[CapabilityExecution] = []
        last_result: Result[Any] | None = None
        aggregate_status = Status.SUCCESS

        for entry in self._entries:
            capability = entry.capability
            runtime_id = entry.capability_id
            diagnostic_id = (
                runtime_id.value
                if runtime_id is not None
                else _safe_capability_id(capability.name)
            )
            _emit_capability_started(sink, diagnostic_id)
            try:
                if policy is not None:
                    policy.check_deadline()
            except ExecutionDeadlineExceeded:
                violation = DeadlineViolation(
                    phase=DeadlinePhase.BEFORE_CAPABILITY
                )
                result = _policy_failure(violation)
                last_result = result
                executions.append(
                    CapabilityExecution(
                        capability_name=capability.name,
                        result=result,
                        capability_id=runtime_id,
                        executed=False,
                        policy_violation=violation,
                    )
                )
                aggregate_status = combine_status(
                    aggregate_status,
                    result.status,
                )
                _emit_policy_violation(
                    sink,
                    violation,
                    diagnostic_id,
                )
                _emit_capability_terminal(
                    sink,
                    diagnostic_id,
                    result.status,
                )
                break
            if runtime_id is None:
                try:
                    legacy_id = normalize_capability_id(capability.name)
                except (TypeError, ValueError):
                    legacy_id = None
                declared_outputs = (
                    self._output_contracts.get(legacy_id)
                    if legacy_id is not None
                    else None
                )
            else:
                declared_outputs = self._output_contracts.get(runtime_id)
            normalized = _NormalizedPublications()
            policy_violation: ExecutionPolicyViolation | None = None
            try:
                candidate = cast(object, capability.execute(context))
            except Exception:
                result: Result[Any] = Result(
                    status=Status.ERROR,
                    data=None,
                    errors=[
                        f"Capability '{capability.name}' failed with an unexpected execution error"
                    ],
                    metadata={"error_kind": "unexpected_execution_error"},
                )
            else:
                if _is_valid_result(candidate):
                    try:
                        normalized = _normalize_capability_result(
                            capability_name=capability.name,
                            result=candidate,
                            declared_outputs=declared_outputs,
                        )
                    except Exception:
                        result = _invalid_result(capability.name)
                    else:
                        result = candidate
                else:
                    result = _invalid_result(capability.name)

            if result.status in {Status.SUCCESS, Status.PARTIAL}:
                try:
                    for publication in normalized.explicit:
                        validate_pipeline_state_value(
                            publication.key,
                            publication.value,
                        )
                    if policy is not None:
                        policy.check_deadline()
                        policy.validate_publications(normalized.explicit)
                except ExecutionDeadlineExceeded:
                    policy_violation = DeadlineViolation(
                        phase=DeadlinePhase.AFTER_CAPABILITY
                    )
                    result = _policy_failure(policy_violation)
                except StateLimitExceeded as error:
                    policy_violation = error.violation
                    result = _policy_failure(policy_violation)
                except Exception:
                    result = _invalid_result(capability.name)

            last_result = result
            executions.append(
                CapabilityExecution(
                    capability_name=capability.name,
                    result=result,
                    capability_id=runtime_id,
                    policy_violation=policy_violation,
                )
            )
            aggregate_status = combine_status(aggregate_status, result.status)

            if result.status in {Status.SUCCESS, Status.PARTIAL}:
                try:
                    context.publish_many(normalized.explicit)
                except Exception:
                    result = _invalid_result(capability.name)
                    last_result = result
                    executions[-1] = CapabilityExecution(
                        capability_name=capability.name,
                        result=result,
                        capability_id=runtime_id,
                    )
                    aggregate_status = combine_status(
                        aggregate_status, result.status
                    )
                    break
                if normalized.legacy is not None:
                    legacy_key, legacy_value = normalized.legacy
                    state[legacy_key] = legacy_value

            if policy_violation is not None:
                _emit_policy_violation(
                    sink,
                    policy_violation,
                    diagnostic_id,
                )
            _emit_capability_terminal(
                sink,
                diagnostic_id,
                result.status,
            )
            if result.status in {Status.FAILURE, Status.ERROR}:
                break

        return PipelineResult(
            status=aggregate_status,
            executed_capabilities=tuple(
                execution.capability_name
                for execution in executions
                if execution.executed
            ),
            context=context,
            last_result=last_result,
            execution_order=execution_order,
            executions=tuple(executions),
        )


def _policy_failure(
    violation: ExecutionPolicyViolation,
) -> Result[None]:
    """Return one sanitized FAILURE for a typed execution-policy violation."""
    if isinstance(violation, StateLimitViolation):
        return Result(
            status=Status.FAILURE,
            data=None,
            errors=[
                "State limit exceeded: "
                f"{violation.state_key.name} "
                f"observed={violation.observed} "
                f"allowed={violation.allowed}"
            ],
            metadata={
                "error_kind": "state_limit_exceeded",
                "state_key": violation.state_key.value,
                "observed": violation.observed,
                "allowed": violation.allowed,
            },
        )
    return Result(
        status=Status.FAILURE,
        data=None,
        errors=["Execution deadline exceeded"],
        metadata={
            "error_kind": "execution_deadline_exceeded",
            "phase": violation.phase.value,
        },
    )


def _safe_capability_id(name: str) -> str | None:
    try:
        return normalize_capability_id(name).value
    except (TypeError, ValueError):
        return None


def _emit_capability_started(
    sink: DiagnosticEventSink,
    capability_id: str | None,
) -> None:
    emit_safely(
        sink,
        DiagnosticEvent(
            event_type=DiagnosticEventType.CAPABILITY_STARTED,
            severity=DiagnosticSeverity.INFO,
            message="Capability started",
            fields=DiagnosticFields(capability_id=capability_id),
        ),
    )


def _emit_capability_terminal(
    sink: DiagnosticEventSink,
    capability_id: str | None,
    status: Status,
) -> None:
    event_type, severity, message = {
        Status.SUCCESS: (
            DiagnosticEventType.CAPABILITY_COMPLETED,
            DiagnosticSeverity.INFO,
            "Capability completed",
        ),
        Status.PARTIAL: (
            DiagnosticEventType.CAPABILITY_PARTIAL,
            DiagnosticSeverity.WARNING,
            "Capability completed partially",
        ),
        Status.FAILURE: (
            DiagnosticEventType.CAPABILITY_FAILED,
            DiagnosticSeverity.ERROR,
            "Capability failed",
        ),
        Status.ERROR: (
            DiagnosticEventType.CAPABILITY_ERROR,
            DiagnosticSeverity.ERROR,
            "Capability error",
        ),
    }[status]
    emit_safely(
        sink,
        DiagnosticEvent(
            event_type=event_type,
            severity=severity,
            message=message,
            fields=DiagnosticFields(
                capability_id=capability_id,
                runtime_status=status.name,
            ),
        ),
    )


def _emit_policy_violation(
    sink: DiagnosticEventSink,
    violation: ExecutionPolicyViolation,
    capability_id: str | None,
) -> None:
    if isinstance(violation, StateLimitViolation):
        event = DiagnosticEvent(
            event_type=DiagnosticEventType.POLICY_LIMIT_EXCEEDED,
            severity=DiagnosticSeverity.ERROR,
            message="State limit exceeded",
            fields=DiagnosticFields(
                capability_id=capability_id,
                policy_type="state_limit",
                state_key=violation.state_key.name,
                observed=violation.observed,
                allowed=violation.allowed,
            ),
        )
    else:
        event = DiagnosticEvent(
            event_type=DiagnosticEventType.POLICY_DEADLINE_EXCEEDED,
            severity=DiagnosticSeverity.ERROR,
            message="Execution deadline exceeded",
            fields=DiagnosticFields(
                capability_id=capability_id,
                policy_type="deadline",
            ),
        )
    emit_safely(sink, event)
