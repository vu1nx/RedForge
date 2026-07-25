"""Sequential pipeline for capability execution."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, TypeGuard, cast

from redforge.domain.target import Target
from redforge.runtime.pipeline_state import CAPABILITY_OUTPUT_CONTRACTS
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, StatePublication, Status
from redforge.sdk.state import PipelineStateKey

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
        output_contracts: (Mapping[str, tuple[PipelineStateKey, ...]] | None) = None,
        output_keys: Mapping[str, str] | None = None,
    ) -> None:
        """Initialize a pipeline with isolated declared output contracts.

        ``output_keys`` preserves the previous single-output configuration API.
        """
        if output_contracts is not None and output_keys is not None:
            raise ValueError("use output_contracts or output_keys, not both")
        self._capabilities: list[Capability] = []
        configured: Mapping[str, tuple[PipelineStateKey, ...]]
        if output_contracts is not None:
            configured = output_contracts
        elif output_keys is not None:
            configured = {name: (PipelineStateKey(key),) for name, key in output_keys.items()}
        else:
            configured = CAPABILITY_OUTPUT_CONTRACTS
        self._output_contracts = self._validate_output_contracts(configured)

    @staticmethod
    def _validate_output_contracts(
        contracts: Mapping[str, tuple[PipelineStateKey, ...]],
    ) -> dict[str, tuple[PipelineStateKey, ...]]:
        validated: dict[str, tuple[PipelineStateKey, ...]] = {}
        for name, keys in contracts.items():
            if not isinstance(cast(object, name), str) or not name:
                raise ValueError("output contract capability name is invalid")
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
            validated[name] = tuple(sorted(typed_keys))
        return validated

    def add(self, capability: Capability) -> None:
        """Register a capability for sequential execution.

        Args:
            capability: Capability instance to append to the pipeline.
        """
        if any(item.name == capability.name for item in self._capabilities):
            raise ValueError(f"duplicate capability name: '{capability.name}'")
        self._capabilities.append(capability)

    def run(self, target: Target | str | Context) -> PipelineResult:
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
        execution_order = tuple(capability.name for capability in self._capabilities)

        if not self._capabilities:
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

        for capability in self._capabilities:
            normalized = _NormalizedPublications()
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
                            declared_outputs=self._output_contracts.get(capability.name),
                        )
                    except Exception:
                        result = _invalid_result(capability.name)
                    else:
                        result = candidate
                else:
                    result = _invalid_result(capability.name)

            last_result = result
            executions.append(
                CapabilityExecution(
                    capability_name=capability.name,
                    result=result,
                )
            )
            aggregate_status = combine_status(aggregate_status, result.status)

            if result.status in {Status.SUCCESS, Status.PARTIAL}:
                context.publish_many(normalized.explicit)
                if normalized.legacy is not None:
                    legacy_key, legacy_value = normalized.legacy
                    state[legacy_key] = legacy_value

            if result.status in {Status.FAILURE, Status.ERROR}:
                break

        return PipelineResult(
            status=aggregate_status,
            executed_capabilities=tuple(execution.capability_name for execution in executions),
            context=context,
            last_result=last_result,
            execution_order=execution_order,
            executions=tuple(executions),
        )
