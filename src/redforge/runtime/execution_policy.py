"""Provider-neutral publication limits and step-boundary deadlines."""

from dataclasses import dataclass, field
from enum import StrEnum
from math import isfinite
from time import monotonic
from typing import Protocol, cast

from redforge.domain.host import HostResolution
from redforge.sdk.result import StatePublication
from redforge.sdk.state import PipelineStateKey
from redforge.sdk.subdomain_discovery import SubdomainDiscoveryResult

_BOUNDED_STATE_KEYS = (
    PipelineStateKey.SUBDOMAINS,
    PipelineStateKey.HOSTS,
    PipelineStateKey.ALIVE_HOSTS,
    PipelineStateKey.HTTP_ENDPOINTS,
    PipelineStateKey.ENDPOINTS,
    PipelineStateKey.TECHNOLOGIES,
)


class MonotonicClock(Protocol):
    """Clock port used to construct and evaluate deterministic deadlines."""

    def monotonic(self) -> float:
        """Return monotonically increasing seconds."""
        ...


@dataclass(frozen=True, slots=True)
class SystemMonotonicClock:
    """Production monotonic clock without wall-clock semantics."""

    def monotonic(self) -> float:
        """Return process-local monotonic seconds."""
        return monotonic()


@dataclass(frozen=True, slots=True, order=True)
class StateLimit:
    """Maximum accepted element count for one canonical state."""

    state_key: PipelineStateKey
    maximum: int

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.state_key), PipelineStateKey):
            raise TypeError("state limit key must be a PipelineStateKey")
        if self.state_key not in _BOUNDED_STATE_KEYS:
            raise ValueError("state limit key is not a bounded collection")
        if (
            not isinstance(cast(object, self.maximum), int)
            or isinstance(cast(object, self.maximum), bool)
            or self.maximum < 1
        ):
            raise ValueError("state limit maximum must be a positive integer")


@dataclass(frozen=True, slots=True)
class StateLimitViolation:
    """Sanitized typed data for one rejected oversized publication."""

    state_key: PipelineStateKey
    observed: int
    allowed: int

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.state_key), PipelineStateKey):
            raise TypeError("state limit violation key is invalid")
        if (
            not isinstance(cast(object, self.observed), int)
            or isinstance(cast(object, self.observed), bool)
            or self.observed < 0
        ):
            raise ValueError("state limit violation observed count is invalid")
        if (
            not isinstance(cast(object, self.allowed), int)
            or isinstance(cast(object, self.allowed), bool)
            or self.allowed < 1
        ):
            raise ValueError("state limit violation allowed count is invalid")


class DeadlinePhase(StrEnum):
    """Step boundary where the application deadline was observed."""

    BEFORE_CAPABILITY = "before_capability"
    AFTER_CAPABILITY = "after_capability"


@dataclass(frozen=True, slots=True)
class DeadlineViolation:
    """Sanitized typed data for an expired step-boundary deadline."""

    phase: DeadlinePhase

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.phase), DeadlinePhase):
            raise TypeError("deadline violation phase is invalid")


type ExecutionPolicyViolation = StateLimitViolation | DeadlineViolation


class StateLimitExceeded(RuntimeError):
    """Raised internally when an otherwise valid publication is oversized."""

    def __init__(self, violation: StateLimitViolation) -> None:
        super().__init__(
            "state limit exceeded: "
            f"{violation.state_key.name} "
            f"observed={violation.observed} allowed={violation.allowed}"
        )
        self.violation = violation


class ExecutionDeadlineExceeded(RuntimeError):
    """Raised internally when a monotonic execution deadline has expired."""


@dataclass(frozen=True, slots=True)
class ExecutionDeadline:
    """Absolute monotonic deadline evaluated only at capability boundaries."""

    expires_at: float
    clock: MonotonicClock = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        expires_at = cast(object, self.expires_at)
        if (
            not isinstance(expires_at, (int, float))
            or isinstance(expires_at, bool)
            or not isfinite(expires_at)
        ):
            raise TypeError("execution deadline must use monotonic seconds")
        monotonic_method = getattr(cast(object, self.clock), "monotonic", None)
        if not callable(monotonic_method):
            raise TypeError("execution deadline requires a monotonic clock")

    @classmethod
    def after(
        cls,
        seconds: int,
        *,
        clock: MonotonicClock,
    ) -> "ExecutionDeadline":
        """Create an absolute deadline from a validated duration in seconds."""
        if (
            not isinstance(cast(object, seconds), int)
            or isinstance(cast(object, seconds), bool)
            or seconds < 1
        ):
            raise ValueError("execution deadline duration must be positive")
        started_at = clock.monotonic()
        if (
            not isinstance(cast(object, started_at), (int, float))
            or isinstance(cast(object, started_at), bool)
            or not isfinite(started_at)
        ):
            raise ValueError("monotonic clock returned an invalid value")
        return cls(expires_at=started_at + seconds, clock=clock)

    def check(self) -> None:
        """Raise when the monotonic deadline is reached or exceeded."""
        current = self.clock.monotonic()
        if (
            not isinstance(cast(object, current), (int, float))
            or isinstance(cast(object, current), bool)
            or not isfinite(current)
        ):
            raise ValueError("monotonic clock returned an invalid value")
        if current >= self.expires_at:
            raise ExecutionDeadlineExceeded("execution deadline exceeded")


class ExecutionPolicy(Protocol):
    """Neutral synchronous policy evaluated around runtime publication."""

    def check_deadline(self) -> None:
        """Raise when no further capability work or publication is allowed."""
        ...

    def validate_publications(
        self,
        publications: tuple[StatePublication, ...],
    ) -> None:
        """Raise a typed violation without mutating publications or Context."""
        ...


@dataclass(frozen=True, slots=True)
class StateLimitPolicy:
    """Immutable state limits with an optional monotonic execution deadline."""

    limits: tuple[StateLimit, ...] = ()
    deadline: ExecutionDeadline | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        limits_value = cast(object, self.limits)
        if not isinstance(limits_value, tuple) or not all(
            isinstance(item, StateLimit)
            for item in cast(tuple[object, ...], limits_value)
        ):
            raise TypeError("state limits must be an immutable tuple")
        typed_limits = cast(tuple[StateLimit, ...], limits_value)
        keys = tuple(item.state_key for item in typed_limits)
        if len(keys) != len(set(keys)):
            raise ValueError("state limits contain duplicate keys")
        if self.deadline is not None and not isinstance(
            cast(object, self.deadline), ExecutionDeadline
        ):
            raise TypeError("state limit deadline is invalid")
        object.__setattr__(self, "limits", tuple(sorted(typed_limits)))

    def check_deadline(self) -> None:
        """Evaluate the optional deadline at a runtime step boundary."""
        if self.deadline is not None:
            self.deadline.check()

    def validate_publications(
        self,
        publications: tuple[StatePublication, ...],
    ) -> None:
        """Reject the complete batch if one known canonical state is oversized."""
        publications_value = cast(object, publications)
        if not isinstance(publications_value, tuple) or not all(
            isinstance(item, StatePublication)
            for item in cast(tuple[object, ...], publications_value)
        ):
            raise TypeError("publication policy requires an immutable batch")
        for publication in publications:
            limit = next(
                (
                    item
                    for item in self.limits
                    if item.state_key is publication.key
                ),
                None,
            )
            if limit is None:
                continue
            observed = _bounded_state_size(
                publication.key,
                publication.value,
            )
            if observed > limit.maximum:
                raise StateLimitExceeded(
                    StateLimitViolation(
                        state_key=publication.key,
                        observed=observed,
                        allowed=limit.maximum,
                    )
                )


def _bounded_state_size(key: PipelineStateKey, value: object) -> int:
    """Measure only configured canonical validated collection states."""
    if key is PipelineStateKey.SUBDOMAINS:
        return len(cast(SubdomainDiscoveryResult, value).hostnames)
    if key is PipelineStateKey.HOSTS:
        return len(cast(HostResolution, value).hosts)
    if key in {
        PipelineStateKey.ALIVE_HOSTS,
        PipelineStateKey.HTTP_ENDPOINTS,
        PipelineStateKey.ENDPOINTS,
        PipelineStateKey.TECHNOLOGIES,
    }:
        return len(cast(tuple[object, ...], value))
    raise ValueError("state limit configured for an unbounded state key")
