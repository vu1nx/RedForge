"""Provider-neutral runtime publication-limit and deadline enforcement tests."""

from dataclasses import FrozenInstanceError

import pytest  # type: ignore[reportMissingImports]

from redforge.domain import Endpoint, Host, HttpProbeEndpoint, Technology
from redforge.domain.host import HostResolution
from redforge.runtime import (
    DeadlinePhase,
    DeadlineViolation,
    ExecutionDeadline,
    Pipeline,
    StateLimit,
    StateLimitPolicy,
    StateLimitViolation,
)
from redforge.sdk import (
    Capability,
    CapabilityId,
    Context,
    PipelineStateKey,
    Result,
    StatePublication,
    Status,
    SubdomainDiscoveryResult,
)


class PublishingCapability(Capability):
    """Return one configured typed publication batch."""

    def __init__(
        self,
        name: str,
        publications: tuple[StatePublication, ...],
        *,
        status: Status = Status.SUCCESS,
    ) -> None:
        self._name = name
        self._publications = publications
        self._status = status
        self.calls = 0

    @property
    def name(self) -> str:
        return self._name

    def execute(self, context: Context) -> Result[None]:  # noqa: ARG002
        self.calls += 1
        return Result(
            status=self._status,
            data=None,
            publications=self._publications,
        )


class ScriptedClock:
    """Deterministic mutable test clock returning configured observations."""

    def __init__(self, observations: tuple[float, ...]) -> None:
        self._observations = observations
        self._position = 0

    def monotonic(self) -> float:
        value = self._observations[self._position]
        if self._position < len(self._observations) - 1:
            self._position += 1
        return value


def _values(
    key: PipelineStateKey,
    count: int,
) -> object:
    if key is PipelineStateKey.SUBDOMAINS:
        return SubdomainDiscoveryResult(
            hostnames=tuple(
                f"host-{index}.example.com" for index in range(count)
            )
        )
    if key is PipelineStateKey.HOSTS:
        return HostResolution(
            hosts=tuple(
                Host(hostname=f"host-{index}.example.com")
                for index in range(count)
            )
        )
    if key is PipelineStateKey.ALIVE_HOSTS:
        return tuple(
            Host(hostname=f"host-{index}.example.com")
            for index in range(count)
        )
    if key is PipelineStateKey.HTTP_ENDPOINTS:
        return tuple(
            HttpProbeEndpoint(
                url=f"https://host-{index}.example.com",
                scheme="https",
                hostname=f"host-{index}.example.com",
                port=443,
                status_code=200,
            )
            for index in range(count)
        )
    if key is PipelineStateKey.ENDPOINTS:
        return tuple(
            Endpoint(
                f"host-{index}.example.com",
                443,
                "https",
                "/",
            )
            for index in range(count)
        )
    if key is PipelineStateKey.TECHNOLOGIES:
        return tuple(
            Technology(
                name=f"technology-{index}",
                category="test",
            )
            for index in range(count)
        )
    raise AssertionError("test requested an unbounded state")


def _pipeline(
    capability: PublishingCapability,
    provides: tuple[PipelineStateKey, ...],
) -> Pipeline:
    identity = CapabilityId(capability.name)
    pipeline = Pipeline(output_contracts={identity: provides})
    pipeline.add(capability, capability_id=identity)
    return pipeline


@pytest.mark.parametrize(
    "key",
    (
        PipelineStateKey.SUBDOMAINS,
        PipelineStateKey.HOSTS,
        PipelineStateKey.ALIVE_HOSTS,
        PipelineStateKey.HTTP_ENDPOINTS,
        PipelineStateKey.ENDPOINTS,
        PipelineStateKey.TECHNOLOGIES,
    ),
)
@pytest.mark.parametrize(("observed", "expected"), ((1, Status.SUCCESS), (2, Status.FAILURE)))
def test_exact_limit_is_accepted_and_over_limit_is_rejected(
    key: PipelineStateKey,
    observed: int,
    expected: Status,
) -> None:
    publication = StatePublication(key, _values(key, observed))
    capability = PublishingCapability("bounded_source", (publication,))
    policy = StateLimitPolicy(limits=(StateLimit(key, 1),))

    result = _pipeline(capability, (key,)).run(
        Context(target_id="example.com"),
        policy=policy,
    )

    assert result.status is expected
    assert capability.calls == 1
    if expected is Status.SUCCESS:
        assert result.context.get(key) == publication.value
        assert result.executions[0].policy_violation is None
    else:
        assert not result.context.has(key)
        violation = result.executions[0].policy_violation
        assert violation == StateLimitViolation(key, observed=2, allowed=1)
        assert result.last_result is not None
        assert result.last_result.metadata == {
            "error_kind": "state_limit_exceeded",
            "state_key": key.value,
            "observed": 2,
            "allowed": 1,
        }
        assert "host-1.example.com" not in repr(result.last_result)
        assert "technology-1" not in repr(result.last_result)


def test_no_policy_preserves_existing_unlimited_runtime_behavior() -> None:
    key = PipelineStateKey.TECHNOLOGIES
    publication = StatePublication(key, _values(key, 2))
    capability = PublishingCapability("unlimited_source", (publication,))

    result = _pipeline(capability, (key,)).run("example.com")

    assert result.status is Status.SUCCESS
    assert result.context.get(key) == publication.value


@pytest.mark.parametrize(
    ("limited_key", "within_key"),
    (
        (
            PipelineStateKey.HTTP_ENDPOINTS,
            PipelineStateKey.ALIVE_HOSTS,
        ),
        (
            PipelineStateKey.ALIVE_HOSTS,
            PipelineStateKey.HTTP_ENDPOINTS,
        ),
    ),
)
def test_multi_output_limit_rejection_is_atomic(
    limited_key: PipelineStateKey,
    within_key: PipelineStateKey,
) -> None:
    publications = (
        StatePublication(limited_key, _values(limited_key, 2)),
        StatePublication(within_key, _values(within_key, 1)),
    )
    capability = PublishingCapability("http_probe", publications)
    policy = StateLimitPolicy(limits=(StateLimit(limited_key, 1),))
    context = Context(
        target_id="example.com",
        state={"upstream": ("preserved",)},
    )

    result = _pipeline(
        capability,
        (
            PipelineStateKey.ALIVE_HOSTS,
            PipelineStateKey.HTTP_ENDPOINTS,
        ),
    ).run(context, policy=policy)

    assert result.status is Status.FAILURE
    assert result.context.state == {"upstream": ("preserved",)}
    assert len(result.executions) == 1


def test_limit_failure_preserves_upstream_and_stops_downstream() -> None:
    hosts = StatePublication(
        PipelineStateKey.HOSTS,
        _values(PipelineStateKey.HOSTS, 1),
    )
    oversized = StatePublication(
        PipelineStateKey.HTTP_ENDPOINTS,
        _values(PipelineStateKey.HTTP_ENDPOINTS, 2),
    )
    first = PublishingCapability("host_resolution", (hosts,))
    violating = PublishingCapability("http_probe", (oversized,))
    skipped = PublishingCapability(
        "technology_detection",
        (
            StatePublication(
                PipelineStateKey.TECHNOLOGIES,
                _values(PipelineStateKey.TECHNOLOGIES, 1),
            ),
        ),
    )
    pipeline = Pipeline(
        output_contracts={
            CapabilityId("host_resolution"): (PipelineStateKey.HOSTS,),
            CapabilityId("http_probe"): (
                PipelineStateKey.HTTP_ENDPOINTS,
            ),
            CapabilityId("technology_detection"): (
                PipelineStateKey.TECHNOLOGIES,
            ),
        }
    )
    for capability in (first, violating, skipped):
        pipeline.add(
            capability,
            capability_id=CapabilityId(capability.name),
        )

    result = pipeline.run(
        "example.com",
        policy=StateLimitPolicy(
            limits=(StateLimit(PipelineStateKey.HTTP_ENDPOINTS, 1),)
        ),
    )

    assert result.status is Status.FAILURE
    assert result.context.get(PipelineStateKey.HOSTS) == hosts.value
    assert not result.context.has(PipelineStateKey.HTTP_ENDPOINTS)
    assert not result.context.has(PipelineStateKey.TECHNOLOGIES)
    assert result.executed_capabilities == (
        "host_resolution",
        "http_probe",
    )
    assert skipped.calls == 0


def test_deadline_before_first_step_records_unexecuted_terminal_failure() -> None:
    capability = PublishingCapability(
        "technology_source",
        (
            StatePublication(
                PipelineStateKey.TECHNOLOGIES,
                _values(PipelineStateKey.TECHNOLOGIES, 1),
            ),
        ),
    )
    policy = StateLimitPolicy(
        deadline=ExecutionDeadline(
            expires_at=5,
            clock=ScriptedClock((5,)),
        )
    )

    result = _pipeline(
        capability,
        (PipelineStateKey.TECHNOLOGIES,),
    ).run("example.com", policy=policy)

    assert result.status is Status.FAILURE
    assert capability.calls == 0
    assert result.executed_capabilities == ()
    assert result.executions[0].executed is False
    assert result.executions[0].policy_violation == DeadlineViolation(
        DeadlinePhase.BEFORE_CAPABILITY
    )


def test_deadline_between_steps_preserves_first_publication() -> None:
    first = PublishingCapability(
        "host_source",
        (
            StatePublication(
                PipelineStateKey.HOSTS,
                _values(PipelineStateKey.HOSTS, 1),
            ),
        ),
    )
    second = PublishingCapability(
        "technology_source",
        (
            StatePublication(
                PipelineStateKey.TECHNOLOGIES,
                _values(PipelineStateKey.TECHNOLOGIES, 1),
            ),
        ),
    )
    pipeline = Pipeline(
        output_contracts={
            CapabilityId("host_source"): (PipelineStateKey.HOSTS,),
            CapabilityId("technology_source"): (
                PipelineStateKey.TECHNOLOGIES,
            ),
        }
    )
    pipeline.add(first, capability_id=CapabilityId(first.name))
    pipeline.add(second, capability_id=CapabilityId(second.name))
    policy = StateLimitPolicy(
        deadline=ExecutionDeadline(
            expires_at=5,
            clock=ScriptedClock((0, 0, 5)),
        )
    )

    result = pipeline.run("example.com", policy=policy)

    assert result.status is Status.FAILURE
    assert result.context.has(PipelineStateKey.HOSTS)
    assert not result.context.has(PipelineStateKey.TECHNOLOGIES)
    assert first.calls == 1
    assert second.calls == 0
    assert result.executed_capabilities == ("host_source",)
    assert result.executions[-1].policy_violation == DeadlineViolation(
        DeadlinePhase.BEFORE_CAPABILITY
    )


def test_deadline_during_step_rejects_returned_publication() -> None:
    capability = PublishingCapability(
        "technology_source",
        (
            StatePublication(
                PipelineStateKey.TECHNOLOGIES,
                _values(PipelineStateKey.TECHNOLOGIES, 1),
            ),
        ),
    )
    policy = StateLimitPolicy(
        deadline=ExecutionDeadline(
            expires_at=5,
            clock=ScriptedClock((0, 5)),
        )
    )

    result = _pipeline(
        capability,
        (PipelineStateKey.TECHNOLOGIES,),
    ).run("example.com", policy=policy)

    assert result.status is Status.FAILURE
    assert capability.calls == 1
    assert not result.context.has(PipelineStateKey.TECHNOLOGIES)
    assert result.executions[0].policy_violation == DeadlineViolation(
        DeadlinePhase.AFTER_CAPABILITY
    )


@pytest.mark.parametrize("violation_kind", ("limit", "deadline"))
def test_earlier_partial_combines_with_policy_failure(
    violation_kind: str,
) -> None:
    partial = PublishingCapability(
        "partial_source",
        (
            StatePublication(
                PipelineStateKey.HOSTS,
                _values(PipelineStateKey.HOSTS, 1),
            ),
        ),
        status=Status.PARTIAL,
    )
    stopping = PublishingCapability(
        "technology_source",
        (
            StatePublication(
                PipelineStateKey.TECHNOLOGIES,
                _values(PipelineStateKey.TECHNOLOGIES, 2),
            ),
        ),
    )
    pipeline = Pipeline(
        output_contracts={
            CapabilityId(partial.name): (PipelineStateKey.HOSTS,),
            CapabilityId(stopping.name): (
                PipelineStateKey.TECHNOLOGIES,
            ),
        }
    )
    pipeline.add(partial, capability_id=CapabilityId(partial.name))
    pipeline.add(stopping, capability_id=CapabilityId(stopping.name))
    policy = (
        StateLimitPolicy(
            limits=(StateLimit(PipelineStateKey.TECHNOLOGIES, 1),)
        )
        if violation_kind == "limit"
        else StateLimitPolicy(
            deadline=ExecutionDeadline(
                expires_at=5,
                clock=ScriptedClock((0, 0, 5)),
            )
        )
    )

    result = pipeline.run("example.com", policy=policy)

    assert result.status is Status.FAILURE
    assert result.context.has(PipelineStateKey.HOSTS)
    assert not result.context.has(PipelineStateKey.TECHNOLOGIES)


def test_provider_error_stops_before_later_policy_evaluation() -> None:
    erroring = PublishingCapability(
        "erroring",
        (),
        status=Status.ERROR,
    )
    later = PublishingCapability(
        "technology_source",
        (
            StatePublication(
                PipelineStateKey.TECHNOLOGIES,
                _values(PipelineStateKey.TECHNOLOGIES, 2),
            ),
        ),
    )
    pipeline = Pipeline(
        output_contracts={
            CapabilityId(erroring.name): (PipelineStateKey.HOSTS,),
            CapabilityId(later.name): (PipelineStateKey.TECHNOLOGIES,),
        }
    )
    pipeline.add(erroring, capability_id=CapabilityId(erroring.name))
    pipeline.add(later, capability_id=CapabilityId(later.name))

    result = pipeline.run(
        "example.com",
        policy=StateLimitPolicy(
            limits=(StateLimit(PipelineStateKey.TECHNOLOGIES, 1),)
        ),
    )

    assert result.status is Status.ERROR
    assert later.calls == 0
    assert result.executions[0].policy_violation is None


def test_policy_models_are_immutable_and_safe() -> None:
    policy = StateLimitPolicy(
        limits=(StateLimit(PipelineStateKey.TECHNOLOGIES, 1),),
        deadline=ExecutionDeadline(
            expires_at=5,
            clock=ScriptedClock((0,)),
        ),
    )

    assert not hasattr(policy, "__dict__")
    assert "ScriptedClock" not in repr(policy)
    with pytest.raises(FrozenInstanceError):
        policy.limits = ()  # type: ignore[misc]
    with pytest.raises(ValueError, match="bounded"):
        StateLimit(PipelineStateKey.RISK_INTELLIGENCE, 1)
