"""Focused deterministic errors for execution planning."""


class PlanningError(Exception):
    """Base exception for an invalid or unsatisfiable execution plan."""


class InvalidPlanningInputError(PlanningError, ValueError):
    """Planner input or a planning model is malformed."""


class UnknownCapabilityError(PlanningError, KeyError):
    """A requested capability descriptor is not registered."""

    def __init__(self, capability_name: str) -> None:
        self.capability_name = capability_name
        super().__init__(f"Unknown capability '{capability_name}'")


class MissingProducerError(PlanningError):
    """No registered capability can provide required state."""

    def __init__(self, state_key: str) -> None:
        self.state_key = state_key
        super().__init__(f"No capability produces required state '{state_key}'")


class AmbiguousProducerError(PlanningError):
    """Multiple registered capabilities provide the same required state."""

    def __init__(self, state_key: str, candidates: tuple[str, ...]) -> None:
        self.state_key = state_key
        self.candidates = candidates
        joined = ", ".join(candidates)
        super().__init__(
            f"Multiple capabilities produce required state '{state_key}': {joined}"
        )


class DependencyCycleError(PlanningError):
    """The requested dependency closure contains a capability cycle."""

    def __init__(self, cycle_path: tuple[str, ...]) -> None:
        self.cycle_path = cycle_path
        super().__init__(
            "Capability dependency cycle detected: " + " -> ".join(cycle_path)
        )


class PipelineBuildError(Exception):
    """Base exception for plan-to-runtime integration failures."""


class MissingCapabilityFactoryError(PipelineBuildError):
    """A planned capability has no registered runtime factory."""

    def __init__(self, capability_name: str) -> None:
        self.capability_name = capability_name
        super().__init__(
            f"No runtime factory is registered for capability '{capability_name}'"
        )


class InvalidCapabilityFactoryError(PipelineBuildError):
    """A runtime factory is invalid, fails, or returns an invalid object."""

    def __init__(self, capability_name: str, *, failed: bool = False) -> None:
        self.capability_name = capability_name
        detail = "failed" if failed else "returned an invalid capability"
        super().__init__(f"Capability factory for '{capability_name}' {detail}")


class CapabilityDescriptorMismatchError(PipelineBuildError):
    """A plan, descriptor, factory, or runtime state contract is inconsistent."""

    def __init__(self, capability_name: str, detail: str) -> None:
        self.capability_name = capability_name
        self.detail = detail
        super().__init__(
            f"Capability '{capability_name}' has an incompatible {detail}"
        )
