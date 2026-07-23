"""Runtime exceptions."""


class RuntimeError(Exception):
    """Base exception for runtime errors."""

    pass


class CapabilityNotFoundError(RuntimeError):
    """Raised when a capability is not found in the registry."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"Capability not found: {name}")


class DuplicateCapabilityError(RuntimeError):
    """Raised when attempting to register a duplicate capability."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"Capability already registered: {name}")
