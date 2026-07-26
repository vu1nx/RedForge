"""Sanitized application-configuration failures."""


class ScanConfigurationError(ValueError):
    """Base error for invalid scan intent or preparation policy."""


class DisabledCapabilityError(ScanConfigurationError):
    """A requested plan requires a capability disabled by policy."""

    def __init__(self, capability_id: str) -> None:
        super().__init__(
            f"requested outputs require disabled capability '{capability_id}'"
        )


class ScanPreparationError(ScanConfigurationError):
    """Validated application intent cannot produce an execution plan."""
