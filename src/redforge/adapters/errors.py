"""Shared sanitized error contract for external adapters."""


class AdapterError(Exception):
    """Base exception for sanitized adapter failures."""


class AdapterUnavailableError(AdapterError):
    """External system could not be reached or used."""


class AdapterResponseError(AdapterError):
    """External system returned an invalid or unsupported response."""


class AdapterConfigurationError(AdapterError):
    """Adapter configuration is invalid or incomplete."""
