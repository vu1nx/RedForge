"""Typed sanitized configuration failures."""

from enum import StrEnum


class ConfigurationReasonCode(StrEnum):
    """Stable machine-readable configuration failure categories."""

    FILE_UNAVAILABLE = "configuration_file_unavailable"
    PARSE_FAILED = "configuration_parse_failed"
    VERSION_MISSING = "configuration_version_missing"
    VERSION_UNSUPPORTED = "configuration_version_unsupported"
    FIELD_UNKNOWN = "configuration_field_unknown"
    VALUE_INVALID = "configuration_value_invalid"
    PROFILE_INCOMPATIBLE = "configuration_profile_incompatible"


class ConfigurationError(ValueError):
    """Base expected configuration failure with bounded public details."""

    def __init__(
        self,
        reason_code: ConfigurationReasonCode,
        message: str,
        *,
        field_path: str | None = None,
    ) -> None:
        self.reason_code = reason_code
        self.field_path = field_path
        super().__init__(message)


class ConfigurationFileError(ConfigurationError):
    """Explicit file could not be safely read."""


class ConfigurationParseError(ConfigurationError):
    """TOML bytes could not be decoded or parsed."""


class ConfigurationValidationError(ConfigurationError):
    """Parsed values do not satisfy the typed contract."""


class UnsupportedConfigurationVersionError(ConfigurationValidationError):
    """Configuration schema version is unsupported."""


class UnknownConfigurationFieldError(ConfigurationValidationError):
    """A deterministic field path is outside schema version 1."""
