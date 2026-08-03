"""Safe standard-library platform and Python runtime probes."""

import platform
import sys
from pathlib import Path

from redforge import MINIMUM_PYTHON_VERSION
from redforge.doctor import (
    PlatformInformation,
    PlatformSupport,
    PythonRuntimeInformation,
)

_OS_RELEASE_PATH = Path("/etc/os-release")


class SystemPlatformInformationProbe:
    """Inspect bounded local OS metadata without shell, environment, or network."""

    def inspect(self) -> PlatformInformation:
        """Return normalized platform classification."""
        family = platform.system().lower()
        architecture = _bounded(platform.machine().lower(), fallback="unknown")
        distribution: str | None = None
        if family == "linux":
            distribution = _linux_distribution()
            support = (
                PlatformSupport.PRIMARY
                if distribution == "kali"
                else PlatformSupport.BEST_EFFORT
            )
        elif family == "windows":
            support = PlatformSupport.DEVELOPMENT
        elif family == "darwin":
            support = PlatformSupport.LIBRARY_ONLY
            family = "macos"
        else:
            support = PlatformSupport.UNSUPPORTED
            family = _bounded(family, fallback="unknown")
        return PlatformInformation(
            family=family,
            architecture=architecture,
            distribution=distribution,
            support=support,
        )


class SystemPythonRuntimeInformationProbe:
    """Inspect the current Python implementation without package discovery."""

    def inspect(self) -> PythonRuntimeInformation:
        """Return current runtime and canonical support classification."""
        major = sys.version_info.major
        minor = sys.version_info.minor
        return PythonRuntimeInformation(
            implementation=_bounded(
                sys.implementation.name.lower(),
                fallback="unknown",
            ),
            major=major,
            minor=minor,
            supported=(major, minor) >= MINIMUM_PYTHON_VERSION,
        )


def _linux_distribution() -> str | None:
    try:
        text = _OS_RELEASE_PATH.read_text(
            encoding="utf-8",
            errors="strict",
        )
    except (OSError, UnicodeError):
        return None
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, raw_value = line.partition("=")
        if not separator or key not in {"ID", "ID_LIKE"}:
            continue
        value = raw_value.strip().strip("\"'").lower()
        if (
            value
            and len(value) <= 128
            and all(
                character.isalnum()
                or character in {"_", "-", " "}
                for character in value
            )
        ):
            values[key] = value
    identifiers = {
        item
        for key in ("ID", "ID_LIKE")
        for item in values.get(key, "").split()
    }
    if "kali" in identifiers:
        return "kali"
    return values.get("ID")


def _bounded(value: str, *, fallback: str) -> str:
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > 64
        or any(character in normalized for character in "\r\n")
    ):
        return fallback
    return normalized
