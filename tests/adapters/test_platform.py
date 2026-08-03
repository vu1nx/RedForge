"""Offline tests for bounded operating-system platform detection."""

from pathlib import Path

import pytest  # type: ignore[reportMissingImports]

import redforge.adapters.platform as platform_adapter
from redforge.adapters.platform import (
    SystemPlatformInformationProbe,
    SystemPythonRuntimeInformationProbe,
)
from redforge.doctor import PlatformSupport


def test_kali_detection_uses_only_narrow_os_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    os_release = tmp_path / "os-release"
    os_release.write_text(
        'NAME="Kali GNU/Linux"\nID=kali\nID_LIKE=debian\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(platform_adapter, "_OS_RELEASE_PATH", os_release)
    monkeypatch.setattr(platform_adapter.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        platform_adapter.platform,
        "machine",
        lambda: "x86_64",
    )

    information = SystemPlatformInformationProbe().inspect()

    assert information.family == "linux"
    assert information.architecture == "x86_64"
    assert information.distribution == "kali"
    assert information.support is PlatformSupport.PRIMARY


@pytest.mark.parametrize(
    ("system", "support"),
    (
        ("Windows", PlatformSupport.DEVELOPMENT),
        ("Darwin", PlatformSupport.LIBRARY_ONLY),
        ("Plan9", PlatformSupport.UNSUPPORTED),
    ),
)
def test_non_linux_platform_policy_has_no_linux_file_dependency(
    monkeypatch: pytest.MonkeyPatch,
    system: str,
    support: PlatformSupport,
) -> None:
    monkeypatch.setattr(platform_adapter.platform, "system", lambda: system)
    monkeypatch.setattr(platform_adapter.platform, "machine", lambda: "amd64")

    information = SystemPlatformInformationProbe().inspect()

    assert information.support is support
    assert information.distribution is None


def test_python_runtime_uses_canonical_requirement() -> None:
    information = SystemPythonRuntimeInformationProbe().inspect()

    assert information.implementation
    assert information.major >= 3
    assert information.supported


def test_missing_or_malformed_os_release_does_not_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing"
    monkeypatch.setattr(platform_adapter, "_OS_RELEASE_PATH", missing)
    monkeypatch.setattr(platform_adapter.platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform_adapter.platform, "machine", lambda: "x86_64")

    information = SystemPlatformInformationProbe().inspect()

    assert information.distribution is None
    assert information.support is PlatformSupport.BEST_EFFORT
