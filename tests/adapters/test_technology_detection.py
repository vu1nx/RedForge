"""Tests for the WhatWeb technology detection adapter."""

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters.technology_detection import (
    TechnologyDetectionAdapter,
    TechnologyDetectionExecutionError,
    TechnologyDetectionNotFoundError,
    TechnologyDetectionParseError,
)

FIXTURE_PATH = (
    Path(__file__).parents[1] / "fixtures" / "whatweb" / "multiple_targets.json"
)


class SuccessfulWhatWebRun:
    """Subprocess replacement that writes WhatWeb output to the requested log file."""

    def __init__(self, output: str) -> None:
        self.output = output
        self.commands: list[tuple[str, ...]] = []

    def __call__(
        self, command: Sequence[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(tuple(command))
        output_argument = next(
            argument for argument in command if argument.startswith("--log-json=")
        )
        output_path = Path(output_argument.removeprefix("--log-json="))
        output_path.write_text(self.output, encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")


@patch("shutil.which")
def test_verify_binary_success(mock_which: MagicMock) -> None:
    """Binary verification succeeds when the configured executable is resolvable."""
    mock_which.return_value = "/usr/bin/whatweb"

    TechnologyDetectionAdapter().verify_binary()

    mock_which.assert_called_once_with("whatweb")


@patch("shutil.which")
def test_verify_binary_not_found(mock_which: MagicMock) -> None:
    """A missing executable is exposed as an adapter-specific failure."""
    mock_which.return_value = None

    with pytest.raises(TechnologyDetectionNotFoundError, match="binary not found"):
        TechnologyDetectionAdapter().verify_binary()


def test_realistic_json_and_command_contract() -> None:
    """The adapter uses files as required by WhatWeb and parses its JSON array."""
    runner = SuccessfulWhatWebRun(FIXTURE_PATH.read_text(encoding="utf-8"))

    with (
        patch("shutil.which", return_value="/usr/bin/whatweb"),
        patch("subprocess.run", side_effect=runner) as mock_run,
    ):
        technologies = TechnologyDetectionAdapter().detect_technologies(
            ["https://www.example.com/", "https://api.example.com/v1"]
        )

    command = runner.commands[0]
    assert any(argument.startswith("--input-file=") for argument in command)
    assert any(argument.startswith("--log-json=") for argument in command)
    assert "--quiet" in command
    assert "-" not in command
    mock_run.assert_called_once()
    assert mock_run.call_args.kwargs["timeout"] == 120.0

    nginx = next(
        technology
        for technology in technologies
        if technology.name == "nginx"
        and technology.source == "https://www.example.com/"
    )
    assert nginx.version == "1.24.0"
    assert nginx.confidence == 100
    assert nginx.evidence == ("string: nginx/1.24.0",)


def test_multiple_targets_preserve_distinct_provenance() -> None:
    """The same technology on separate endpoints remains separate knowledge."""
    runner = SuccessfulWhatWebRun(FIXTURE_PATH.read_text(encoding="utf-8"))

    with (
        patch("shutil.which", return_value="/usr/bin/whatweb"),
        patch("subprocess.run", side_effect=runner),
    ):
        technologies = TechnologyDetectionAdapter().detect_technologies(
            ["https://www.example.com/", "https://api.example.com/v1"]
        )

    nginx_detections = [
        technology for technology in technologies if technology.name == "nginx"
    ]
    assert len(nginx_detections) == 2
    assert {technology.source for technology in nginx_detections} == {
        "https://www.example.com/",
        "https://api.example.com/v1",
    }

    wordpress_versions = {
        technology.version
        for technology in technologies
        if technology.name == "WordPress"
    }
    assert wordpress_versions == {"6.4.3", "6.4.4"}

    uncertain = next(
        technology for technology in technologies if technology.name == "HTTPServer"
    )
    assert uncertain.confidence == 75


def test_malformed_json_raises_parse_error() -> None:
    """Malformed output is not silently interpreted as an empty result."""
    runner = SuccessfulWhatWebRun("{not valid json")

    with (
        patch("shutil.which", return_value="/usr/bin/whatweb"),
        patch("subprocess.run", side_effect=runner),
        pytest.raises(TechnologyDetectionParseError, match="Failed to parse"),
    ):
        TechnologyDetectionAdapter().detect_technologies(["https://example.com"])


@pytest.mark.parametrize("output", ["{}", "[null]", '["not an object"]'])
def test_invalid_json_shape_raises_parse_error(output: str) -> None:
    """Structurally invalid JSON is rejected at the adapter boundary."""
    runner = SuccessfulWhatWebRun(output)

    with (
        patch("shutil.which", return_value="/usr/bin/whatweb"),
        patch("subprocess.run", side_effect=runner),
        pytest.raises(TechnologyDetectionParseError),
    ):
        TechnologyDetectionAdapter().detect_technologies(["https://example.com"])


def test_missing_fields_are_handled_safely() -> None:
    """Optional target and plugin metadata may be absent in valid output."""
    output = json.dumps(
        [
            {"http_status": 200, "plugins": {"UnknownTech": {}}},
            {"target": "https://empty.example.com", "http_status": 404},
        ]
    )
    runner = SuccessfulWhatWebRun(output)

    with (
        patch("shutil.which", return_value="/usr/bin/whatweb"),
        patch("subprocess.run", side_effect=runner),
    ):
        technologies = TechnologyDetectionAdapter().detect_technologies(
            ["https://example.com"]
        )

    assert len(technologies) == 1
    assert technologies[0].name == "UnknownTech"
    assert technologies[0].version is None
    assert technologies[0].source is None
    assert technologies[0].evidence == ()
    assert technologies[0].confidence == 100


def test_command_failure_preserves_diagnostics() -> None:
    """A non-zero WhatWeb exit becomes a meaningful adapter exception."""
    error = subprocess.CalledProcessError(
        2, ["whatweb"], stderr="invalid target input"
    )

    with (
        patch("shutil.which", return_value="/usr/bin/whatweb"),
        patch("subprocess.run", side_effect=error),
        pytest.raises(TechnologyDetectionExecutionError) as exc_info,
    ):
        TechnologyDetectionAdapter().detect_technologies(["https://example.com"])

    assert exc_info.value.returncode == 2
    assert exc_info.value.stderr == "invalid target input"
    assert "invalid target input" in str(exc_info.value)


def test_timeout_becomes_execution_error() -> None:
    """A hung external process is bounded by the configured timeout."""
    timeout = subprocess.TimeoutExpired(["whatweb"], 5)

    with (
        patch("shutil.which", return_value="/usr/bin/whatweb"),
        patch("subprocess.run", side_effect=timeout),
        pytest.raises(TechnologyDetectionExecutionError, match="timed out"),
    ):
        TechnologyDetectionAdapter(timeout_seconds=5).detect_technologies(
            ["https://example.com"]
        )


@patch("shutil.which")
def test_empty_input_skips_binary_and_subprocess(mock_which: MagicMock) -> None:
    """An empty endpoint list is a successful no-op."""
    assert TechnologyDetectionAdapter().detect_technologies([]) == []
    mock_which.assert_not_called()
