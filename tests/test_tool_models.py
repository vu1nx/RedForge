"""Tests for immutable external tool execution contracts."""

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest  # type: ignore[reportMissingImports]

from redforge.sdk import (
    ToolDefinition,
    ToolExecutableResolution,
    ToolExecutableResolutionStatus,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolId,
    ToolInvocation,
    ToolRunnerConfig,
)


def test_tool_id_is_stable_extensible_and_immutable() -> None:
    identity = ToolId("custom_scanner")

    assert str(identity) == "custom_scanner"
    assert identity == ToolId("custom_scanner")
    assert hash(identity) == hash(ToolId("custom_scanner"))
    assert sorted((ToolId("subfinder"), identity)) == [
        identity,
        ToolId("subfinder"),
    ]
    assert not hasattr(identity, "__dict__")
    with pytest.raises(FrozenInstanceError):
        identity.value = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    "value",
    ("", "UPPER", "with space", "with-dash", "9prefix", "_prefix", "a__b"),
)
def test_tool_id_rejects_malformed_values(value: str) -> None:
    with pytest.raises(ValueError, match="tool ID"):
        ToolId(value)


def test_tool_definition_normalizes_immutable_metadata() -> None:
    version_arguments = ["--version"]
    tags = ["Recon", "Active"]
    definition = ToolDefinition(
        tool_id="fake_scanner",
        display_name=" Fake Scanner ",
        description=" Executes a portable test provider. ",
        executable="fake_scanner",
        version_argument=version_arguments,
        default_timeout_seconds=10,
        tags=tags,
    )
    version_arguments.append("--json")
    tags.append("later")

    assert definition.tool_id == ToolId("fake_scanner")
    assert definition.display_name == "Fake Scanner"
    assert definition.description == "Executes a portable test provider."
    assert definition.version_argument == ("--version",)
    assert definition.default_timeout_seconds == 10.0
    assert definition.tags == ("active", "recon")
    assert definition.executable_candidates == ("fake_scanner",)
    assert not hasattr(definition, "__dict__")
    with pytest.raises(FrozenInstanceError):
        definition.executable_candidates = ("changed",)  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("display_name", ""),
        ("description", " "),
        ("executable", "python --version"),
        ("executable", " python"),
        ("default_timeout_seconds", 0),
        ("default_timeout_seconds", float("inf")),
    ),
)
def test_tool_definition_rejects_invalid_metadata(
    field: str,
    value: object,
) -> None:
    values: dict[str, object] = {
        "tool_id": "example",
        "display_name": "Example",
        "description": "Example tool.",
        "executable": "example",
    }
    values[field] = value
    with pytest.raises(ValueError):
        ToolDefinition(**values)  # type: ignore[arg-type]


def test_tool_definition_rejects_duplicate_tags_and_bad_version_arguments() -> None:
    with pytest.raises(ValueError, match="duplicates"):
        ToolDefinition(
            "example",
            "Example",
            "Example tool.",
            "example",
            tags=("Recon", "recon"),
        )
    with pytest.raises(TypeError, match="collection"):
        ToolDefinition(
            "example",
            "Example",
            "Example tool.",
            "example",
            version_argument="--version",
        )


def test_tool_definition_normalizes_ordered_executable_candidates() -> None:
    candidates = ["httpx-toolkit", "httpx"]
    definition = ToolDefinition(
        "httpx",
        "HTTPX",
        "ProjectDiscovery HTTP probe.",
        executable_candidates=candidates,
        identity_output_pattern=(
            r"Current Version: (?P<version>v[0-9.]+)"
        ),
    )
    candidates.reverse()

    assert definition.executable_candidates == ("httpx-toolkit", "httpx")
    assert definition.executable == "httpx-toolkit"
    assert definition.identity_timeout_seconds == 5.0


@pytest.mark.parametrize(
    "candidates",
    ((), ("",), ("httpx", "httpx")),
)
def test_tool_definition_rejects_invalid_executable_candidates(
    candidates: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError):
        ToolDefinition(
            "httpx",
            "HTTPX",
            "ProjectDiscovery HTTP probe.",
            executable_candidates=candidates,
        )


def test_tool_definition_rejects_ambiguous_executable_configuration() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        ToolDefinition(
            "httpx",
            "HTTPX",
            "ProjectDiscovery HTTP probe.",
            executable="httpx",
            executable_candidates=("httpx-toolkit", "httpx"),
        )
    with pytest.raises(ValueError, match="version group"):
        ToolDefinition(
            "httpx",
            "HTTPX",
            "ProjectDiscovery HTTP probe.",
            executable="httpx",
            identity_output_pattern=r"ProjectDiscovery",
        )


def test_tool_definition_repr_hides_executable_path() -> None:
    sensitive_marker = "private-executable-marker"
    definition = ToolDefinition(
        "example",
        "Example",
        "Example tool.",
        str((Path.cwd() / sensitive_marker / "example").absolute()),
    )

    assert sensitive_marker not in repr(definition)


def test_resolution_contract_rejects_path_disclosure() -> None:
    with pytest.raises(ValueError, match="path"):
        ToolExecutableResolution(
            ToolId("httpx"),
            ToolExecutableResolutionStatus.RESOLVED,
            executable_candidate="private/httpx-toolkit",
            version="v1.9.0",
        )


def test_invocation_copies_inputs_and_has_safe_repr() -> None:
    arguments = [";", "&&", "|", "$(touch nope)", "`echo nope`", "two words"]
    environment = {"SECRET_TOKEN": "do-not-render", "MODE": "test"}
    invocation = ToolInvocation(
        "example",
        arguments=arguments,
        timeout_seconds=2,
        cwd=".",
        environment=environment,
        stdin="sensitive-input",
    )
    arguments.append("later")
    environment["MODE"] = "changed"

    assert invocation.arguments == (
        ";",
        "&&",
        "|",
        "$(touch nope)",
        "`echo nope`",
        "two words",
    )
    assert invocation.environment == (
        ("MODE", "test"),
        ("SECRET_TOKEN", "do-not-render"),
    )
    assert invocation.cwd == Path(".")
    assert invocation.timeout_seconds == 2.0
    rendered = repr(invocation)
    assert "do-not-render" not in rendered
    assert "sensitive-input" not in rendered
    assert "$(touch nope)" not in rendered
    assert "SECRET_TOKEN" in rendered


@pytest.mark.parametrize("timeout", (0, -1, float("nan"), True))
def test_invocation_rejects_invalid_timeout(timeout: object) -> None:
    with pytest.raises(ValueError, match="timeout"):
        ToolInvocation("example", timeout_seconds=timeout)  # type: ignore[arg-type]


def test_invocation_rejects_invalid_or_duplicate_environment() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        ToolInvocation(
            "example",
            environment=(("MODE", "one"), ("mode", "two")),
        )
    with pytest.raises(ValueError, match="name"):
        ToolInvocation("example", environment=(("BAD=KEY", "value"),))
    with pytest.raises(TypeError, match="stdin"):
        ToolInvocation("example", stdin=object())  # type: ignore[arg-type]


def test_result_is_typed_immutable_and_safe_to_repr() -> None:
    result = ToolExecutionResult(
        tool_id=ToolId("example"),
        status=ToolExecutionStatus.FAILURE,
        exit_code=7,
        stdout="sensitive stdout",
        stderr="sensitive stderr",
        duration_seconds=0.5,
        truncated=True,
    )

    assert result == ToolExecutionResult(
        tool_id=ToolId("example"),
        status=ToolExecutionStatus.FAILURE,
        exit_code=7,
        stdout="sensitive stdout",
        stderr="sensitive stderr",
        duration_seconds=0.5,
        truncated=True,
    )
    assert "sensitive stdout" not in repr(result)
    assert "sensitive stderr" not in repr(result)
    assert not hasattr(result, "__dict__")
    with pytest.raises(FrozenInstanceError):
        result.exit_code = 0  # type: ignore[misc]


def test_result_status_semantics_are_validated() -> None:
    with pytest.raises(ValueError, match="exit code zero"):
        ToolExecutionResult(
            ToolId("example"),
            ToolExecutionStatus.SUCCESS,
            1,
            "",
            "",
            0,
        )
    with pytest.raises(ValueError, match="timed_out"):
        ToolExecutionResult(
            ToolId("example"),
            ToolExecutionStatus.TIMEOUT,
            None,
            "",
            "",
            0,
        )
    timeout = ToolExecutionResult(
        ToolId("example"),
        ToolExecutionStatus.TIMEOUT,
        None,
        "",
        "",
        0,
        timed_out=True,
    )
    assert timeout.exit_code is None
    with pytest.raises(TypeError, match="truncated"):
        ToolExecutionResult(
            ToolId("example"),
            ToolExecutionStatus.SUCCESS,
            0,
            "",
            "",
            0,
            truncated=1,  # type: ignore[arg-type]
        )


def test_runner_config_is_immutable_and_validated() -> None:
    config = ToolRunnerConfig(
        max_stdout_bytes=10,
        max_stderr_bytes=20,
        max_stdin_bytes=30,
        inherited_environment_keys=("PATH", "LANG"),
    )

    assert config.inherited_environment_keys == ("LANG", "PATH")
    with pytest.raises(FrozenInstanceError):
        config.max_stdout_bytes = 100  # type: ignore[misc]
    with pytest.raises(ValueError):
        ToolRunnerConfig(max_stdout_bytes=0)
    with pytest.raises(ValueError, match="encoding"):
        ToolRunnerConfig(encoding="redforge-not-a-codec")
    with pytest.raises(ValueError, match="environment key"):
        ToolRunnerConfig(inherited_environment_keys=("BAD=KEY",))
    with pytest.raises(TypeError, match="inherit_environment"):
        ToolRunnerConfig(inherit_environment=1)  # type: ignore[arg-type]
