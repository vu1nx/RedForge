"""Passive Subfinder provider implemented through the ToolRunner port."""

import json
import math
from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

from redforge.domain.hostname import normalize_dns_hostname
from redforge.sdk.subdomain_discovery import (
    SubdomainDiscoveryResult,
    SubdomainDiscoveryStatus,
    SubdomainProvider,
)
from redforge.sdk.tool import (
    ToolDefinition,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolId,
    ToolInvocation,
    ToolRunner,
)

SUBFINDER_TOOL_ID = ToolId("subfinder")
SUBFINDER_TOOL = ToolDefinition(
    tool_id=SUBFINDER_TOOL_ID,
    display_name="Subfinder",
    description="Performs passive subdomain enumeration.",
    executable="subfinder",
    version_argument=("-version",),
    default_timeout_seconds=600.0,
    tags=("passive", "recon", "subdomain"),
)


def _source_names(values: Iterable[str], *, label: str) -> tuple[str, ...]:
    if isinstance(cast(object, values), (str, bytes)):
        raise TypeError(f"{label} must be a collection")
    try:
        items = tuple(values)
    except TypeError as error:
        raise TypeError(f"{label} must be iterable") from error
    normalized: list[str] = []
    for value in items:
        if not isinstance(cast(object, value), str):
            raise TypeError(f"{label} must contain strings")
        item = value.strip().lower()
        if (
            not item
            or item[0] in "-_"
            or item[-1] in "-_"
            or any(
                not (character.isascii() and character.isalnum())
                and character not in "-_"
                for character in item
            )
        ):
            raise ValueError(f"{label} contains an invalid source")
        normalized.append(item)
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{label} contains duplicate sources")
    return tuple(sorted(normalized))


@dataclass(frozen=True, slots=True, init=False)
class SubfinderConfig:
    """Narrow immutable configuration for supported passive enumeration flags."""

    timeout_seconds: float | None
    max_enumeration_minutes: int | None
    rate_limit_per_second: int | None
    sources: tuple[str, ...]
    excluded_sources: tuple[str, ...]
    recursive: bool
    use_all_sources: bool

    def __init__(
        self,
        timeout_seconds: float | None = None,
        max_enumeration_minutes: int | None = None,
        rate_limit_per_second: int | None = None,
        sources: Iterable[str] = (),
        excluded_sources: Iterable[str] = (),
        recursive: bool = False,
        use_all_sources: bool = False,
    ) -> None:
        if timeout_seconds is not None and (
            isinstance(cast(object, timeout_seconds), bool)
            or not isinstance(cast(object, timeout_seconds), (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("Subfinder timeout must be positive and finite")
        for label, value in (
            ("maximum enumeration minutes", max_enumeration_minutes),
            ("rate limit", rate_limit_per_second),
        ):
            if value is not None and (
                not isinstance(cast(object, value), int)
                or isinstance(cast(object, value), bool)
                or value <= 0
            ):
                raise ValueError(f"Subfinder {label} must be a positive integer")
        if not isinstance(cast(object, recursive), bool):
            raise TypeError("Subfinder recursive flag must be boolean")
        if not isinstance(cast(object, use_all_sources), bool):
            raise TypeError("Subfinder all-sources flag must be boolean")
        included = _source_names(sources, label="Subfinder sources")
        excluded = _source_names(
            excluded_sources,
            label="Subfinder excluded sources",
        )
        if set(included).intersection(excluded):
            raise ValueError("Subfinder source cannot be included and excluded")
        if use_all_sources and included:
            raise ValueError("Subfinder all-sources conflicts with explicit sources")

        object.__setattr__(
            self,
            "timeout_seconds",
            float(timeout_seconds) if timeout_seconds is not None else None,
        )
        object.__setattr__(
            self,
            "max_enumeration_minutes",
            max_enumeration_minutes,
        )
        object.__setattr__(
            self,
            "rate_limit_per_second",
            rate_limit_per_second,
        )
        object.__setattr__(self, "sources", included)
        object.__setattr__(self, "excluded_sources", excluded)
        object.__setattr__(self, "recursive", recursive)
        object.__setattr__(self, "use_all_sources", use_all_sources)


@dataclass(frozen=True, slots=True)
class _ParseSummary:
    hostnames: tuple[str, ...]
    malformed_record_count: int
    out_of_scope_count: int
    duplicate_count: int

    @property
    def has_issues(self) -> bool:
        return bool(self.malformed_record_count or self.out_of_scope_count)


def _parse_jsonl(
    stdout: str,
    root_domain: str,
    *,
    discard_unterminated_final_line: bool,
) -> _ParseSummary:
    accepted: set[str] = set()
    malformed_count = 0
    out_of_scope_count = 0
    duplicate_count = 0
    lines = stdout.splitlines()
    if (
        discard_unterminated_final_line
        and stdout
        and not stdout.endswith(("\n", "\r"))
    ):
        malformed_count += 1
        lines = lines[:-1]

    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            malformed_count += 1
            continue
        if not isinstance(record, dict):
            malformed_count += 1
            continue
        host = cast(dict[object, object], record).get("host")
        if not isinstance(host, str):
            malformed_count += 1
            continue
        try:
            hostname = normalize_dns_hostname(host)
        except ValueError:
            malformed_count += 1
            continue
        if not hostname.endswith(f".{root_domain}"):
            out_of_scope_count += 1
            continue
        if hostname in accepted:
            duplicate_count += 1
            continue
        accepted.add(hostname)

    return _ParseSummary(
        hostnames=tuple(sorted(accepted)),
        malformed_record_count=malformed_count,
        out_of_scope_count=out_of_scope_count,
        duplicate_count=duplicate_count,
    )


class SubfinderSubdomainProvider:
    """Build passive Subfinder invocations and parse bounded JSONL evidence."""

    def __init__(
        self,
        *,
        runner: ToolRunner,
        definition: ToolDefinition = SUBFINDER_TOOL,
        config: SubfinderConfig | None = None,
    ) -> None:
        if not isinstance(cast(object, definition), ToolDefinition):
            raise TypeError("Subfinder provider requires a ToolDefinition")
        if definition.tool_id != SUBFINDER_TOOL_ID:
            raise ValueError("Subfinder provider tool identity does not match")
        self._runner = runner
        self._definition = definition
        self._config = config or SubfinderConfig()

    @property
    def definition(self) -> ToolDefinition:
        """Return immutable Subfinder execution metadata."""
        return self._definition

    @property
    def config(self) -> SubfinderConfig:
        """Return immutable supported adapter configuration."""
        return self._config

    def build_invocation(self, domain: str) -> ToolInvocation:
        """Return deterministic literal argv for passive JSONL enumeration."""
        root = normalize_dns_hostname(domain)
        arguments: list[str] = [
            "-d",
            root,
            "-json",
            "-silent",
            "-disable-update-check",
        ]
        if self._config.max_enumeration_minutes is not None:
            arguments.extend(
                ("-max-time", str(self._config.max_enumeration_minutes))
            )
        if self._config.rate_limit_per_second is not None:
            arguments.extend(
                ("-rl", str(self._config.rate_limit_per_second))
            )
        if self._config.recursive:
            arguments.append("-recursive")
        if self._config.use_all_sources:
            arguments.append("-all")
        if self._config.sources:
            arguments.extend(("-s", ",".join(self._config.sources)))
        if self._config.excluded_sources:
            arguments.extend(("-es", ",".join(self._config.excluded_sources)))
        return ToolInvocation(
            tool_id=self._definition.tool_id,
            arguments=arguments,
            timeout_seconds=self._config.timeout_seconds,
        )

    def discover(self, domain: str) -> SubdomainDiscoveryResult:
        """Run Subfinder once and map bounded tool evidence to domain semantics."""
        try:
            invocation = self.build_invocation(domain)
        except (TypeError, ValueError):
            return SubdomainDiscoveryResult(
                status=SubdomainDiscoveryStatus.ERROR,
                message="Subdomain discovery target is invalid.",
            )
        result = self._runner.run(self._definition, invocation)
        return self._map_result(
            result,
            root_domain=invocation.arguments[1],
        )

    @staticmethod
    def _map_result(
        result: ToolExecutionResult,
        *,
        root_domain: str,
    ) -> SubdomainDiscoveryResult:
        if result.status is ToolExecutionStatus.NOT_FOUND:
            return SubdomainDiscoveryResult(
                status=SubdomainDiscoveryStatus.UNAVAILABLE,
                message="Subfinder executable is unavailable.",
            )
        if result.status is ToolExecutionStatus.ERROR:
            return SubdomainDiscoveryResult(
                status=SubdomainDiscoveryStatus.ERROR,
                message="Subfinder execution failed.",
            )
        if result.status is ToolExecutionStatus.FAILURE:
            return SubdomainDiscoveryResult(
                status=SubdomainDiscoveryStatus.FAILURE,
                message="Subfinder returned a non-zero exit status.",
                truncated=result.truncated,
            )

        parsed = _parse_jsonl(
            result.stdout,
            root_domain,
            discard_unterminated_final_line=(
                result.status is ToolExecutionStatus.TIMEOUT
                or result.truncated
            ),
        )
        if result.status is ToolExecutionStatus.TIMEOUT:
            if parsed.hostnames:
                status = SubdomainDiscoveryStatus.PARTIAL
                message = "Subfinder enumeration timed out with partial findings."
            else:
                status = SubdomainDiscoveryStatus.FAILURE
                message = "Subfinder enumeration timed out."
        elif parsed.hostnames:
            status = (
                SubdomainDiscoveryStatus.PARTIAL
                if parsed.has_issues or result.truncated
                else SubdomainDiscoveryStatus.SUCCESS
            )
            message = (
                "Subfinder output contained incomplete or rejected records."
                if status is SubdomainDiscoveryStatus.PARTIAL
                else None
            )
        elif parsed.has_issues or result.truncated:
            status = SubdomainDiscoveryStatus.FAILURE
            message = "Subfinder output contained no valid in-scope records."
        else:
            status = SubdomainDiscoveryStatus.SUCCESS
            message = None

        return SubdomainDiscoveryResult(
            hostnames=parsed.hostnames,
            status=status,
            message=message,
            malformed_record_count=parsed.malformed_record_count,
            out_of_scope_count=parsed.out_of_scope_count,
            duplicate_count=parsed.duplicate_count,
            truncated=result.truncated,
        )


__all__ = [
    "SUBFINDER_TOOL",
    "SUBFINDER_TOOL_ID",
    "SubdomainDiscoveryResult",
    "SubdomainDiscoveryStatus",
    "SubdomainProvider",
    "SubfinderConfig",
    "SubfinderSubdomainProvider",
]
