"""Adapter for WhatWeb technology detection."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from redforge.domain.technology import Technology

if TYPE_CHECKING:
    from collections.abc import Sequence


class TechnologyDetectionAdapterError(Exception):
    """Base exception for technology detection adapter errors."""

    pass


class TechnologyDetectionNotFoundError(TechnologyDetectionAdapterError):
    """Raised when WhatWeb binary is not found."""

    pass


class TechnologyDetectionExecutionError(TechnologyDetectionAdapterError):
    """Raised when WhatWeb execution fails."""

    def __init__(self, returncode: int | None, stderr: str) -> None:
        self.returncode = returncode
        self.stderr = stderr
        if returncode is None:
            message = "WhatWeb execution failed"
        else:
            message = f"WhatWeb execution failed with return code {returncode}"
        if stderr:
            message = f"{message}: {stderr.strip()}"
        super().__init__(message)


class TechnologyDetectionParseError(TechnologyDetectionAdapterError):
    """Raised when WhatWeb output cannot be parsed."""

    pass


class TechnologyDetectionAdapter:
    """Adapter for executing WhatWeb and parsing its JSON output.

    This adapter handles subprocess execution, output capture, and parsing
    of technology detection results from WhatWeb into Technology domain objects.
    """

    def __init__(self, binary_path: str = "whatweb", timeout_seconds: float = 120.0) -> None:
        """Initialize the technology detection adapter.

        Args:
            binary_path: Path to the WhatWeb binary (default: "whatweb").
            timeout_seconds: Maximum execution time before terminating WhatWeb.
        """
        self.binary_path = binary_path
        self.timeout_seconds = timeout_seconds

    def verify_binary(self) -> None:
        """Verify that WhatWeb binary exists and is executable.

        Raises:
            TechnologyDetectionNotFoundError: If WhatWeb binary is not found.
        """
        if not shutil.which(self.binary_path):
            raise TechnologyDetectionNotFoundError(
                f"WhatWeb binary not found: {self.binary_path}"
            )

    def detect_technologies(self, endpoints: list[str]) -> list[Technology]:
        """Detect technologies for the given endpoints using WhatWeb.

        Args:
            endpoints: List of endpoint URLs to analyze.

        Returns:
            List of detected technologies.

        Raises:
            TechnologyDetectionNotFoundError: If WhatWeb binary is not found.
            TechnologyDetectionExecutionError: If WhatWeb execution fails.
            TechnologyDetectionParseError: If WhatWeb output cannot be parsed.
        """
        if not endpoints:
            return []

        self.verify_binary()

        with tempfile.TemporaryDirectory(prefix="redforge-whatweb-") as temporary_directory:
            directory = Path(temporary_directory)
            input_path = directory / "targets.txt"
            output_path = directory / "results.json"
            input_path.write_text("\n".join(endpoints), encoding="utf-8")

            command: Sequence[str] = [
                self.binary_path,
                f"--input-file={input_path}",
                f"--log-json={output_path}",
                "--quiet",
            ]
            try:
                subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=self.timeout_seconds,
                )
            except subprocess.CalledProcessError as e:
                raise TechnologyDetectionExecutionError(e.returncode, e.stderr) from e
            except subprocess.TimeoutExpired as e:
                raise TechnologyDetectionExecutionError(
                    None, f"timed out after {self.timeout_seconds:g} seconds"
                ) from e
            except OSError as e:
                raise TechnologyDetectionExecutionError(None, str(e)) from e

            if not output_path.exists():
                raise TechnologyDetectionParseError("WhatWeb did not create its JSON output file")

            return self._parse_output(output_path.read_text(encoding="utf-8"))

    def _parse_output(self, output: str) -> list[Technology]:
        technologies: list[Technology] = []
        seen: set[Technology] = set()
        if not output.strip():
            return technologies

        try:
            parsed = json.loads(output)
        except json.JSONDecodeError as e:
            raise TechnologyDetectionParseError(
                f"Failed to parse WhatWeb JSON output: {e}"
            ) from e

        if not isinstance(parsed, list):
            raise TechnologyDetectionParseError("WhatWeb JSON output must be an array")

        for item in cast(list[Any], parsed):
            if not isinstance(item, dict):
                raise TechnologyDetectionParseError(
                    "Each WhatWeb JSON result must be an object"
                )
            entry = cast(dict[str, Any], item)
            endpoint_technologies = self._entry_to_technologies(entry)
            for tech in endpoint_technologies:
                if tech in seen:
                    continue
                seen.add(tech)
                technologies.append(tech)

        return technologies

    def _entry_to_technologies(self, entry: dict[str, Any]) -> list[Technology]:
        """Convert a WhatWeb entry to Technology objects."""
        technologies: list[Technology] = []
        plugins = entry.get("plugins", {})
        target = entry.get("target")
        source = target if isinstance(target, str) and target else None

        if not isinstance(plugins, dict):
            return technologies

        typed_plugins = cast(dict[str, Any], plugins)
        for plugin_name, plugin_data in typed_plugins.items():
            if not isinstance(plugin_data, dict):
                continue

            technologies.extend(
                self._plugin_to_technologies(
                    plugin_name, cast(dict[str, Any], plugin_data), source
                )
            )

        return technologies

    def _plugin_to_technologies(
        self, plugin_name: str, plugin_data: dict[str, Any], source: str | None
    ) -> list[Technology]:
        """Convert one WhatWeb plugin result to technology observations."""
        versions = self._string_values(plugin_data.get("version")) or [None]
        evidence = self._extract_evidence(plugin_data)
        confidence = self._extract_confidence(plugin_data)
        category = self._infer_category(plugin_name)

        return [
            Technology(
                name=plugin_name,
                category=category,
                version=version,
                source=source,
                evidence=evidence,
                confidence=confidence,
            )
            for version in versions
        ]

    def _extract_evidence(self, plugin_data: dict[str, Any]) -> tuple[str, ...]:
        """Extract useful match metadata without retaining adapter-specific structures."""
        evidence: list[str] = []
        for field in ("string", "os", "account", "model", "firmware", "module", "filepath"):
            evidence.extend(
                f"{field}: {value}" for value in self._string_values(plugin_data.get(field))
            )
        return tuple(evidence)

    def _extract_confidence(self, plugin_data: dict[str, Any]) -> int | None:
        """Return WhatWeb certainty, which is omitted when the match is certain."""
        certainty = plugin_data.get("certainty")
        if certainty is None:
            return 100
        if isinstance(certainty, bool) or not isinstance(certainty, int):
            return None
        return certainty if 0 <= certainty <= 100 else None

    def _string_values(self, value: Any) -> list[str]:
        """Normalize WhatWeb scalar or array fields to non-empty strings."""
        if isinstance(value, str):
            return [value] if value else []
        if not isinstance(value, list):
            return []
        return [item for item in cast(list[Any], value) if isinstance(item, str) and item]

    def _infer_category(self, plugin_name: str) -> str:
        """Infer technology category from plugin name."""
        plugin_lower = plugin_name.lower()

        # Common web frameworks
        if any(
            fw in plugin_lower
            for fw in ["django", "flask", "rails", "express", "spring", "laravel"]
        ):
            return "framework"

        # Web servers
        if any(
            ws in plugin_lower
            for ws in ["nginx", "apache", "iis", "lighttpd", "caddy", "traefik"]
        ):
            return "web-server"

        # Databases
        if any(
            db in plugin_lower
            for db in ["mysql", "postgresql", "mongodb", "redis", "sqlite", "oracle"]
        ):
            return "database"

        # JavaScript libraries
        if any(
            js in plugin_lower
            for js in ["jquery", "react", "angular", "vue", "backbone", "ember"]
        ):
            return "javascript-library"

        # CMS
        if any(cms in plugin_lower for cms in ["wordpress", "drupal", "joomla", "ghost"]):
            return "cms"

        # Analytics
        if any(
            an in plugin_lower for an in ["google analytics", "analytics", "tracking"]
        ):
            return "analytics"

        # CDNs
        if any(cdn in plugin_lower for cdn in ["cloudflare", "akamai", "fastly"]):
            return "cdn"

        # Default category
        return "other"
