"""Lightweight import-boundary regression tests."""

import ast
from pathlib import Path

_SOURCE_ROOT = Path(__file__).parents[1] / "src" / "redforge"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    return imported


def test_domain_does_not_import_adapters_runtime_or_external_transports() -> None:
    forbidden = ("redforge.adapters", "redforge.runtime", "socket", "urllib", "httpx")
    for path in (_SOURCE_ROOT / "domain").glob("*.py"):
        imports = _imports(path)
        assert not any(
            name == prefix or name.startswith(f"{prefix}.")
            for name in imports
            for prefix in forbidden
        ), path


def test_capabilities_do_not_import_transport_libraries_or_socket() -> None:
    forbidden = ("socket", "urllib.request", "urllib.error", "httpx", "requests")
    for path in (_SOURCE_ROOT / "capabilities").glob("*.py"):
        imports = _imports(path)
        assert not any(
            name == prefix or name.startswith(f"{prefix}.")
            for name in imports
            for prefix in forbidden
        ), path


def test_vulnerability_capability_does_not_reference_nvd_payload_keys() -> None:
    source = (
        _SOURCE_ROOT / "capabilities" / "vulnerability_intelligence.py"
    ).read_text(encoding="utf-8")
    for provider_key in (
        "vulnerabilities",
        "startIndex",
        "resultsPerPage",
        "totalResults",
        "cvssMetricV31",
    ):
        assert f'"{provider_key}"' not in source
