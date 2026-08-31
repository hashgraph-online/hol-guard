"""Validate the hook data-plane ownership contract."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Final

SCHEMA: Final = "hol-guard.hook-data-plane-ownership.v2"
NODE_CLASSES: Final = frozenset(
    {
        "rust_semantic",
        "rust_io",
        "python_semantic",
        "python_transport",
        "python_control",
        "persistence_only",
    }
)
HARNESS_ROUTE_STATUSES: Final = frozenset(
    {
        "detected_external_only",
        "installed_alias_requires_native_normalization",
        "installed_canonical",
        "installed_canonical_source_ref",
        "installed_cli_bridge",
        "installed_observation_only",
        "normalizer_only_not_installed",
        "preflight_only",
        "unavailable",
    }
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(f"required authority source is missing: {path}") from exc


def registered_harnesses() -> frozenset[str]:
    path = Path("src/codex_plugin_scanner/guard/adapters/contracts.py")
    tree = ast.parse(_read(path), filename=str(path))
    harnesses: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id != "HarnessProtectionContract":
            continue
        value = next((keyword.value for keyword in node.keywords if keyword.arg == "harness"), None)
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            harnesses.add(value.value)
    if not harnesses:
        raise RuntimeError("registered harness inventory is empty")
    return frozenset(harnesses)


def _validate_identity(value: dict[str, object]) -> None:
    if value.get("schema") != SCHEMA:
        raise RuntimeError("hook data-plane ownership manifest has an invalid schema")
    for key in ("audit_baseline", "implementation_base"):
        digest = value.get(key)
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{40}", digest) is None:
            raise RuntimeError(f"hook data-plane ownership manifest has an invalid {key}")
    if value.get("target_branch") != "main":
        raise RuntimeError("hook data-plane ownership target must remain main")


def _validate_harnesses(value: dict[str, object]) -> None:
    registered = registered_harnesses()
    harnesses = value.get("supported_harnesses")
    if not isinstance(harnesses, list) or set(harnesses) != registered:
        raise RuntimeError("hook data-plane ownership harness inventory is incomplete")
    routes = value.get("harness_routes")
    if not isinstance(routes, dict) or set(routes) != registered:
        raise RuntimeError("hook data-plane route inventory is incomplete")
    for harness, route in routes.items():
        if not isinstance(route, dict) or set(route) != {"pre_tool_use", "post_tool_use"}:
            raise RuntimeError(f"hook data-plane route is incomplete: {harness}")
        if set(route.values()) - HARNESS_ROUTE_STATUSES:
            raise RuntimeError(f"hook data-plane route has an invalid status: {harness}")


def _validate_routes(value: dict[str, object]) -> None:
    routes = value.get("routes")
    expected = {"http_pre_tool_use", "http_post_tool_use", "cli_pre_tool_use", "cli_post_tool_use"}
    if not isinstance(routes, list) or {route.get("id") for route in routes if isinstance(route, dict)} != expected:
        raise RuntimeError("hook data-plane production routes are incomplete")
    for route in routes:
        if not isinstance(route, dict):
            raise RuntimeError("hook data-plane production route is invalid")
        route_id = route.get("id")
        if route.get("target_authority") != "rust" or route.get("python_semantic_fallback_target") is not False:
            raise RuntimeError(f"hook data-plane target authority is not exclusive: {route_id}")
        if route.get("native_failure") != "fail_closed":
            raise RuntimeError(f"hook data-plane route is not fail closed: {route_id}")


def _validate_defaults(value: dict[str, object]) -> None:
    defaults = value.get("production_defaults")
    if not isinstance(defaults, dict):
        raise RuntimeError("hook data-plane production defaults are missing")
    native = defaults.get("HOL_GUARD_NATIVE")
    binary = defaults.get("HOL_GUARD_NATIVE_BINARY")
    fast_path = defaults.get("HOL_GUARD_HOOK_FAST_PATH")
    if not isinstance(native, dict) or native.get("unset") != "auto" or native.get("invalid") != "auto":
        raise RuntimeError("unset or invalid native mode does not select auto")
    if not isinstance(binary, dict) or binary.get("auto_override") != "ignored":
        raise RuntimeError("auto mode may accept a native binary override")
    if not isinstance(fast_path, dict) or fast_path.get("unset") != "enabled":
        raise RuntimeError("unset fast-path configuration is not enabled")
    if defaults.get("runtime_search") != "package_only_no_path" or defaults.get("runtime_download") is not False:
        raise RuntimeError("production runtime selection is not package-bound")


def _validate_nodes(value: dict[str, object]) -> None:
    nodes = value.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise RuntimeError("hook data-plane ownership nodes are missing")
    node_ids: set[str] = set()
    for node in nodes:
        if not isinstance(node, dict):
            raise RuntimeError("hook data-plane ownership node is invalid")
        node_id = node.get("id")
        paths = node.get("paths")
        if not isinstance(node_id, str) or not node_id or node_id in node_ids:
            raise RuntimeError("hook data-plane ownership node id is invalid or duplicated")
        node_ids.add(node_id)
        if node.get("class") not in NODE_CLASSES:
            raise RuntimeError(f"hook data-plane ownership class is invalid: {node_id}")
        if not isinstance(paths, list) or not paths or not all(isinstance(path, str) and path for path in paths):
            raise RuntimeError(f"hook data-plane ownership paths are missing: {node_id}")
        for pattern in paths:
            if not any(Path.cwd().glob(pattern)):
                raise RuntimeError(f"hook data-plane ownership path has no repository match: {pattern}")


def load_manifest(path: Path) -> dict[str, object]:
    """Load and validate the declarative ownership contract."""
    value = json.loads(_read(path))
    if not isinstance(value, dict):
        raise RuntimeError("hook data-plane ownership manifest has an invalid schema")
    _validate_identity(value)
    _validate_harnesses(value)
    _validate_routes(value)
    _validate_defaults(value)
    _validate_nodes(value)
    return value
