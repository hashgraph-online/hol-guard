"""Validated manifest and config paths for Hermes lifecycle operations."""

from __future__ import annotations

from pathlib import Path

from .adapter_state_integrity import adapter_state_is_authenticated
from .base import HarnessContext, _ensure_path_within_root, _json_payload
from .hermes_file_inspection import inspect_hermes_config


def hermes_install_paths(context: HarnessContext, managed_root: Path) -> tuple[Path, Path, Path]:
    _ensure_path_within_root(context.guard_home, managed_root, label="Hermes managed")
    paths = (
        managed_root / "manifest.json",
        managed_root / "mcp-overlay.json",
        managed_root / "pretool-hook.json",
    )
    for path in paths:
        _ensure_path_within_root(managed_root, path, label="Hermes managed")
    return paths


def hermes_install_config_path(context: HarnessContext, current_home: Path) -> Path:
    path = current_home / "config.yaml"
    _ensure_path_within_root(current_home, path, label="Hermes config")
    return path


def hermes_manifest(context: HarnessContext, managed_root: Path) -> dict[str, object]:
    manifest_path = managed_root / "manifest.json"
    _ensure_path_within_root(context.guard_home, manifest_path, label="Hermes manifest")
    return _json_payload(manifest_path)


def hermes_uninstall_state(
    context: HarnessContext,
    managed_root: Path,
    current_home: Path,
) -> tuple[dict[str, object], Path | None]:
    manifest = hermes_manifest(context, managed_root)
    authenticated = adapter_state_is_authenticated(context.guard_home, harness="hermes", payload=manifest)
    return manifest, validated_hermes_config_path(
        context,
        current_home,
        manifest.get("hermes_config_yaml_path"),
        authenticated_resolved_path=manifest.get("hermes_config_yaml_resolved_path"),
        authenticated=authenticated,
    )


def hermes_previous_guard_for_install(
    context: HarnessContext,
    existing_manifest: dict[str, object],
    observed_previous_guard: dict[str, object] | None,
) -> dict[str, object] | None:
    if not adapter_state_is_authenticated(context.guard_home, harness="hermes", payload=existing_manifest):
        return observed_previous_guard
    previous = existing_manifest.get("previous_guard_section")
    return previous if isinstance(previous, dict) else None


def hermes_cleanup_values(
    context: HarnessContext,
    manifest: dict[str, object],
    config_path: Path,
) -> tuple[list[str], dict[str, object] | None]:
    if adapter_state_is_authenticated(context.guard_home, harness="hermes", payload=manifest):
        names = manifest.get("managed_server_names")
        previous = manifest.get("previous_guard_section")
        managed_names = [name for name in names if isinstance(name, str)] if isinstance(names, list) else []
        return managed_names, previous if isinstance(previous, dict) else None
    return _legacy_guard_proxy_names(context, config_path), None


def _legacy_guard_proxy_names(context: HarnessContext, config_path: Path) -> list[str]:
    inspection = inspect_hermes_config(config_path, syntax="yaml")
    if not inspection.complete or inspection.payload is None:
        return []
    servers = inspection.payload.get("mcp_servers")
    if not isinstance(servers, dict):
        return []
    managed: list[str] = []
    marker = ["-m", "codex_plugin_scanner.cli", "hermes", "mcp-proxy", "--guard-home", str(context.guard_home)]
    for name, config in servers.items():
        args = config.get("args") if isinstance(config, dict) else None
        if isinstance(name, str) and isinstance(args, list) and args[: len(marker)] == marker:
            managed.append(name)
    return managed


def remove_hermes_managed_files(context: HarnessContext, managed_root: Path) -> list[str]:
    removed: list[str] = []
    for path in (
        managed_root / "mcp-overlay.json",
        managed_root / "pretool-hook.json",
        managed_root / "manifest.json",
    ):
        _ensure_path_within_root(managed_root, path, label="Hermes managed")
        if path.exists():
            path.unlink()
            removed.append(str(path))
    return removed


def validated_hermes_managed_paths(
    context: HarnessContext,
    manifest: dict[str, object],
    managed_root: Path,
) -> tuple[Path, Path] | None:
    if "state_authentication" in manifest and not adapter_state_is_authenticated(
        context.guard_home,
        harness="hermes",
        payload=manifest,
    ):
        return None
    expected_overlay = managed_root / "mcp-overlay.json"
    expected_pretool = managed_root / "pretool-hook.json"
    try:
        _ensure_path_within_root(context.guard_home, managed_root, label="Hermes managed")
        _ensure_path_within_root(managed_root, expected_overlay, label="Hermes managed")
        _ensure_path_within_root(managed_root, expected_pretool, label="Hermes managed")
    except ValueError:
        return None
    overlay_value = manifest.get("mcp_overlay_path")
    pretool_value = manifest.get("pretool_hook_path")
    if not isinstance(overlay_value, str) or not overlay_value or "\x00" in overlay_value:
        return None
    if not isinstance(pretool_value, str) or not pretool_value or "\x00" in pretool_value:
        return None
    overlay_path = Path(overlay_value)
    pretool_path = Path(pretool_value)
    if not overlay_path.is_absolute() or not pretool_path.is_absolute():
        return None
    if overlay_path.resolve() != expected_overlay.resolve() or pretool_path.resolve() != expected_pretool.resolve():
        return None
    return expected_overlay, expected_pretool


def validated_hermes_config_path(
    context: HarnessContext,
    current_home: Path,
    value: object,
    *,
    authenticated_resolved_path: object = None,
    authenticated: bool,
) -> Path | None:
    candidate = current_home / "config.yaml" if not isinstance(value, str) or not value else Path(value)
    if "\x00" in str(candidate) or not candidate.is_absolute() or candidate.name != "config.yaml":
        return None
    if authenticated:
        if not isinstance(authenticated_resolved_path, str) or "\x00" in authenticated_resolved_path:
            return None
        expected_resolved = Path(authenticated_resolved_path)
        if not expected_resolved.is_absolute() or candidate.resolve() != expected_resolved:
            return None
        return candidate
    for allowed_root in (context.home_dir, current_home):
        try:
            _ensure_path_within_root(allowed_root, candidate, label="Hermes config")
        except ValueError:
            continue
        return candidate
    return None
