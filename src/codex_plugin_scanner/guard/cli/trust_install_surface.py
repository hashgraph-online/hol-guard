"""Installed-CLI facts for the trust doctor payload."""

from __future__ import annotations

import importlib.metadata
import json
from collections.abc import Callable
from typing import Any

from .update_commands import build_guard_install_surface_payload


def _installed_trust_cli_payload(
    *,
    install_surface: dict[str, object] | None = None,
    resolve_distribution: Callable[[str], Any] | None = None,
) -> dict[str, object]:
    """Build installed-CLI facts; callers may inject their resolved collaborators."""
    version = None
    installation_mode = "unknown"
    editable_install = False
    official_install = False
    if install_surface is None:
        install_surface = build_guard_install_surface_payload()
    binary_diagnostics = install_surface.get("binary_diagnostics")
    if not isinstance(binary_diagnostics, dict):
        binary_diagnostics = {}
    distribution_resolver = resolve_distribution or importlib.metadata.distribution
    try:
        distribution = distribution_resolver("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        distribution = None
    if distribution is not None:
        version = distribution.version
        direct_url_text = distribution.read_text("direct_url.json")
        if isinstance(direct_url_text, str) and direct_url_text.strip():
            try:
                direct_url_payload = json.loads(direct_url_text)
            except json.JSONDecodeError:
                direct_url_payload = None
            dir_info = direct_url_payload.get("dir_info") if isinstance(direct_url_payload, dict) else None
            editable_install = bool(isinstance(dir_info, dict) and dir_info.get("editable") is True)
        try:
            distribution_root = str(distribution.locate_file("")).replace("\\", "/")
        except Exception:
            distribution_root = ""
        official_install = (
            "pipx/venvs/hol-guard/" in distribution_root or "/venvs/hol-guard/" in distribution_root
        ) and not editable_install
        if official_install:
            installation_mode = "official-pipx"
        elif editable_install:
            installation_mode = "editable"
        else:
            installation_mode = "packaged"
    active_command_status = str(binary_diagnostics.get("path_status") or "unknown")
    active_command_verified = active_command_status in {
        "pipx_shim_detected",
        "uv_tool_shim_detected",
        "matches_installer",
    }
    return {
        "package": "hol-guard",
        "version": version,
        "installation_mode": installation_mode,
        "official_install": official_install,
        "official_install_verified": official_install and active_command_status == "pipx_shim_detected",
        "editable_install": editable_install,
        "installer": install_surface.get("installer"),
        "active_command_path": binary_diagnostics.get("resolved_hol_guard"),
        "active_command_status": active_command_status,
        "active_command_verified": active_command_verified,
        "expected_script_dir": binary_diagnostics.get("expected_script_dir"),
        "self_check_command": "command -v hol-guard && hol-guard --version",
        "update_command": "hol-guard update",
        "dry_run_command": "hol-guard update --dry-run --json",
    }
