"""A Codex hook state shaped like the one the runtime's `live_hook_state` returns."""

from __future__ import annotations

from collections.abc import Callable

from codex_plugin_scanner.guard.harness_context import HarnessContext

MANAGED_EVENTS = ("pre_tool", "permission_request", "prompt", "post_tool")


def guard_hooks_state(context: HarnessContext, *, verified: bool, reason: str | None) -> dict[str, object]:
    """Guard's hooks are present for every managed event; `verified` says whether
    their manifest still matches this Guard CLI."""

    codex_home = context.home_dir / ".codex"
    state: dict[str, object] = {
        "config_path": str(codex_home / "config.toml"),
        "config_present": True,
        "hooks_path": str(codex_home / "hooks.json"),
        "hooks_present": True,
        "toml_hooks_present": False,
        "json_hooks_present": True,
        "hooks_enabled": True,
        "codex_hooks_enabled": True,
        "legacy_codex_hooks_enabled": False,
        "managed_hook_installed": True,
        "shell_enforcement_boundary": "codex-native-hooks",
        "shell_hook_installed": True,
        "shell_protection_active": verified,
        "shell_reason_code": None if verified else "codex_authoritative_hook_unavailable",
        "protection_active": verified,
        "hook_trust_stale": False,
        "bridge_sha256": None,
        "foreign_hook_entries_present": False,
        "foreign_hook_group_count": 0,
        "integrity_message": None if verified else "The Codex hook interpreter does not match this Guard installation.",
        "integrity_reason": reason,
        "integrity_status": "valid" if verified else "tampered",
        "interpreter_sha256": None,
        "manifest_generated_at": None,
        "manifest_package_version": None,
        "manifest_path": str(context.guard_home / "managed" / "codex" / "hooks.manifest.json"),
        "manifest_schema_version": None,
    }
    for event in MANAGED_EVENTS:
        state[f"managed_{event}_hook_installed"] = True
    return state


def fixed_hook_state(*, verified: bool, reason: str | None = None) -> Callable[[HarnessContext], dict[str, object]]:
    """A `codex_native_hook_state` stand-in that answers `guard_hooks_state`."""

    return lambda context: guard_hooks_state(context, verified=verified, reason=reason)
