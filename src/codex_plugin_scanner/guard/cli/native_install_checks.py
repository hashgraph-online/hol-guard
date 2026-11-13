"""Native OpenCode and Grok verification used by harness setup flows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..adapters.base import HarnessContext
from ..store import GuardStore


def _opencode_protection_checks(context: HarnessContext, store: GuardStore | None) -> dict[str, object]:
    """Verify the managed OpenCode plugin, launcher, and MCP routing configuration."""
    from ..adapters.opencode_runtime import opencode_protection_checks

    return opencode_protection_checks(context, store)


def _grok_pretool_is_catchall(pretool_hook: Path, context: HarnessContext | None = None) -> bool:
    """Check that Grok uses one managed catch-all pre-tool hook."""
    if not pretool_hook.is_file():
        return False
    try:
        payload = json.loads(pretool_hook.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        return False
    entries = hooks.get("PreToolUse")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        return False
    matcher = entries[0].get("matcher")
    if matcher not in {None, ""}:
        return False
    nested = entries[0].get("hooks")
    if not isinstance(nested, list) or len(nested) != 1 or not isinstance(nested[0], dict):
        return False
    command = nested[0].get("command")
    return (
        nested[0].get("type") == "command"
        and isinstance(command, str)
        and _grok_hook_command_is_guard(command, context)
    )


def _grok_hook_command_is_guard(command: str, context: HarnessContext | None = None) -> bool:
    """Validate a serialized native hook invocation, not arbitrary Guard marker text."""
    from .grok_hook_validation import is_grok_hook_command

    return is_grok_hook_command(command, context)


def _grok_prompt_hook_is_observe(prompt_hook: Path, context: HarnessContext | None = None) -> bool:
    """Verify the prompt gate and passive lifecycle callbacks have managed hooks."""
    if not prompt_hook.is_file():
        return False
    try:
        payload = json.loads(prompt_hook.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        return False
    required = ("UserPromptSubmit", "SubagentStart", "SessionStart")
    return all(_grok_event_has_command_hook(hooks.get(event_name), context) for event_name in required)


def _grok_event_has_command_hook(entries: object, context: HarnessContext | None = None) -> bool:
    """Find a valid Guard command hook in a native event configuration."""
    if not isinstance(entries, list) or not entries:
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        nested = entry.get("hooks")
        if not isinstance(nested, list):
            continue
        for hook_entry in nested:
            if not isinstance(hook_entry, dict) or hook_entry.get("type") != "command":
                continue
            command = hook_entry.get("command")
            if isinstance(command, str) and _grok_hook_command_is_guard(command, context):
                return True
    return False


def grok_protection(context: HarnessContext) -> dict[str, Any]:
    """Grok's protection paths, deny rules and hook timeouts, as the native adapter names them."""
    from ..adapters.native_harness import ask

    return ask("protection", context, harness="grok")


def grok_runtime_hooks_verified(context: HarnessContext) -> bool:
    """Return whether Grok catch-all PreToolUse and prompt screening hooks are installed.

    Managed permission rules in ``managed_config.toml`` are a second layer. Missing
    that file must not fail machine-wide local protection health while hooks still
    intercept every tool.
    """
    protection = grok_protection(context)
    return _grok_pretool_is_catchall(Path(protection["pretool_hook_path"]), context) and _grok_prompt_hook_is_observe(
        Path(protection["prompt_hook_path"]), context
    )


def _grok_managed_config_is_active(managed_text: str, context: HarnessContext) -> bool:
    """Verify durable permission floors, compatibility, and catch-all backup hooks."""
    from ..codex_config import tomllib

    try:
        payload = tomllib.loads(managed_text)
    except (ValueError, TypeError):
        return False
    permission = payload.get("permission")
    denied = permission.get("deny") if isinstance(permission, dict) else None
    compat = payload.get("compat")
    if (
        not isinstance(denied, list)
        or not all(rule in denied for rule in grok_protection(context)["managed_deny_rules"])
        or not isinstance(compat, dict)
    ):
        return False
    for vendor in ("claude", "cursor"):
        settings = compat.get(vendor)
        if not isinstance(settings, dict) or settings.get("hooks") is not False:
            return False
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        return False
    for event in ("PreToolUse", "UserPromptSubmit", "SessionStart", "SubagentStart"):
        entries = hooks.get(event)
        if not isinstance(entries, list):
            return False
        catchall = [entry for entry in entries if isinstance(entry, dict) and not entry.get("matcher")]
        if not _grok_event_has_command_hook(catchall, context):
            return False
    return True


def grok_hooks_protection_ready(context: HarnessContext) -> bool:
    """Return whether live Grok hook files and managed permission rules are active."""

    checks = _grok_protection_checks(context)
    warnings = checks.get("warnings")
    warning_items = warnings if isinstance(warnings, list) else []
    hook_warnings = [
        warning
        for warning in warning_items
        if isinstance(warning, str) and "shim" not in warning.lower() and "launcher" not in warning.lower()
    ]
    return (
        checks.get("pretool_catchall_installed") is True
        and checks.get("prompt_hook_installed") is True
        and checks.get("managed_config_installed") is True
        and not hook_warnings
    )


def _grok_has_legacy_deny_rules(text: str, deny_rules: list[str]) -> bool:
    from ..codex_config import tomllib

    try:
        payload = tomllib.loads(text)
    except (ValueError, TypeError):
        return False
    permission = payload.get("permission")
    denied = permission.get("deny") if isinstance(permission, dict) else None
    return isinstance(denied, list) and any(
        rule not in denied and rule.replace("**/", "~/", 1) in denied
        for rule in deny_rules
        if rule.startswith("Read(**/")
    )


def _grok_protection_checks(context: HarnessContext) -> dict[str, object]:
    """Report missing or stale Grok protection artifacts with repair instructions."""
    protection = grok_protection(context)
    managed_config = Path(protection["config_path"])
    pretool_hook = Path(protection["pretool_hook_path"])
    prompt_hook = Path(protection["prompt_hook_path"])
    warnings: list[str] = []
    if not pretool_hook.is_file() or not prompt_hook.is_file():
        warnings.append("Grok Guard hook files are missing from ~/.grok/hooks/. Re-run `hol-guard apps connect grok`.")
    elif not _grok_pretool_is_catchall(pretool_hook, context):
        warnings.append(
            "Grok Guard pre-tool hook still uses a stale per-tool matcher list. Re-run `hol-guard apps repair grok`."
        )
    elif not _grok_prompt_hook_is_observe(prompt_hook, context):
        warnings.append("The Grok prompt gate or lifecycle hooks are missing. Re-run `hol-guard apps repair grok`.")
    try:
        managed_text = managed_config.read_text(encoding="utf-8") if managed_config.is_file() else ""
        managed_read_error = False
    except (OSError, UnicodeError):
        managed_text = ""
        managed_read_error = True
    if managed_read_error:
        warnings.append("Grok managed config could not be read. Re-run `hol-guard apps repair grok`.")
    elif _grok_has_legacy_deny_rules(managed_text, protection["managed_deny_rules"]):
        warnings.append(
            "Grok managed deny rules still use literal home prefixes that Grok does not expand. "
            "Re-run `hol-guard apps repair grok`."
        )
    elif not managed_config.is_file() or not _grok_managed_config_is_active(managed_text, context):
        warnings.append(
            "Grok protection settings are missing or stale in .grok/config.toml. Re-run `hol-guard apps connect grok`."
        )
    shim_path = context.guard_home / "bin" / "guard-grok"
    if not shim_path.is_file():
        warnings.append(
            f"guard-grok launcher shim is missing. Add {context.guard_home / 'bin'} to PATH or launch with "
            "`hol-guard run grok` for pre-launch checks."
        )
    return {
        "pretool_hook_installed": pretool_hook.is_file(),
        "prompt_hook_installed": prompt_hook.is_file(),
        "pretool_catchall_installed": _grok_pretool_is_catchall(pretool_hook, context),
        "managed_config_installed": _grok_managed_config_is_active(managed_text, context),
        "launch_shim_installed": shim_path.is_file(),
        "warnings": warnings,
        "ready": not warnings,
    }
