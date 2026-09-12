"""Native OpenCode and Grok verification used by harness setup flows."""

from __future__ import annotations

import json
from pathlib import Path

from ..adapters.base import HarnessContext
from ..store import GuardStore


def _native_mcp_server_names(config_path: Path) -> set[str]:
    """Read configured native MCP names while excluding Guard companion identities."""
    from ...ecosystems.opencode import _load_json_or_jsonc

    payload, parse_error, _ = _load_json_or_jsonc(config_path)
    if parse_error or not isinstance(payload, dict):
        return set()
    mcp = payload.get("mcp")
    if not isinstance(mcp, dict):
        return set()
    return {name for name in mcp if isinstance(name, str) and not name.startswith("hol-guard::")}


def _opencode_protection_checks(context: HarnessContext, store: GuardStore | None) -> dict[str, object]:
    """Verify the managed OpenCode plugin, launcher, and MCP routing configuration."""
    from ..adapters.opencode import OpenCodeHarnessAdapter
    from ..adapters.opencode_artifacts import runtime_config_path
    from ..adapters.opencode_pretool import (
        global_plugin_path,
        opencode_config_has_mcp_servers,
        opencode_config_uses_guard_proxy,
    )

    adapter = OpenCodeHarnessAdapter()
    managed = store.get_managed_install("opencode") if store is not None else None
    config_path = adapter._managed_install_config_path(context)
    shim_path = context.guard_home / "bin" / "guard-opencode"
    plugin_path = global_plugin_path(context)
    loaded_config_paths = [Path(path) for path in adapter.detect(context).config_paths if Path(path).is_file()] or (
        [config_path] if config_path.is_file() else []
    )
    has_loaded_mcp = any(opencode_config_has_mcp_servers(path) for path in loaded_config_paths)
    if not has_loaded_mcp:
        mcp_proxy_configured = False
    else:
        mcp_proxy_configured = all(
            (not opencode_config_has_mcp_servers(path)) or opencode_config_uses_guard_proxy(path)
            for path in loaded_config_paths
        )
        runtime_overlay_path = runtime_config_path(context)
        if not mcp_proxy_configured and runtime_overlay_path.is_file():
            try:
                runtime_payload = json.loads(runtime_overlay_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                runtime_payload = {}
            runtime_mcp = runtime_payload.get("mcp")
            if isinstance(runtime_mcp, dict) and runtime_mcp:
                managed_server_names = {
                    name
                    for path in loaded_config_paths
                    if opencode_config_has_mcp_servers(path)
                    for name in _native_mcp_server_names(path)
                }
                mcp_proxy_configured = managed_server_names.issubset(set(runtime_mcp))
    has_unproxied_mcp = has_loaded_mcp and not mcp_proxy_configured
    warnings: list[str] = []
    if not (managed and managed.get("active")):
        warnings.append("Run `hol-guard install opencode` to activate Guard-managed OpenCode protection.")
    if not plugin_path.is_file():
        warnings.append(
            "OpenCode pretool plugin is missing from ~/.config/opencode/plugins/. Re-run `hol-guard install opencode`."
        )
    if not config_path.is_file():
        warnings.append(
            "OpenCode root config is missing at ~/.config/opencode/opencode.json. Re-run `hol-guard install opencode`."
        )
    if has_unproxied_mcp:
        warnings.append(
            "OpenCode MCP servers are not routed through hol-guard companion servers or the runtime overlay. "
            "Re-run `hol-guard install opencode`."
        )
    if not shim_path.is_file():
        warnings.append(
            f"guard-opencode launcher shim is missing. Add {context.guard_home / 'bin'} to PATH or launch with "
            "`hol-guard run opencode` for pre-launch checks."
        )
    return {
        "pretool_plugin_installed": plugin_path.is_file(),
        "mcp_proxy_configured": mcp_proxy_configured,
        "launch_shim_installed": shim_path.is_file(),
        "managed_install_active": bool(managed and managed.get("active")),
        "warnings": warnings,
        "ready": not warnings,
    }


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
    """Verify the required Grok observation events have managed command hooks."""
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


def _grok_managed_config_is_active(managed_text: str) -> bool:
    """Require the credential deny rule in the parsed managed permission table."""
    from ..adapters.grok_config import GUARD_MANAGED_BEGIN, GUARD_MANAGED_END
    from ..codex_config import tomllib

    start = managed_text.find(GUARD_MANAGED_BEGIN)
    stop = managed_text.find(GUARD_MANAGED_END)
    if start < 0 or stop <= start:
        return False
    try:
        payload = tomllib.loads(managed_text[start:stop])
    except (ValueError, TypeError):
        return False
    permission = payload.get("permission")
    denied = permission.get("deny") if isinstance(permission, dict) else None
    return isinstance(denied, list) and "Read(**/.grok/auth/**)" in denied


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


def _grok_protection_checks(context: HarnessContext) -> dict[str, object]:
    """Report missing or stale Grok protection artifacts with repair instructions."""
    from ..adapters.grok import GrokHarnessAdapter

    adapter = GrokHarnessAdapter()
    hooks_dir = adapter._hooks_dir(context)
    managed_config = adapter._managed_config_path(context)
    pretool_hook = hooks_dir / "hol-guard-pretooluse.json"
    prompt_hook = hooks_dir / "hol-guard-prompt.json"
    warnings: list[str] = []
    if not pretool_hook.is_file() or not prompt_hook.is_file():
        warnings.append("Grok Guard hook files are missing from ~/.grok/hooks/. Re-run `hol-guard apps connect grok`.")
    elif not _grok_pretool_is_catchall(pretool_hook, context):
        warnings.append(
            "Grok Guard pre-tool hook still uses a stale per-tool matcher list. Re-run `hol-guard apps repair grok`."
        )
    elif not _grok_prompt_hook_is_observe(prompt_hook, context):
        warnings.append(
            "Grok Guard observe hooks are missing prompt, session, or subagent events. "
            "Re-run `hol-guard apps repair grok`."
        )
    try:
        managed_text = managed_config.read_text(encoding="utf-8") if managed_config.is_file() else ""
        managed_read_error = False
    except (OSError, UnicodeError):
        managed_text = ""
        managed_read_error = True
    if managed_read_error:
        warnings.append("Grok managed config could not be read. Re-run `hol-guard apps repair grok`.")
    elif not managed_config.is_file() or not _grok_managed_config_is_active(managed_text):
        warnings.append(
            "Grok managed permission rules are missing from ~/.grok/managed_config.toml. "
            "Re-run `hol-guard apps connect grok`."
        )
    elif "Read(~/" in managed_text:
        warnings.append(
            "Grok managed deny rules still use literal home prefixes that Grok does not expand. "
            "Re-run `hol-guard apps repair grok`."
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
        "managed_config_installed": managed_config.is_file(),
        "launch_shim_installed": shim_path.is_file(),
        "warnings": warnings,
        "ready": not warnings,
    }
