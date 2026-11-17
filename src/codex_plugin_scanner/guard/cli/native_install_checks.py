"""Native OpenCode and Grok verification used by harness setup flows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..harness.base import HarnessContext
from ..store import GuardStore


def _opencode_protection_checks(context: HarnessContext, store: GuardStore | None) -> dict[str, object]:
    """Verify the managed OpenCode plugin, launcher, and MCP routing configuration."""
    from ..harness.native_harness import ask
    from ..harness.registry import get_adapter

    managed = store.get_managed_install("opencode") if store is not None else None
    answer = ask(
        "protection",
        context,
        harness="opencode",
        managed_active=bool(managed and managed.get("active")),
        config_paths=list(get_adapter("opencode").detect(context).config_paths),
    )
    return json.loads(str(answer["checks"]))


#: A hook check may verify a signed Desktop proxy, which runs three `codesign` checks of up to 5s each.
_GROK_HOOK_CHECK_TIMEOUT_SECONDS = 60.0


def _grok_hook_check(op: str, context: HarnessContext | None, **fields: object) -> dict[str, Any]:
    """Ask the native runtime a Grok hook question, owned by ``context`` or by no one."""
    from ..config import resolve_guard_home
    from ..harness.native_harness import ask

    scope = context or HarnessContext(Path.home(), None, resolve_guard_home())
    return ask(op, scope, owner=context is not None, timeout_seconds=_GROK_HOOK_CHECK_TIMEOUT_SECONDS, **fields)


def _grok_hook_command_is_guard(command: str, context: HarnessContext | None = None) -> bool:
    """Whether a serialized hook invocation is Guard's native Grok hook, not arbitrary marker text."""
    return _grok_hook_check("grok_hook_command", context, command=command)["valid"] is True


def _grok_hook_files(context: HarnessContext, pretool_hook: Path, prompt_hook: Path) -> tuple[bool, bool]:
    """Whether the pre-tool file is the managed catch-all and the prompt file has the prompt and lifecycle hooks."""
    answer = _grok_hook_check("grok_hook_files", context, pretool=str(pretool_hook), prompt=str(prompt_hook))
    return answer["pretool"] is True, answer["prompt"] is True


def grok_protection(context: HarnessContext) -> dict[str, Any]:
    """Grok's protection paths, deny rules and hook timeouts, as the native adapter names them."""
    from ..harness.native_harness import ask

    return ask("protection", context, harness="grok")


def grok_runtime_hooks_verified(context: HarnessContext) -> bool:
    """Return whether Grok catch-all PreToolUse and prompt screening hooks are installed.

    Managed permission rules in ``managed_config.toml`` are a second layer. Missing
    that file must not fail machine-wide local protection health while hooks still
    intercept every tool.
    """
    protection = grok_protection(context)
    return all(_grok_hook_files(context, Path(protection["pretool_hook_path"]), Path(protection["prompt_hook_path"])))


def _grok_managed_config_is_active(managed_text: str, context: HarnessContext) -> bool:
    """Verify durable permission floors, compatibility, and catch-all backup hooks."""
    from ..codex_config import loads_toml

    try:
        payload = loads_toml(managed_text)
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
    events = [hooks.get(event) for event in ("PreToolUse", "UserPromptSubmit", "SessionStart", "SubagentStart")]
    return _grok_hook_check("grok_hook_events", context, events=events, catchall=True)["valid"] is True


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
    from ..codex_config import loads_toml

    try:
        payload = loads_toml(text)
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
    pretool_catchall, prompt_observe = _grok_hook_files(context, pretool_hook, prompt_hook)
    if not pretool_hook.is_file() or not prompt_hook.is_file():
        warnings.append("Grok Guard hook files are missing from ~/.grok/hooks/. Re-run `hol-guard apps connect grok`.")
    elif not pretool_catchall:
        warnings.append(
            "Grok Guard pre-tool hook still uses a stale per-tool matcher list. Re-run `hol-guard apps repair grok`."
        )
    elif not prompt_observe:
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
        "pretool_catchall_installed": pretool_catchall,
        "managed_config_installed": _grok_managed_config_is_active(managed_text, context),
        "launch_shim_installed": shim_path.is_file(),
        "warnings": warnings,
        "ready": not warnings,
    }
