"""Exact ownership and legacy-adoption operations for Codex hook groups."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path

from .codex_hook_command_line import (
    hook_command_launchable,
    hook_command_tokens,
    hook_commands_use_windows_syntax,
    hook_token_name,
    plain_json_hook_argv,
)
from .codex_hook_file_integrity import split_hook_command
from .codex_hook_foreign_groups import is_foreign_guard_codex_hook_group, prune_foreign_guard_codex_hook_groups
from .codex_hook_manifest import MANAGED_CODEX_HOOK_EVENTS
from .codex_hook_owner_commands import has_codex_harness_tokens, python_codex_hook_command
from .frozen_runtime_commands import frozen_codex_bridge_tokens_are_live


def remove_manifest_bound_hook_events(
    hooks: dict[str, object],
    bindings: Sequence[Mapping[str, object]],
) -> tuple[dict[str, object], bool]:
    """Remove only handlers whose exact identity is authenticated by a manifest."""

    updated_hooks = deepcopy(hooks)
    changed = False
    for binding in bindings:
        event_name = binding.get("event")
        expected_group = binding.get("group")
        expected_handler = binding.get("handler")
        if (
            not isinstance(event_name, str)
            or event_name not in MANAGED_CODEX_HOOK_EVENTS
            or not isinstance(expected_group, dict)
            or not isinstance(expected_handler, dict)
        ):
            continue
        groups = updated_hooks.get(event_name)
        if not isinstance(groups, list):
            continue
        remaining_groups: list[object] = []
        removed_for_binding = False
        for group in groups:
            if removed_for_binding or not isinstance(group, dict):
                remaining_groups.append(group)
                continue
            if group == expected_group:
                removed_for_binding = True
                changed = True
                continue
            if group.get("matcher") != expected_group.get("matcher"):
                remaining_groups.append(group)
                continue
            handlers = group.get("hooks")
            if not isinstance(handlers, list) or expected_handler not in handlers:
                remaining_groups.append(group)
                continue
            remaining_handlers = list(handlers)
            remaining_handlers.remove(expected_handler)
            removed_for_binding = True
            changed = True
            if remaining_handlers:
                updated_group = dict(group)
                updated_group["hooks"] = remaining_handlers
                remaining_groups.append(updated_group)
        if remaining_groups:
            updated_hooks[event_name] = remaining_groups
        else:
            updated_hooks.pop(event_name, None)
    return updated_hooks, changed


def exact_legacy_hook_bindings(
    hooks: Mapping[str, object],
    *,
    expected_bindings: Sequence[Mapping[str, object]],
    current_argv: Sequence[str],
    legacy_argv: Sequence[str],
    legacy_status_messages: set[str],
    windows: bool | None = None,
) -> list[dict[str, object]]:
    """Select exact current-package entries for explicit pre-manifest adoption."""

    accepted_argvs = [list(current_argv), list(legacy_argv)]
    if hook_commands_use_windows_syntax(windows):
        # Earlier Windows installs passed the config as plain JSON.
        accepted_argvs.extend(plain_json_hook_argv(argv) for argv in tuple(accepted_argvs))

    expected_by_event = {
        event: binding for binding in expected_bindings if isinstance((event := binding.get("event")), str)
    }
    bindings: list[dict[str, object]] = []
    for event_name in MANAGED_CODEX_HOOK_EVENTS:
        groups = hooks.get(event_name)
        expected = expected_by_event.get(event_name)
        expected_group = expected.get("group") if isinstance(expected, Mapping) else None
        if not isinstance(groups, list) or not isinstance(expected_group, dict):
            continue
        for group in groups:
            if not isinstance(group, dict) or group.get("matcher") != expected_group.get("matcher"):
                continue
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                continue
            handler = next(
                (
                    item
                    for item in handlers
                    if isinstance(item, dict)
                    and split_hook_command(item.get("command"), windows=windows) in accepted_argvs
                    and item.get("statusMessage") in legacy_status_messages
                ),
                None,
            )
            if handler is not None:
                bindings.append({"event": event_name, "group": group, "handler": handler})
                break
    return bindings


def _has_codex_harness(blob: str, *, windows: bool | None = None) -> bool:
    return has_codex_harness_tokens(hook_command_tokens(blob, windows=windows))


def _skip_leading_flags(tokens: Sequence[str]) -> list[str]:
    rest = list(tokens)
    while rest and rest[0].startswith("-") and rest[0] != "-c":
        rest = rest[1:]
    return rest


_FROZEN_GUARD_CLI_NAMES = {
    "current-hol-guard",
    "current-hol-guard.cmd",
    "current-hol-guard.exe",
    "hol-guard",
    "hol-guard.exe",
}


_LIVE_OWNED_FALLBACK_REASONS = frozenset(
    {
        "codex_hook_interpreter_path_mismatch",
        "codex_hook_manifest_packaged_files_stale",
        "codex_hook_manifest_package_version_stale",
        "codex_hook_manifest_registration_stale",
        "codex_hook_manifest_schema_unsupported",
    }
)


def _is_live_guard_codex_hook_command(command: str, *, windows: bool | None = None) -> bool:
    tokens = hook_command_tokens(command, windows=windows)
    if not tokens:
        return False
    first_name = hook_token_name(tokens[0], windows=windows)
    first = first_name.lower()
    rest = tokens[1:]
    payload = _skip_leading_flags(rest)
    if first_name == "codex_daemon_hook_bridge.py":
        return True
    if "hol-guard-codex-hook" in first:
        return True
    if first.startswith("python"):
        if not payload:
            return False
        if payload[0] == "-c":
            script = " ".join(payload[1:])
            return "codex_plugin_scanner.cli" in script and "guard" in script.split() and "hook" in script.split()
        return hook_token_name(payload[0], windows=windows) == "codex_daemon_hook_bridge.py"
    if first in _FROZEN_GUARD_CLI_NAMES:
        if payload and hook_token_name(payload[0], windows=windows) == "codex_daemon_hook_bridge.py":
            return True
        if frozen_codex_bridge_tokens_are_live(rest):
            return True
        return "hook" in rest and _has_codex_harness(" ".join(rest), windows=windows)
    return False


def require_codex_hook_owner(command: str, *, ownership: str, windows: bool | None = None) -> None:
    """Reject competing Guard handlers without silently adopting or deleting them.

    Launcher syntax is conflict evidence, never proof of a live managed bridge.
    """
    tokens = hook_command_tokens(command, windows=windows)
    python_launcher = bool(tokens and hook_token_name(tokens[0], windows=windows).lower().startswith("python"))
    guard_hook = (
        python_codex_hook_command(tokens, windows=windows)
        if python_launcher
        else _is_live_guard_codex_hook_command(command, windows=windows)
    )
    if ownership == "unmanaged" and guard_hook:
        raise RuntimeError(
            "codex_hook_owner_conflict: An existing Codex Guard handler has no verified ownership binding. "
            "Resolve its installation owner before retrying install; existing hooks have been preserved."
        )


_HEALTH_INTERCEPT_EVENTS = ("PreToolUse", "PermissionRequest")


def _hook_entry_is_active(entry: Mapping[str, object]) -> bool:
    return entry.get("enabled") is not False and entry.get("disabled") is not True


def _matcher_covers_shell(matcher: object) -> bool:
    if matcher is None:
        return True
    if not isinstance(matcher, str):
        return False
    text = matcher.strip()
    return text in {"", "*"} or "Bash" in text


def _group_has_active_guard_handler(
    group: Mapping[str, object],
    *,
    windows: bool | None = None,
    require_launchable: bool = False,
) -> bool:
    if not _hook_entry_is_active(group):
        return False

    def _routes_guard(command: object) -> bool:
        return (
            isinstance(command, str)
            and _is_live_guard_codex_hook_command(command, windows=windows)
            and (not require_launchable or hook_command_launchable(command, windows=windows))
        )

    handlers = group.get("hooks")
    if isinstance(handlers, list):
        return any(
            isinstance(handler, dict) and _hook_entry_is_active(handler) and _routes_guard(handler.get("command"))
            for handler in handlers
        )
    return _routes_guard(group.get("command"))


def _group_has_active_guard_shell_handler(group: Mapping[str, object], *, windows: bool | None = None) -> bool:
    # Health needs a handler Codex can actually start. A Windows entry that
    # still uses POSIX quoting never launches, and Codex then fails open.
    return _group_has_active_guard_handler(group, windows=windows, require_launchable=True) and _matcher_covers_shell(
        group.get("matcher")
    )


def live_owned_codex_event_matches(hooks: object, *, windows: bool | None = None) -> dict[str, bool]:
    """Return which managed Codex events still route a live Guard handler.

    Authenticated interpreter identity stays a repair contract. Doctor and
    repair copy must not say those events are missing while Guard still owns them.
    """

    matches = {event_name: False for event_name in MANAGED_CODEX_HOOK_EVENTS}
    if not isinstance(hooks, dict):
        return matches
    for event_name in MANAGED_CODEX_HOOK_EVENTS:
        groups = hooks.get(event_name)
        if not isinstance(groups, list):
            continue
        matches[event_name] = any(
            isinstance(group, dict) and _group_has_active_guard_handler(group, windows=windows) for group in groups
        )
    return matches


def live_guard_codex_hooks_intercept(hooks: object, *, windows: bool | None = None) -> bool:
    """Return whether live Codex config still routes Guard intercept hooks.

    Authenticated manifest mismatches stay repair work. They must not fail
    machine-wide protection health while Guard still intercepts PreToolUse and
    PermissionRequest.
    """

    if not isinstance(hooks, dict):
        return False
    for event_name in _HEALTH_INTERCEPT_EVENTS:
        groups = hooks.get(event_name)
        if not isinstance(groups, list) or not any(
            isinstance(group, dict) and _group_has_active_guard_shell_handler(group, windows=windows)
            for group in groups
        ):
            return False
    return True


def install_managed_codex_hook_groups(
    hooks: dict[str, object],
    managed_groups: Mapping[str, dict[str, object]],
    *,
    current_guard_home: Path,
) -> None:
    """Append after authenticated and explicitly adopted bindings are removed.

    Remaining Guard handlers have no proven owner; matching command syntax
    alone cannot authorize their replacement or duplication.
    """
    for event_name in managed_groups:
        existing = hooks.get(event_name)
        for group in existing if isinstance(existing, list) else []:
            if not isinstance(group, Mapping) or not _hook_entry_is_active(group):
                continue
            handlers = group.get("hooks")
            for handler in handlers if isinstance(handlers, list) else [group]:
                if (
                    isinstance(handler, Mapping)
                    and _hook_entry_is_active(handler)
                    and isinstance((command := handler.get("command")), str)
                ):
                    require_codex_hook_owner(command, ownership="unmanaged")
    for event_name, managed_group in managed_groups.items():
        existing = hooks.get(event_name)
        hooks[event_name] = [
            *deepcopy(existing if isinstance(existing, list) else []),
            managed_group,
        ]


def overlay_live_owned_event_matches(integrity: Mapping[str, object], hooks: object) -> dict[str, bool]:
    """Keep stale-CLI ownership, but never treat missing or tampered manifests as installed."""

    event_matches_value = integrity.get("event_matches")
    event_matches = event_matches_value if isinstance(event_matches_value, dict) else {}
    matches = {event_name: event_matches.get(event_name) is True for event_name in MANAGED_CODEX_HOOK_EVENTS}
    if integrity.get("integrity_status") == "valid":
        return matches
    if integrity.get("integrity_reason") not in _LIVE_OWNED_FALLBACK_REASONS:
        return matches
    live_matches = live_owned_codex_event_matches(hooks)
    return {
        event_name: matches[event_name] or live_matches.get(event_name) is True
        for event_name in MANAGED_CODEX_HOOK_EVENTS
    }


def codex_hook_doctor_warnings(hook_state: Mapping[str, object]) -> list[str]:
    """Return doctor copy for Codex native-hook state."""

    warnings: list[str] = []
    if not bool(hook_state.get("config_present")):
        return warnings
    if not bool(hook_state.get("codex_hooks_enabled")):
        warnings.append(
            "Codex config was found, but native hooks are disabled. Run `hol-guard install codex` or "
            "`hol-guard update` to repair protection."
        )
    if not bool(hook_state.get("managed_hook_installed")):
        warnings.append(
            "Codex config was found, but Guard's managed Codex hooks are missing. Run "
            "`hol-guard install codex` or `hol-guard update` to repair protection."
        )
        return warnings
    if hook_state.get("integrity_status") != "valid":
        warnings.append(
            "Codex hooks are installed but do not match this Guard CLI. Run "
            "`hol-guard install codex` or `hol-guard update` to rebind them."
        )
    return warnings


_FALSE_UNINSTALLED_MARKER = "guard is not installed for this harness"


def finalize_codex_doctor_warnings(
    warnings: Sequence[str],
    hook_state: Mapping[str, object],
) -> list[str]:
    """Keep Codex hook warnings and drop the false uninstalled copy when hooks exist."""

    merged = [str(item) for item in warnings]
    merged.extend(codex_hook_doctor_warnings(hook_state))
    if not bool(hook_state.get("managed_hook_installed")):
        return merged
    return [warning for warning in merged if _FALSE_UNINSTALLED_MARKER not in warning.lower()]


def finalize_codex_doctor_setup_status(
    current_status: object,
    hook_state: Mapping[str, object],
    warnings: Sequence[str],
) -> str:
    """Project Codex setup from live hook proof, including partial base status."""

    text = " ".join(warnings).lower()
    setup_failure = "command is not available" in text or "native hooks are disabled" in text
    if bool(hook_state.get("managed_hook_installed")):
        if bool(hook_state.get("protection_active")) and not setup_failure:
            return "active"
        return "broken"
    status = current_status if isinstance(current_status, str) and current_status else "partial"
    return "broken" if status == "active" else status


__all__ = [
    "codex_hook_doctor_warnings",
    "exact_legacy_hook_bindings",
    "finalize_codex_doctor_setup_status",
    "finalize_codex_doctor_warnings",
    "install_managed_codex_hook_groups",
    "is_foreign_guard_codex_hook_group",
    "live_guard_codex_hooks_intercept",
    "live_owned_codex_event_matches",
    "overlay_live_owned_event_matches",
    "prune_foreign_guard_codex_hook_groups",
    "remove_manifest_bound_hook_events",
    "require_codex_hook_owner",
]
