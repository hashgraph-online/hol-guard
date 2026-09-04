"""Exact ownership and legacy-adoption operations for Codex hook groups."""

from __future__ import annotations

import re
import shlex
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path

from .codex_hook_file_integrity import split_hook_command
from .codex_hook_manifest import MANAGED_CODEX_HOOK_EVENTS

_STATE_PATH_RE = re.compile(r'"state_path"\s*:\s*"([^"]+)"')
_GUARD_HOME_QUERY_RE = re.compile(r"guard-home=([^&\"'\s]+)")


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
) -> list[dict[str, object]]:
    """Select exact current-package entries for explicit pre-manifest adoption."""

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
                    and split_hook_command(item.get("command")) in (list(current_argv), list(legacy_argv))
                    and item.get("statusMessage") in legacy_status_messages
                ),
                None,
            )
            if handler is not None:
                bindings.append({"event": event_name, "group": group, "handler": handler})
                break
    return bindings


def _hook_group_command_blob(group: object) -> str:
    if not isinstance(group, Mapping):
        return ""
    parts: list[str] = []
    command = group.get("command")
    if isinstance(command, str):
        parts.append(command)
    hooks = group.get("hooks")
    if isinstance(hooks, list):
        for hook in hooks:
            if isinstance(hook, Mapping):
                hook_command = hook.get("command")
                if isinstance(hook_command, str):
                    parts.append(hook_command)
    return "\n".join(parts)


def _has_codex_harness(blob: str) -> bool:
    compact = blob.replace(" ", "")
    return (
        "--harness codex" in blob
        or "--harness=codex" in blob
        or '"--harness","codex"' in compact
        or "'--harness','codex'" in compact
    )


def _looks_like_guard_codex_hook(blob: str) -> bool:
    if "codex_daemon_hook_bridge.py" in blob:
        return True
    if not _has_codex_harness(blob):
        return False
    if "hol-guard hook" in blob:
        return True
    return "codex_plugin_scanner.cli" in blob and "guard hook" in blob


def _command_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


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


def _is_live_guard_codex_hook_command(command: str) -> bool:
    tokens = _command_tokens(command)
    if not tokens:
        return False
    first_path = Path(tokens[0])
    first = first_path.name.lower()
    rest = tokens[1:]
    payload = _skip_leading_flags(rest)
    if first_path.name == "codex_daemon_hook_bridge.py":
        return True
    if "hol-guard-codex-hook" in first:
        return True
    if first.startswith("python"):
        if not payload:
            return False
        if payload[0] == "-c":
            script = " ".join(payload[1:])
            return "codex_plugin_scanner.cli" in script and "guard" in script.split() and "hook" in script.split()
        return Path(payload[0]).name == "codex_daemon_hook_bridge.py"
    if first in _FROZEN_GUARD_CLI_NAMES:
        if payload and Path(payload[0]).name == "codex_daemon_hook_bridge.py":
            return True
        return "hook" in rest and _has_codex_harness(" ".join(rest))
    return False


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


def _group_has_active_guard_handler(group: Mapping[str, object]) -> bool:
    if not _hook_entry_is_active(group):
        return False
    handlers = group.get("hooks")
    if isinstance(handlers, list):
        return any(
            isinstance(handler, dict)
            and _hook_entry_is_active(handler)
            and isinstance(handler.get("command"), str)
            and _is_live_guard_codex_hook_command(str(handler.get("command")))
            for handler in handlers
        )
    command = group.get("command")
    return isinstance(command, str) and _is_live_guard_codex_hook_command(command)


def _group_has_active_guard_shell_handler(group: Mapping[str, object]) -> bool:
    return _group_has_active_guard_handler(group) and _matcher_covers_shell(group.get("matcher"))


def live_owned_codex_event_matches(hooks: object) -> dict[str, bool]:
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
            isinstance(group, dict) and _group_has_active_guard_handler(group) for group in groups
        )
    return matches


def live_guard_codex_hooks_intercept(hooks: object) -> bool:
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
            isinstance(group, dict) and _group_has_active_guard_shell_handler(group) for group in groups
        ):
            return False
    return True


def _normalize_guard_home_path(value: str) -> Path | None:
    stripped = value.strip().strip("'\"")
    if not stripped:
        return None
    return Path(stripped).expanduser()


def _extract_guard_home_flags(command: str) -> list[Path]:
    homes: list[Path] = []
    try:
        tokens = shlex.split(command, posix=True, comments=False)
    except ValueError:
        tokens = command.split()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--guard-home" and index + 1 < len(tokens):
            parsed = _normalize_guard_home_path(tokens[index + 1])
            if parsed is not None:
                homes.append(parsed)
            index += 2
            continue
        if token.startswith("--guard-home="):
            parsed = _normalize_guard_home_path(token.split("=", 1)[1])
            if parsed is not None:
                homes.append(parsed)
        index += 1
    return homes


def _extract_guard_homes_from_hook_blob(blob: str) -> tuple[Path, ...]:
    decoded = blob.replace('\\"', '"')
    homes: list[Path] = []
    for command in decoded.split("\n"):
        homes.extend(_extract_guard_home_flags(command))
    for match in _STATE_PATH_RE.finditer(decoded):
        state_path = Path(match.group(1))
        if state_path.name == "daemon-state.json":
            homes.append(state_path.parent)
    for match in _GUARD_HOME_QUERY_RE.finditer(decoded):
        token = match.group(1)
        if token.startswith("/") or token.startswith("~"):
            parsed = _normalize_guard_home_path(token)
            if parsed is not None:
                homes.append(parsed)
    return tuple(homes)


def _resolved_guard_home(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


def is_foreign_guard_codex_hook_group(group: object, *, current_guard_home: Path) -> bool:
    """Return True when a Guard Codex hook is bound to a different Guard home."""

    blob = _hook_group_command_blob(group)
    if not _looks_like_guard_codex_hook(blob):
        return False
    extracted = _extract_guard_homes_from_hook_blob(blob)
    if not extracted:
        return False
    current = _resolved_guard_home(current_guard_home.expanduser())
    return all(_resolved_guard_home(home) != current for home in extracted)


def prune_foreign_guard_codex_hook_groups(
    groups: Sequence[object],
    *,
    current_guard_home: Path,
) -> list[object]:
    """Drop foreign Guard handlers while keeping current-home and non-Guard hooks."""

    pruned: list[object] = []
    for group in groups:
        if not isinstance(group, Mapping):
            pruned.append(group)
            continue
        handlers = group.get("hooks")
        if isinstance(handlers, list) and handlers:
            kept_handlers: list[object] = []
            for handler in handlers:
                probe = {"hooks": [handler]} if isinstance(handler, Mapping) else handler
                if is_foreign_guard_codex_hook_group(probe, current_guard_home=current_guard_home):
                    continue
                kept_handlers.append(handler)
            if not kept_handlers:
                continue
            updated = dict(group)
            updated["hooks"] = kept_handlers
            pruned.append(updated)
            continue
        if is_foreign_guard_codex_hook_group(group, current_guard_home=current_guard_home):
            continue
        pruned.append(group)
    return pruned


def install_managed_codex_hook_groups(
    hooks: dict[str, object],
    managed_groups: Mapping[str, dict[str, object]],
    *,
    current_guard_home: Path,
) -> None:
    for event_name, managed_group in managed_groups.items():
        existing = hooks.get(event_name)
        hooks[event_name] = [
            *prune_foreign_guard_codex_hook_groups(
                existing if isinstance(existing, list) else [],
                current_guard_home=current_guard_home,
            ),
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


__all__ = [
    "codex_hook_doctor_warnings",
    "exact_legacy_hook_bindings",
    "finalize_codex_doctor_warnings",
    "install_managed_codex_hook_groups",
    "is_foreign_guard_codex_hook_group",
    "live_guard_codex_hooks_intercept",
    "live_owned_codex_event_matches",
    "overlay_live_owned_event_matches",
    "prune_foreign_guard_codex_hook_groups",
    "remove_manifest_bound_hook_events",
]
