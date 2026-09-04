"""Cursor managed-hook configuration helpers."""

from __future__ import annotations

import json
import shlex
import stat
import sys
from collections.abc import Sequence
from hashlib import sha256
from pathlib import Path

from .base import HarnessContext
from .cursor_hook_guard_cli import resolve_frozen_cursor_hook_launcher
from .hook_payloads import inline_hooks_payload
from .state_files import load_backup_payload

HOOK_SCRIPT_NAME = "hol-guard-cursor-hook.py"
FROZEN_CURSOR_HOOK_COMMAND = "__guard-cursor-hook"
_BLOCKING_MANAGED_HOOK_EVENTS = (
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
    "beforeWriteFile",
)
_OBSERVER_MANAGED_HOOK_EVENTS = ("afterShellExecution", "afterMCPExecution")
_MANAGED_HOOK_EVENTS = _BLOCKING_MANAGED_HOOK_EVENTS + _OBSERVER_MANAGED_HOOK_EVENTS
_MANAGED_HOOK_TIMEOUT_SECONDS = 45


def _frozen_cursor_hook_launcher() -> str:
    return resolve_frozen_cursor_hook_launcher()


def _managed_hook_command(
    *,
    python_executable: Path | None,
    script_path: Path,
    event_name: str,
) -> str:
    script = str(script_path.resolve())
    event_args = ["--cursor-hook-event", event_name]
    if python_executable is not None:
        return shlex.join([str(python_executable), script, *event_args])
    if bool(getattr(sys, "frozen", False)):
        return shlex.join([_frozen_cursor_hook_launcher(), FROZEN_CURSOR_HOOK_COMMAND, script, *event_args])
    return shlex.join([sys.executable, script, *event_args])


def _is_managed_cursor_hook_script(path: Path) -> bool:
    parts = [part.lower() for part in path.parts]
    if not parts or parts[-1] != HOOK_SCRIPT_NAME.lower() or ".." in parts:
        return False
    if len(parts) >= 3 and parts[-3:-1] == [".cursor", "hooks"]:
        return True
    return len(parts) >= 3 and parts[-3:-1] == ["managed", "cursor"]


def _cursor_hook_path_contains_symlink(path: Path) -> bool:
    parts = path.parts
    if not parts:
        return True
    current = Path(parts[0])
    try:
        if current.is_symlink():
            return True
    except OSError:
        return True
    for part in parts[1:]:
        current = current / part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False


def run_frozen_cursor_hook(argv: Sequence[str]) -> int:
    """Execute the installed Cursor hook script from a frozen Guard binary."""

    if not argv:
        return 2
    script = Path(argv[0])
    if not _is_managed_cursor_hook_script(script) or not script.is_file() or _cursor_hook_path_contains_symlink(script):
        return 3
    import runpy

    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as error:
        code = error.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        return 1
    return 0


def _managed_hook_entry(
    context: HarnessContext,
    *,
    script_path: Path,
    event_name: str,
    python_executable: Path | None = None,
) -> dict[str, object]:
    del context
    entry: dict[str, object] = {
        "command": _managed_hook_command(
            python_executable=python_executable,
            script_path=script_path,
            event_name=event_name,
        ),
        "timeout": _MANAGED_HOOK_TIMEOUT_SECONDS,
        "failClosed": event_name in _BLOCKING_MANAGED_HOOK_EVENTS,
    }
    return entry


def _strip_managed_hook_entries(entries: object, *, script_path: Path) -> list[object]:
    if not isinstance(entries, list):
        return []
    command = str(script_path.resolve())
    return [entry for entry in entries if not _is_managed_hook_entry(entry, command=command)]


def _merge_hook_entries(entries: object, hook_entry: dict[str, object], *, event_name: str) -> list[object]:
    del event_name
    normalized = list(entries) if isinstance(entries, list) else []
    command = str(hook_entry.get("command", ""))
    preserved = [entry for entry in normalized if not _is_managed_hook_entry(entry, command=command)]
    return [*preserved, hook_entry]


def _is_managed_hook_entry(entry: object, *, command: str) -> bool:
    if not isinstance(entry, dict):
        return False
    entry_command = entry.get("command")
    if isinstance(entry_command, str) and entry_command == command:
        return True
    return _is_managed_hook_command(entry_command)


def _is_managed_hook_command(command: object) -> bool:
    if not isinstance(command, str):
        return False
    lowered = command.lower()
    if "hol-guard-cursor-hook" in lowered:
        return True
    if FROZEN_CURSOR_HOOK_COMMAND in lowered:
        return True
    if HOOK_SCRIPT_NAME.lower() in lowered:
        return True
    if "hol_guard_hook_argv" not in lowered.replace("-", "_"):
        return False
    if "--harness" not in lowered or "cursor" not in lowered:
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    if tokens and Path(tokens[0]).name == HOOK_SCRIPT_NAME:
        return True
    return Path(tokens[0]).name.lower().startswith("python") if tokens else False


_MANAGED_CURSOR_HOOK_DOCSTRING = (
    '"""Managed by HOL Guard. Re-run `hol-guard install cursor` after moving Guard home."""'
)


def _is_managed_hook_script(source: str) -> bool:
    """Return whether *source* was written by Guard's Cursor installer.

    Installed scripts use a Cursor-specific module docstring and bake
    ``GUARD_CLI``. They do not embed ``HOOK_SCRIPT_NAME``, so requiring that
    filename would treat every live Guard hook as unmanaged and skip
    prune-safe rebind. A mention of ``Managed by HOL Guard`` alone is not
    ownership.
    """

    return (
        _MANAGED_CURSOR_HOOK_DOCSTRING in source
        and "\nGUARD_CLI =" in source
        and "\nGUARD_RECOVERY_COMMAND =" in source
    )


def _managed_hooks_payload(payload: dict[str, object]) -> dict[str, object]:
    normalized: dict[str, object] = {"version": 1, "hooks": {}}
    version = payload.get("version")
    if isinstance(version, int):
        normalized["version"] = version
    hooks = payload.get("hooks")
    if isinstance(hooks, dict):
        normalized["hooks"] = {
            str(name): list(entries) if isinstance(entries, list) else entries for name, entries in hooks.items()
        }
        return normalized
    normalized["hooks"] = {
        str(name): list(entries) for name, entries in payload.items() if name != "version" and isinstance(entries, list)
    }
    return normalized


_inline_hooks = inline_hooks_payload


def _json_object(path: Path, *, recover_missing: bool) -> dict[str, object]:
    if not path.is_file():
        if recover_missing:
            return {}
        raise RuntimeError(f"Guard refused to overwrite missing Cursor hooks config at {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Guard refused to overwrite unreadable Cursor hooks config at {path}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Guard refused to overwrite non-object Cursor hooks config at {path}")
    return payload


def _hooks_backup_path(target_path: Path, context: HarnessContext) -> Path:
    digest = sha256(str(target_path.resolve()).encode("utf-8")).hexdigest()[:12]
    return context.guard_home / "managed" / "cursor" / f"hooks-{digest}.backup.json"


def _hooks_state_path(target_path: Path, context: HarnessContext) -> Path:
    digest = sha256(str(target_path.resolve()).encode("utf-8")).hexdigest()[:12]
    return context.guard_home / "managed" / "cursor" / f"hooks-{digest}.state.json"


_backup_payload = load_backup_payload


def _skip_leading_flags(tokens: Sequence[str]) -> list[str]:
    rest = list(tokens)
    while rest and rest[0].startswith("-") and rest[0] != "-c":
        rest = rest[1:]
    return rest


def _accepted_live_cursor_hook_script(path: Path) -> Path | None:
    if not _is_managed_cursor_hook_script(path) or _cursor_hook_path_contains_symlink(path):
        return None
    return path


def _live_cursor_hook_script_path(command: str) -> Path | None:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    if not tokens:
        return None
    first = Path(tokens[0]).name
    if first == HOOK_SCRIPT_NAME:
        return _accepted_live_cursor_hook_script(Path(tokens[0]))
    if len(tokens) >= 3 and tokens[1] == FROZEN_CURSOR_HOOK_COMMAND:
        return _accepted_live_cursor_hook_script(Path(tokens[2]))
    if first.lower().startswith("python"):
        payload = _skip_leading_flags(tokens[1:])
        if not payload or payload[0] == "-c":
            return None
        return _accepted_live_cursor_hook_script(Path(payload[0]))
    return None


def live_guard_cursor_hooks_intercept(hooks: object) -> bool:
    """Return whether live Cursor config still routes Guard blocking hooks.

    Exact attested CLI/script identity stays repair work. Extra third-party
    hook entries must not fail machine-wide protection health while Guard still
    intercepts shell, MCP, file-read, and file-write events.
    """

    if not isinstance(hooks, dict):
        return False
    for event_name in _BLOCKING_MANAGED_HOOK_EVENTS:
        entries = hooks.get(event_name)
        if not isinstance(entries, list):
            return False
        matched = False
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            command = entry.get("command")
            if not isinstance(command, str) or not command.strip():
                continue
            script_path = _live_cursor_hook_script_path(command)
            if script_path is None or not script_path.is_file():
                continue
            matched = True
            break
        if not matched:
            return False
    return True


def _make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
