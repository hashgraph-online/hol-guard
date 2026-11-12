"""Cursor managed-hook configuration helpers.

Which hook entries and commands Guard owns, and the merge that installs Guard's
entries, are decided by the native ``cursor_hook_config`` runner-authority
kind. Python keeps file I/O, interpreter probing, command rendering, the
live-script path checks and the preToolUse matcher regex.
"""

from __future__ import annotations

import functools
import json
import os
import stat
import subprocess
import sys
from collections.abc import Sequence
from hashlib import sha256
from pathlib import Path
from typing import cast

from .. import codex_hook_command_line
from ..codex_hook_command_line import render_hook_command
from ..models import GuardArtifact
from ._modules.cursor.cursor_hook_events import (
    CURSOR_FILE_MUTATION_TOOL_MATCHER,
    CURSOR_SHELL_ROUTE_TOOL_MATCHER,
    cursor_entry_guards_file_mutations,
)
from ._modules.cursor.cursor_hook_guard_cli import resolve_frozen_cursor_hook_launcher
from ._modules.cursor.cursor_hook_native import (
    NATIVE_CURSOR_HOOK_COMMAND,
    CursorNativeBridgeUnavailableError,
    native_cursor_hook_bridge,
    python_client_pinned,
)
from .base import HarnessContext

HOOK_SCRIPT_NAME = "hol-guard-cursor-hook.py"
FROZEN_CURSOR_HOOK_COMMAND = "__guard-cursor-hook"
_BLOCKING_MANAGED_HOOK_EVENTS = (
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
    "preToolUse",
)
_OBSERVER_MANAGED_HOOK_EVENTS = ("afterShellExecution", "afterMCPExecution")
_MANAGED_HOOK_EVENTS = _BLOCKING_MANAGED_HOOK_EVENTS + _OBSERVER_MANAGED_HOOK_EVENTS
_MANAGED_HOOK_TIMEOUT_SECONDS = 45
_ISOLATED_PYTHON_PROBE = (
    "import hmac, json, sys, urllib.request; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)"
)
_ISOLATED_PYTHON_PROBE_TIMEOUT_SECONDS = 1.5


def _frozen_cursor_hook_launcher() -> str:
    return resolve_frozen_cursor_hook_launcher()


def _isolated_python_candidates() -> tuple[str, ...]:
    candidates = ["/usr/bin/python3"] if sys.platform == "darwin" or sys.platform.startswith("linux") else []
    return tuple(candidates)


def _isolated_python_is_usable(path: Path) -> bool:
    """Return whether *path* can run the stdlib Cursor hook client in isolation."""

    try:
        metadata = path.stat()
    except OSError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        return False
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o022:
        return False
    probe_env = {"PATH": "/usr/bin:/bin"}
    system_root = os.environ.get("SYSTEMROOT")
    if isinstance(system_root, str) and system_root:
        probe_env["SYSTEMROOT"] = system_root
    try:
        completed = subprocess.run(
            [str(path), "-I", "-c", _ISOLATED_PYTHON_PROBE],
            check=False,
            capture_output=True,
            timeout=_ISOLATED_PYTHON_PROBE_TIMEOUT_SECONDS,
            env=probe_env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


@functools.lru_cache(maxsize=1)
def _discover_isolated_cursor_hook_python() -> str | None:
    for candidate in _isolated_python_candidates():
        path = Path(candidate)
        if _isolated_python_is_usable(path):
            return str(path)
    return None


def isolated_cursor_hook_python() -> str | None:
    """Return a probed system interpreter for the stdlib Cursor hook client."""

    return _discover_isolated_cursor_hook_python()


def _managed_hook_command(
    *,
    python_executable: Path | None,
    script_path: Path,
    event_name: str,
    guard_home: Path | None = None,
) -> str:
    script = str(script_path.resolve())
    event_args = ["--cursor-hook-event", event_name]
    interpreter = str(python_executable) if python_executable is not None else isolated_cursor_hook_python()
    native_bridge = native_cursor_hook_bridge(guard_home)
    if native_bridge is None and not python_client_pinned():
        # The client this command would launch denies every gated hook, so the
        # frozen launcher must not render a command without the runtime either.
        raise CursorNativeBridgeUnavailableError("guard_cursor_native_bridge_unavailable")
    prefix = [] if native_bridge is None else [str(native_bridge), NATIVE_CURSOR_HOOK_COMMAND]
    if not interpreter and bool(getattr(sys, "frozen", False)):
        launcher = [_frozen_cursor_hook_launcher(), FROZEN_CURSOR_HOOK_COMMAND, script, *event_args]
        return render_hook_command([*prefix, *launcher])
    return render_hook_command([*prefix, interpreter or sys.executable, "-I", script, *event_args])


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
    entry: dict[str, object] = {
        "command": _managed_hook_command(
            python_executable=python_executable,
            script_path=script_path,
            event_name=event_name,
            guard_home=context.guard_home,
        ),
        "timeout": _MANAGED_HOOK_TIMEOUT_SECONDS,
        "failClosed": event_name in _BLOCKING_MANAGED_HOOK_EVENTS,
    }
    if event_name == "preToolUse":
        entry["matcher"] = (
            CURSOR_FILE_MUTATION_TOOL_MATCHER if sys.platform == "win32" else CURSOR_SHELL_ROUTE_TOOL_MATCHER
        )
    return entry


def _malformed() -> RuntimeError:
    return RuntimeError("Cursor hook config answer is malformed")


def _ask_once(request: dict[str, object]) -> tuple[dict[str, object], dict[str, str]]:
    # Imported here so the hook bridges stay off the native runtime at import time.
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer: dict[str, object] = native_runner_authority("cursor_hook_config", request)
    except NativeRunnerAuthorityError as error:
        # Best-effort repair and rebind callers handle RuntimeError, not ValueError.
        raise RuntimeError(f"Cursor hook config request failed: {error}") from error
    short_tokens = answer.get("short_tokens")
    if not isinstance(short_tokens, list) or not all(isinstance(token, str) for token in short_tokens):
        raise _malformed()
    known = cast(dict[str, str], request["long_paths"])
    resolved = {token: codex_hook_command_line._expand_short_token(token) for token in short_tokens}
    return answer, {token: path for token, path in resolved.items() if path != token and token not in known}


def _ask(op: str, **fields: object) -> dict[str, object]:
    """Ask the native kind, sending the long path of each 8.3 name it reports once."""

    windows = codex_hook_command_line.hook_commands_use_windows_syntax()
    request: dict[str, object] = {"op": op, "windows": windows, "long_paths": {}, **fields}
    answer, resolved = _ask_once(request)
    if resolved:
        answer, _ = _ask_once({**request, "long_paths": resolved})
    return answer


def _flag(answer: dict[str, object], key: str) -> bool:
    value = answer.get(key)
    if not isinstance(value, bool):
        raise _malformed()
    return value


def _index(value: object, size: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < size:
        raise _malformed()
    return value


def _managed_hooks_payload(
    payload: dict[str, object],
    managed_entries: dict[str, dict[str, object]],
    *,
    script_path: Path,
) -> dict[str, object]:
    """Return the normalized hooks config with Guard's entries merged into each managed event.

    Guard entries under events Cursor rejects, such as the retired beforeWriteFile,
    are dropped. Another tool's entry under such an event still makes Cursor ignore
    every hook, so install stops with the event names instead of reporting protection.
    """

    nested = payload.get("hooks")
    source = nested if isinstance(nested, dict) else payload
    answer = _ask(
        "install",
        payload=payload,
        top_keys=list(payload),
        hooks_keys=list(nested) if isinstance(nested, dict) else None,
        managed=[[event, str(entry.get("command", ""))] for event, entry in managed_entries.items()],
        script=str(script_path.resolve()),
    )
    error = answer.get("error")
    if isinstance(error, str):
        raise RuntimeError(error)
    version, specs = answer.get("version"), answer.get("hooks")
    if not isinstance(version, int) or not isinstance(specs, list):
        raise _malformed()
    hooks: dict[str, object] = {}
    for spec in specs:
        if not isinstance(spec, list) or len(spec) != 3:
            raise _malformed()
        event, kept, guard = spec
        if not isinstance(event, str) or event in hooks or not isinstance(guard, bool):
            raise _malformed()
        current = source.get(event)
        if kept is None:
            if guard or event not in source or isinstance(current, list):
                raise _malformed()
            hooks[event] = current
            continue
        entries = current if isinstance(current, list) else []
        if not isinstance(kept, list) or (guard and event not in managed_entries):
            raise _malformed()
        merged = [entries[_index(index, len(entries))] for index in kept]
        hooks[event] = [*merged, managed_entries[event]] if guard else merged
    return {"version": version, "hooks": hooks}


def _managed_entry_flags(entries: list[object], command: str) -> list[bool]:
    flags = _ask("entries", entries=entries, command=command).get("managed")
    if not isinstance(flags, list) or len(flags) != len(entries) or not all(isinstance(flag, bool) for flag in flags):
        raise _malformed()
    return cast(list[bool], flags)


def _strip_managed_hook_entries(entries: object, *, script_path: Path) -> list[object]:
    if not isinstance(entries, list):
        return []
    flags = _managed_entry_flags(entries, str(script_path.resolve()))
    return [entry for entry, managed in zip(entries, flags, strict=True) if not managed]


def _command_facts(command: str) -> tuple[bool, bool, str | None]:
    answer = _ask("command", command=command)
    script = answer.get("script")
    if script is not None and not isinstance(script, str):
        raise _malformed()
    return _flag(answer, "managed"), _flag(answer, "structured"), script


def _is_managed_hook_command(command: object) -> bool:
    return isinstance(command, str) and _command_facts(command)[0]


def _is_managed_hook_script(source: str) -> bool:
    """Return whether *source* was written by Guard's Cursor installer.

    Installed scripts use a Cursor-specific module docstring and bake
    ``GUARD_CLI``. They do not embed ``HOOK_SCRIPT_NAME``, so requiring that
    filename would treat every live Guard hook as unmanaged and skip
    prune-safe rebind. A mention of ``Managed by HOL Guard`` alone is not
    ownership.
    """

    return _flag(_ask("script", source=source), "managed")


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


def _accepted_live_cursor_hook_script(path: Path) -> Path | None:
    if not _is_managed_cursor_hook_script(path) or _cursor_hook_path_contains_symlink(path):
        return None
    return path


def _live_script_exists(script: object) -> bool:
    if not isinstance(script, str):
        raise _malformed()
    accepted = _accepted_live_cursor_hook_script(Path(script))
    return accepted is not None and accepted.is_file()


def _live_cursor_hook_script_path(command: str) -> Path | None:
    script = _command_facts(command)[2]
    return None if script is None else _accepted_live_cursor_hook_script(Path(script))


def _hook_pairs(hooks: dict[object, object]) -> list[list[object]]:
    return [[str(name), entries] for name, entries in hooks.items()]


def _intercepts(event_name: str, entries: list[object], candidate: object) -> bool:
    if not isinstance(candidate, list) or len(candidate) != 2:
        raise _malformed()
    entry = entries[_index(candidate[0], len(entries))]
    if not isinstance(entry, dict) or not _live_script_exists(candidate[1]):
        return False
    return event_name != "preToolUse" or cursor_entry_guards_file_mutations(entry)


def live_guard_cursor_hooks_intercept(hooks: object) -> bool:
    """Return whether live Cursor config still routes Guard blocking hooks.

    Exact attested CLI/script identity stays repair work. Extra third-party
    hook entries must not fail machine-wide protection health while Guard still
    intercepts shell, MCP, file-read, and file-write events. Cursor ignores
    the whole file when it names an unknown event, and a preToolUse entry only
    guards writes while it fails closed and matches every file mutation tool.
    """

    if not isinstance(hooks, dict):
        return False
    events = _ask("intercept", hooks=_hook_pairs(hooks)).get("events")
    if events is None:
        return False
    if not isinstance(events, list) or len(events) != len(_BLOCKING_MANAGED_HOOK_EVENTS):
        raise _malformed()
    for event_name, routed in zip(_BLOCKING_MANAGED_HOOK_EVENTS, events, strict=True):
        entries = hooks.get(event_name)
        if not isinstance(routed, list) or len(routed) != 2 or routed[0] != event_name:
            raise _malformed()
        if not isinstance(entries, list) or not isinstance(routed[1], list):
            raise _malformed()
        if not any(_intercepts(event_name, entries, candidate) for candidate in routed[1]):
            return False
    return True


def _is_structured_managed_cursor_hook_command(command: str) -> bool:
    return _command_facts(command)[1]


def _live_managed_commands(hooks: object) -> list[tuple[str, bool]]:
    if not isinstance(hooks, dict):
        return []
    found = _ask("commands", hooks=_hook_pairs(hooks)).get("commands")
    if not isinstance(found, list):
        raise _malformed()
    commands: list[tuple[str, bool]] = []
    for item in found:
        if not isinstance(item, dict) or item.keys() != {"command", "script", "frozen"}:
            raise _malformed()
        command, frozen = item["command"], item["frozen"]
        if not isinstance(command, str) or not isinstance(frozen, bool):
            raise _malformed()
        if _live_script_exists(item["script"]):
            commands.append((command, frozen))
    return commands


def live_cursor_hooks_use_frozen_control_plane(hooks: object) -> bool:
    """Return whether live Cursor config still boots the frozen control plane."""

    return any(frozen for _command, frozen in _live_managed_commands(hooks))


def managed_cursor_hook_commands(hooks: object) -> tuple[str, ...]:
    """Return structured Guard-owned Cursor hook commands from a live hooks payload."""

    return tuple(command for command, _frozen in _live_managed_commands(hooks))


def detect_managed_cursor_hook_artifact(hooks_path: Path, payload: object) -> GuardArtifact | None:
    """Return a Guard hook artifact when Cursor still routes a structured Guard command."""

    if not isinstance(payload, dict):
        return None
    nested = payload.get("hooks")
    commands = managed_cursor_hook_commands(nested if isinstance(nested, dict) else payload)
    if not commands:
        return None
    return GuardArtifact(
        artifact_id="cursor:global:managed-hooks",
        name="HOL Guard Cursor hooks",
        harness="cursor",
        artifact_type="guard_hook",
        source_scope="global",
        config_path=str(hooks_path),
        command=commands[0],
    )


def _make_executable(path: Path) -> None:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise OSError("refusing to change permissions on a non-regular Cursor hook")
    if os.name == "nt":
        return
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise OSError("Cursor hook changed before its permission update")
        # Cursor launches this user-owned hook through its configured interpreter;
        # only the owner execute bit is needed, and the writer keeps its content owner-only.
        os.fchmod(descriptor, opened.st_mode | stat.S_IXUSR)
    finally:
        os.close(descriptor)
