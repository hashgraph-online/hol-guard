"""Cursor IDE native hooks (.cursor/hooks.json) for HOL Guard."""

from __future__ import annotations

import json
import os
import stat
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING

from ..frozen_runtime_commands import frozen_daemon_recovery_command
from ._modules.cursor.cursor_hook_entries import _remove_managed_hook_entries, _render_without_managed_hook_entries
from ._modules.cursor.cursor_hook_native import CursorNativeBridgeUnavailableError, require_cursor_hook_bridge
from .adapter_safe_output import write_text_at_authorized_path
from .base import HarnessContext, PreparedHarnessInstall, _ensure_path_within_root
from .cursor_hook_config import (
    _MANAGED_HOOK_EVENTS,
    HOOK_SCRIPT_NAME,
    _hooks_backup_path,
    _hooks_state_path,
    _is_managed_hook_script,
    _json_object,
    _make_executable,
    _managed_entry_flags,
    _managed_hook_entry,
    _managed_hooks_payload,
    _strip_managed_hook_entries,
)
from .cursor_native_approval import cursor_hook_attestation_secret_path, ensure_cursor_hook_attestation_secret
from .cursor_path_cleanup import prune_empty_project_cursor_dir
from .guard_cli_attestation import resolve_attested_guard_cli
from .hook_python import HookPythonAttestation
from .state_files import plan_backup_restore, restore_from_backup

if TYPE_CHECKING:
    from collections.abc import Callable

    from ..runtime_transition import TransitionFile


def cursor_hooks_path(context: HarnessContext) -> Path:
    """Cursor hooks are always installed in the global Cursor config."""

    return context.home_dir / ".cursor" / "hooks.json"


def cursor_hook_script_path(context: HarnessContext) -> Path:
    return context.home_dir / ".cursor" / "hooks" / HOOK_SCRIPT_NAME


def _legacy_project_cursor_hooks_path(workspace_dir: Path) -> Path:
    return workspace_dir / ".cursor" / "hooks.json"


def _legacy_project_cursor_hook_script_path(workspace_dir: Path) -> Path:
    return workspace_dir / ".cursor" / "hooks" / HOOK_SCRIPT_NAME


def managed_hook_script_path(context: HarnessContext) -> Path:
    return context.guard_home / "managed" / "cursor" / HOOK_SCRIPT_NAME


def prepare_cursor_hooks(context: HarnessContext) -> PreparedHarnessInstall:
    """Render the complete native rebind with existing authority and captured inverses."""
    from .hook_python import disposable_guard_hook_probe

    with disposable_guard_hook_probe():
        return _prepare_cursor_hooks(context)


def _prepare_cursor_hooks(context: HarnessContext) -> PreparedHarnessInstall:
    from ..codex_hook_recovery import _snapshot
    from ..runtime_transition import RuntimeTransition, TransitionError, TransitionFile

    try:
        require_cursor_hook_bridge(context.guard_home)
    except CursorNativeBridgeUnavailableError as error:
        raise TransitionError("adapter_preparation_native_cursor_bridge_missing") from error
    secret_path = cursor_hook_attestation_secret_path(context.guard_home)
    secret = _snapshot(secret_path)
    if secret is None:
        raise TransitionError("adapter_preparation_authority_missing")
    if len(secret) != 32 or (os.name != "nt" and secret_path.stat().st_mode & 0o077):
        raise TransitionError("adapter_preparation_authority_invalid")
    files = [TransitionFile.identity_dependency(secret_path)]
    guard_cli = resolve_attested_guard_cli(context)
    hooks_path = cursor_hooks_path(context)
    script_path = cursor_hook_script_path(context)
    managed_path = managed_hook_script_path(context)
    backup_path, state_path = _hooks_backup_path(hooks_path, context), _hooks_state_path(hooks_path, context)
    for path in (hooks_path, script_path):
        _ensure_path_within_root(context.home_dir, path, label="Cursor hook")
    for path in (managed_path, backup_path, state_path):
        _ensure_path_within_root(context.guard_home, path, label="Cursor hook state")
    before = {path: _snapshot(path) for path in (hooks_path, script_path, managed_path, backup_path, state_path)}
    original = before[hooks_path]
    payload = json.loads(original) if original is not None else {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Guard refused to overwrite non-object Cursor hooks config at {hooks_path}")
    python_executable = guard_cli.python.executable if guard_cli.python is not None else None
    managed = {
        event: _managed_hook_entry(
            context, script_path=script_path, event_name=event, python_executable=python_executable
        )
        for event in _MANAGED_HOOK_EVENTS
    }
    payload = _managed_hooks_payload(payload, managed, script_path=script_path)
    source = cursor_hook_script_source(
        context, guard_cli=list(guard_cli.command), recovery_command=_cursor_recovery_command(context, guard_cli.python)
    )
    manifest: dict[str, object] = {
        "managed_hooks_path": str(hooks_path),
        "managed_hook_script_path": str(script_path),
        "managed_hook_events": list(_MANAGED_HOOK_EVENTS),
        "guard_cli_identity": guard_cli.manifest_payload(),
        "hook_script_sha256": sha256(source.encode("utf-8")).hexdigest(),
        "backup_path": str(backup_path),
        "state_path": str(state_path),
    }
    state = {key: value for key, value in manifest.items() if key not in {"managed_hook_events", "state_path"}}
    state["workspace_dir"] = str(context.workspace_dir.resolve()) if context.workspace_dir is not None else None
    after = {
        hooks_path: (json.dumps(payload, indent=2) + "\n").encode("utf-8"),
        script_path: source.encode("utf-8"),
        managed_path: source.encode("utf-8"),
        state_path: (json.dumps(state, indent=2) + "\n").encode("utf-8"),
        backup_path: before[backup_path]
        if before[backup_path] is not None
        else (
            json.dumps(
                {
                    "existed": original is not None,
                    "content": original.decode("utf-8") if original is not None else None,
                },
                indent=2,
            )
            + "\n"
        ).encode("utf-8"),
    }
    for path, data in after.items():
        mode = path.stat().st_mode & 0o777 if before[path] is not None else 0o600
        after_mode = mode if path == backup_path and before[path] is not None else 0o600
        if path in {script_path, managed_path} and os.name != "nt":
            after_mode |= stat.S_IXUSR
        files.append(
            TransitionFile(
                path.resolve(strict=False), before[path], data, before_mode=mode, after_mode=after_mode, no_follow=True
            )
        )
    files.extend(_prepare_legacy_project_cursor_cleanup(context))
    prepared = PreparedHarnessInstall(tuple(files), manifest)
    RuntimeTransition._compare({"files": [change.payload() for change in files]}, "before")
    return prepared


def _prepare_legacy_project_cursor_cleanup(context: HarnessContext) -> tuple[TransitionFile, ...]:
    from ..codex_hook_recovery import _snapshot
    from ..runtime_transition import TransitionFile

    if context.workspace_dir is None:
        return ()
    hooks_path = _legacy_project_cursor_hooks_path(context.workspace_dir)
    script_path = _legacy_project_cursor_hook_script_path(context.workspace_dir)
    if hooks_path.resolve() == cursor_hooks_path(context).resolve():
        return ()
    _ensure_path_within_root(context.workspace_dir, hooks_path, label="Cursor legacy hooks")
    _ensure_path_within_root(context.workspace_dir, script_path, label="Cursor legacy script")
    backup_path, state_path = _hooks_backup_path(hooks_path, context), _hooks_state_path(hooks_path, context)
    for path in (backup_path, state_path):
        _ensure_path_within_root(context.guard_home, path, label="Cursor legacy state")
    before = {path: _snapshot(path) for path in (hooks_path, script_path, backup_path, state_path)}
    script = before[script_path]
    managed_script = script is not None and _is_managed_hook_script(script.decode("utf-8"))
    hook_before, backup_before = before[hooks_path], before[backup_path]
    try:
        payload = json.loads(hook_before) if hook_before is not None else {}
    except json.JSONDecodeError:
        payload = {}
    cleaned, removed = _render_without_managed_hook_entries(payload, script_path=script_path)
    after = dict(before)
    if managed_script or removed:
        action, content, restored = plan_backup_restore(
            backup_before.decode("utf-8") if backup_before is not None else None,
            target_exists=hook_before is not None,
        )
        if action == "write" and content is not None:
            after[hooks_path] = content.encode("utf-8")
        elif action == "unlink":
            after[hooks_path] = None
        if restored:
            after[backup_path] = after[state_path] = None
        elif removed:
            after[hooks_path] = (json.dumps(cleaned, indent=2) + "\n").encode("utf-8") if cleaned is not None else None
            after[state_path] = None
        if managed_script:
            after[script_path] = None
    files = []
    for path, data in after.items():
        mode = path.stat().st_mode & 0o777 if before[path] is not None else 0o600
        files.append(
            TransitionFile(
                path.resolve(strict=False), before[path], data, before_mode=mode, after_mode=mode, no_follow=True
            )
        )
    return tuple(files)


def install_cursor_hooks(context: HarnessContext) -> dict[str, object]:
    """Install Guard-managed Cursor hooks and bridge script."""

    # A hook written without the runtime denies every shell, read and MCP action
    # Cursor gates, so there is no install to write when none can answer.
    require_cursor_hook_bridge(context.guard_home)
    guard_cli = resolve_attested_guard_cli(context)
    hooks_path = cursor_hooks_path(context)
    script_path = cursor_hook_script_path(context)
    managed_script_path = managed_hook_script_path(context)
    _ensure_path_within_root(context.home_dir, hooks_path, label="Cursor hooks")
    _ensure_path_within_root(context.home_dir, script_path, label="Cursor hook script")
    _ensure_path_within_root(context.guard_home, managed_script_path, label="Cursor managed hook script")
    managed_script_path.parent.mkdir(parents=True, exist_ok=True)
    script_source = cursor_hook_script_source(
        context,
        guard_cli=list(guard_cli.command),
        recovery_command=_cursor_recovery_command(context, guard_cli.python),
    )
    write_text_at_authorized_path(managed_script_path, script_source)
    _make_executable(managed_script_path)
    script_path.parent.mkdir(parents=True, exist_ok=True)
    write_text_at_authorized_path(script_path, script_source)
    _make_executable(script_path)
    ensure_cursor_hook_attestation_secret(context.guard_home)

    original_text = hooks_path.read_text(encoding="utf-8") if hooks_path.is_file() else None
    backup_path = _hooks_backup_path(hooks_path, context)
    _ensure_path_within_root(context.guard_home, backup_path, label="Cursor hook backup")
    if not backup_path.exists():
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        write_text_at_authorized_path(
            backup_path,
            json.dumps({"existed": original_text is not None, "content": original_text}, indent=2) + "\n",
        )
    state_path = _hooks_state_path(hooks_path, context)
    _ensure_path_within_root(context.guard_home, state_path, label="Cursor hook state")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    workspace_dir = str(context.workspace_dir.resolve()) if context.workspace_dir is not None else None
    write_text_at_authorized_path(
        state_path,
        json.dumps(
            {
                "managed_hooks_path": str(hooks_path),
                "managed_hook_script_path": str(script_path),
                "guard_cli_identity": guard_cli.manifest_payload(),
                "hook_script_sha256": sha256(script_source.encode("utf-8")).hexdigest(),
                "backup_path": str(backup_path),
                "workspace_dir": workspace_dir,
            },
            indent=2,
        )
        + "\n",
    )

    current = _json_object(hooks_path, recover_missing=True)
    python_executable = guard_cli.python.executable if guard_cli.python is not None else None
    managed = {
        event: _managed_hook_entry(
            context, script_path=script_path, event_name=event, python_executable=python_executable
        )
        for event in _MANAGED_HOOK_EVENTS
    }
    payload = _managed_hooks_payload(current, managed, script_path=script_path)
    hooks_path.parent.mkdir(parents=True, exist_ok=True)
    write_text_at_authorized_path(hooks_path, json.dumps(payload, indent=2) + "\n")
    _cleanup_legacy_project_cursor_hooks(context)
    hook_state = cursor_native_hook_state(context)
    if hook_state["protection_active"] is not True:
        reason = hook_state.get("reason")
        raise RuntimeError(f"guard_cursor_hook_install_verification_failed:{reason}")
    return {
        "managed_hooks_path": str(hooks_path),
        "managed_hook_script_path": str(script_path),
        "managed_hook_events": list(_MANAGED_HOOK_EVENTS),
        "guard_cli_identity": guard_cli.manifest_payload(),
        "hook_script_sha256": sha256(script_source.encode("utf-8")).hexdigest(),
        "backup_path": str(backup_path),
        "state_path": str(state_path),
    }


def uninstall_cursor_hooks(context: HarnessContext) -> dict[str, object]:
    """Remove Guard-managed Cursor hooks and restore prior hooks.json."""

    hooks_path = cursor_hooks_path(context)
    script_path = cursor_hook_script_path(context)
    _ensure_path_within_root(context.home_dir, hooks_path, label="Cursor hooks")
    _ensure_path_within_root(context.home_dir, script_path, label="Cursor hook script")
    return _uninstall_cursor_hooks_at_paths(
        hooks_path=hooks_path,
        script_path=script_path,
        authorized_root=context.home_dir,
        context=context,
        remove_managed_copy=True,
    )


def _uninstall_cursor_hooks_at_paths(
    *,
    hooks_path: Path,
    script_path: Path,
    authorized_root: Path,
    context: HarnessContext,
    remove_managed_copy: bool,
) -> dict[str, object]:
    _ensure_path_within_root(authorized_root, hooks_path, label="Cursor hooks")
    _ensure_path_within_root(authorized_root, script_path, label="Cursor hook script")
    backup_path = _hooks_backup_path(hooks_path, context)
    state_path = _hooks_state_path(hooks_path, context)
    _ensure_path_within_root(context.guard_home, backup_path, label="Cursor hook backup")
    _ensure_path_within_root(context.guard_home, state_path, label="Cursor hook state")
    restored = restore_from_backup(backup_path, hooks_path, write=write_text_at_authorized_path)
    if restored and backup_path.is_file():
        backup_path.unlink()
    if restored and state_path.is_file():
        state_path.unlink()
    if (
        not restored
        and hooks_path.is_file()
        and _remove_managed_hook_entries(hooks_path=hooks_path, script_path=script_path)
    ):
        restored = True
        if state_path.is_file():
            state_path.unlink()
    if script_path.is_file():
        try:
            script_source = script_path.read_text(encoding="utf-8")
        except OSError:
            script_source = ""
        if _is_managed_hook_script(script_source):
            script_path.unlink()
    if remove_managed_copy:
        managed_script_path = managed_hook_script_path(context)
        _ensure_path_within_root(context.guard_home, managed_script_path, label="Cursor managed hook script")
        if managed_script_path.is_file():
            managed_script_path.unlink()
    return {
        "managed_hooks_path": str(hooks_path),
        "restored": restored,
        "removed_hook_script": not script_path.is_file(),
    }


def _cleanup_legacy_project_cursor_hooks(context: HarnessContext) -> None:
    if context.workspace_dir is None:
        return
    hooks_path = _legacy_project_cursor_hooks_path(context.workspace_dir)
    script_path = _legacy_project_cursor_hook_script_path(context.workspace_dir)
    if hooks_path.resolve() == cursor_hooks_path(context).resolve():
        return
    if not hooks_path.is_file() and not script_path.is_file():
        return
    managed = False
    if script_path.is_file():
        try:
            managed = _is_managed_hook_script(script_path.read_text(encoding="utf-8"))
        except OSError:
            managed = False
    if hooks_path.is_file() and not managed:
        try:
            payload = json.loads(hooks_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        if isinstance(payload, dict):
            hooks = payload.get("hooks")
            if isinstance(hooks, dict):
                command = str(script_path.resolve())
                event_lists = [entries for entries in hooks.values() if isinstance(entries, list)]
                managed = any(any(_managed_entry_flags(entries, command)) for entries in event_lists)
    if not managed:
        return
    _uninstall_cursor_hooks_at_paths(
        hooks_path=hooks_path,
        script_path=script_path,
        authorized_root=context.workspace_dir,
        context=context,
        remove_managed_copy=False,
    )
    prune_empty_project_cursor_dir(context.workspace_dir)


def _resolve_guard_cli_command(context: HarnessContext) -> list[str]:
    """Return only the isolated CLI bound to the running Guard distribution."""

    return list(resolve_attested_guard_cli(context).command)


def _cursor_hook_script(request: dict[str, object], field: str) -> object:
    """Ask the native ``cursor_hook_script`` kind for one rendered value."""

    # Imported here so the hook bridges stay off the native runtime at import time.
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority("cursor_hook_script", request)
        value = answer.get(field) if isinstance(answer, dict) and set(answer) == {field} else None
        if not isinstance(value, str) and not (
            isinstance(value, list) and all(isinstance(item, str) for item in value)
        ):
            raise NativeRunnerAuthorityError("native_cursor_hook_script_invalid")
    except NativeRunnerAuthorityError as error:
        # Best-effort repair and rebind callers handle RuntimeError, not ValueError.
        raise RuntimeError(f"Cursor hook script request failed: {error}") from error
    return value


def _cursor_recovery_command(
    context: HarnessContext,
    attestation: HookPythonAttestation | None,
) -> list[str]:
    if attestation is None:
        return list(frozen_daemon_recovery_command(context.guard_home, context.home_dir))
    request: dict[str, object] = {
        "op": "recovery",
        "python": str(attestation.identity.target_path),
        "import_roots": [str(root) for root in attestation.import_roots],
        "guard_home": str(context.guard_home.resolve()),
        "home": str(context.home_dir.resolve()),
    }
    command = _cursor_hook_script(request, "command")
    if not isinstance(command, list):
        raise RuntimeError("Cursor hook script answer is malformed")
    return command


def cursor_hook_script_source(
    context: HarnessContext,
    *,
    guard_cli: list[str] | None = None,
    recovery_command: list[str] | None = None,
) -> str:
    if guard_cli is None:
        guard_cli = _resolve_guard_cli_command(context)
    if recovery_command is None:
        recovery_command = _cursor_recovery_command(context, resolve_attested_guard_cli(context).python)
    request: dict[str, object] = {
        "op": "render",
        "guard_home": str(context.guard_home),
        "guard_home_resolved": str(context.guard_home.resolve()),
        # The user's own home is never named, so the hook keeps following it.
        "home": None if context.home_dir.resolve() == Path.home().resolve() else str(context.home_dir),
        "guard_cli": list(guard_cli),
        "recovery_command": list(recovery_command),
    }
    source = _cursor_hook_script(request, "source")
    if not isinstance(source, str):
        raise RuntimeError("Cursor hook script answer is malformed")
    return source


_STATE_STATUSES = frozenset({"missing", "tampered", "stale"})


def _observe(errors: dict[str, Exception], label: str, read: Callable[[], object]) -> object:
    """Run a later read or render; keep its error under ``label`` and send ``false``."""

    try:
        return read()
    except Exception as error:
        errors[label] = error
        return False


_NOFOLLOW_NONBLOCK = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)


def _read_script(path: Path) -> object:
    try:
        mode = path.lstat().st_mode
        # Never read a link, pipe or device. A link to a file reads as tampered;
        # anything else could not be read as a script, so it is missing.
        if not stat.S_ISREG(mode):
            return {"regular": False, "text": ""} if stat.S_ISLNK(mode) and path.is_file() else None
        # The path can be swapped after lstat, so the descriptor is checked too.
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW_NONBLOCK)
        with os.fdopen(fd, encoding="utf-8") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return None
            return {"regular": True, "text": handle.read()}
    except OSError:
        return None


def _read_hooks(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def cursor_native_hook_state(context: HarnessContext) -> dict[str, object]:
    """Verify Cursor registration, scripts, and the current attested CLI identity."""

    try:
        require_cursor_hook_bridge(context.guard_home)
    except CursorNativeBridgeUnavailableError:
        # Checked before the attestation branch below: this is a RuntimeError too,
        # and a missing runtime is not an attestation failure.
        return {
            "protection_active": False,
            "integrity_status": "missing",
            "reason": "guard_cursor_native_bridge_unavailable",
        }
    try:
        guard_cli = resolve_attested_guard_cli(context)
        expected_source = cursor_hook_script_source(context, guard_cli=list(guard_cli.command))
    except RuntimeError:
        return {
            "protection_active": False,
            "integrity_status": "attestation-unavailable",
            "reason": "guard_cursor_cli_attestation_unavailable",
        }
    # Imported here so the hook bridges stay off the native runtime at import time.
    from ..native_runner_authority import native_runner_authority

    hooks_path = cursor_hooks_path(context)
    script_path = cursor_hook_script_path(context)
    managed_script_path = managed_hook_script_path(context)
    try:
        state_text: str | None = _hooks_state_path(hooks_path, context).read_text(encoding="utf-8")
    except OSError:
        state_text = None
    python_executable = guard_cli.python.executable if guard_cli.python is not None else None
    errors: dict[str, Exception] = {}
    request = {
        "source": expected_source,
        "identity": guard_cli.manifest_payload(),
        "state_text": state_text,
        "scripts": [
            _observe(errors, "script", lambda: _read_script(script_path)),
            _observe(errors, "managed_script", lambda: _read_script(managed_script_path)),
        ],
        "hooks_text": _observe(errors, "hooks", lambda: _read_hooks(hooks_path)),
        "entries": {
            event: _observe(
                errors,
                event,
                lambda event=event: _managed_hook_entry(
                    context, script_path=script_path, event_name=event, python_executable=python_executable
                ),
            )
            for event in _MANAGED_HOOK_EVENTS
        },
    }
    answer = native_runner_authority("cursor_hook_state", request)
    if not isinstance(answer, dict):
        raise ValueError("Cursor hook state answer is malformed")
    label = answer.get("raise")
    if set(answer) == {"raise"} and isinstance(label, str) and label in errors:
        raise errors[label]
    status = answer.get("integrity_status")
    reason = answer.get("reason")
    if set(answer) != {"integrity_status", "reason"}:
        raise ValueError("Cursor hook state answer is malformed")
    if status == "valid" and reason is None:
        return {
            "protection_active": True,
            "integrity_status": "valid",
            "reason": None,
            "guard_cli_identity": guard_cli.manifest_payload(),
        }
    if status not in _STATE_STATUSES or not isinstance(reason, str):
        raise ValueError("Cursor hook state answer is malformed")
    return {"protection_active": False, "integrity_status": status, "reason": reason}


__all__ = [
    "HOOK_SCRIPT_NAME",
    "_resolve_guard_cli_command",
    "_strip_managed_hook_entries",
    "cursor_hook_script_source",
    "cursor_hooks_path",
    "cursor_native_hook_state",
    "install_cursor_hooks",
    "uninstall_cursor_hooks",
]
