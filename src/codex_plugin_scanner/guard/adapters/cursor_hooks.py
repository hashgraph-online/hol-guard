"""Cursor IDE native hooks (.cursor/hooks.json) for HOL Guard."""

from __future__ import annotations

import json
import os
import stat
from hashlib import sha256
from pathlib import Path

from .base import HarnessContext
from .cursor_hook_config import (
    _MANAGED_HOOK_EVENTS,
    _MANAGED_HOOK_TIMEOUT_SECONDS,
    HOOK_SCRIPT_NAME,
    _backup_payload,
    _hooks_backup_path,
    _hooks_state_path,
    _inline_hooks,
    _is_managed_hook_entry,
    _is_managed_hook_script,
    _json_object,
    _make_executable,
    _managed_hook_entry,
    _managed_hooks_payload,
    _merge_hook_entries,
    _strip_managed_hook_entries,
)
from .cursor_hook_payload import (
    _validated_hol_guard_src_path,
    cursor_hook_requires_approval_center_queue,
    cursor_hook_response_from_guard,
    cursor_hook_should_block,
    cursor_hook_would_prompt_user,
    prepare_cursor_hook_payload,
)
from .cursor_hook_script_template_head import HOOK_SCRIPT_TEMPLATE_HEAD
from .cursor_hook_script_template_tail import HOOK_SCRIPT_TEMPLATE_TAIL
from .cursor_native_approval import ensure_cursor_hook_attestation_secret
from .guard_cli_attestation import resolve_attested_guard_cli

_HOOK_SCRIPT_TEMPLATE = HOOK_SCRIPT_TEMPLATE_HEAD + HOOK_SCRIPT_TEMPLATE_TAIL
_INHERIT_ENV_KEYS = (
    "PATH",
    "HOME",
    "USER",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "SYSTEMROOT",
    "CURSOR_PROJECT_DIR",
    "CURSOR_VERSION",
    "CURSOR_TRACE_ID",
    "CURSOR_SESSION_ID",
    "CURSOR_TRANSCRIPT_PATH",
    "HOL_GUARD_SRC",
)


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


def install_cursor_hooks(context: HarnessContext) -> dict[str, object]:
    """Install Guard-managed Cursor hooks and bridge script."""

    guard_cli = resolve_attested_guard_cli(context)
    hooks_path = cursor_hooks_path(context)
    script_path = cursor_hook_script_path(context)
    managed_script_path = managed_hook_script_path(context)
    managed_script_path.parent.mkdir(parents=True, exist_ok=True)
    script_source = cursor_hook_script_source(context, guard_cli=list(guard_cli.command))
    managed_script_path.write_text(script_source, encoding="utf-8")
    _make_executable(managed_script_path)
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text(script_source, encoding="utf-8")
    _make_executable(script_path)
    ensure_cursor_hook_attestation_secret(context.guard_home)

    original_text = hooks_path.read_text(encoding="utf-8") if hooks_path.is_file() else None
    backup_path = _hooks_backup_path(hooks_path, context)
    if not backup_path.exists():
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        backup_path.write_text(
            json.dumps({"existed": original_text is not None, "content": original_text}, indent=2) + "\n",
            encoding="utf-8",
        )
    state_path = _hooks_state_path(hooks_path, context)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    workspace_dir = str(context.workspace_dir.resolve()) if context.workspace_dir is not None else None
    state_path.write_text(
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
        encoding="utf-8",
    )

    payload = _managed_hooks_payload(_json_object(hooks_path, recover_missing=True))
    hooks = _inline_hooks(payload)
    for event_name in _MANAGED_HOOK_EVENTS:
        entry = _managed_hook_entry(context, script_path=script_path, event_name=event_name)
        hooks[event_name] = _merge_hook_entries(hooks.get(event_name), entry, event_name=event_name)
    pre_tool_use = hooks.get("preToolUse")
    if pre_tool_use is not None:
        stripped = _strip_managed_hook_entries(pre_tool_use, script_path=script_path)
        if stripped:
            hooks["preToolUse"] = stripped
        else:
            hooks.pop("preToolUse", None)
    payload["hooks"] = hooks
    hooks_path.parent.mkdir(parents=True, exist_ok=True)
    hooks_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
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

    return _uninstall_cursor_hooks_at_paths(
        hooks_path=cursor_hooks_path(context),
        script_path=cursor_hook_script_path(context),
        context=context,
        remove_managed_copy=True,
    )


def _uninstall_cursor_hooks_at_paths(
    *,
    hooks_path: Path,
    script_path: Path,
    context: HarnessContext,
    remove_managed_copy: bool,
) -> dict[str, object]:
    backup_path = _hooks_backup_path(hooks_path, context)
    state_path = _hooks_state_path(hooks_path, context)
    backup_payload = _backup_payload(backup_path)
    restored = False
    if backup_payload["readable"] is True:
        if backup_payload["existed"] and isinstance(backup_payload["content"], str):
            hooks_path.parent.mkdir(parents=True, exist_ok=True)
            hooks_path.write_text(str(backup_payload["content"]), encoding="utf-8")
            restored = True
        elif backup_payload["existed"] is not True and hooks_path.is_file():
            hooks_path.unlink()
            restored = True
        elif backup_payload["existed"] is not True:
            restored = True
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
                for entries in hooks.values():
                    if not isinstance(entries, list):
                        continue
                    for entry in entries:
                        if _is_managed_hook_entry(entry, command=str(script_path.resolve())):
                            managed = True
                            break
                    if managed:
                        break
    if not managed:
        return
    _uninstall_cursor_hooks_at_paths(
        hooks_path=hooks_path,
        script_path=script_path,
        context=context,
        remove_managed_copy=False,
    )
    _prune_empty_project_cursor_dir(context.workspace_dir)


def _prune_empty_project_cursor_dir(workspace_dir: Path) -> None:
    hooks_dir = workspace_dir / ".cursor" / "hooks"
    cursor_dir = workspace_dir / ".cursor"
    if hooks_dir.is_dir():
        try:
            if not any(hooks_dir.iterdir()):
                hooks_dir.rmdir()
        except OSError:
            return
    if not cursor_dir.is_dir():
        return
    try:
        remaining = list(cursor_dir.iterdir())
    except OSError:
        return
    if not remaining:
        try:
            cursor_dir.rmdir()
        except OSError:
            return


def _remove_managed_hook_entries(*, hooks_path: Path, script_path: Path) -> bool:
    try:
        payload = json.loads(hooks_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    hooks = payload.get("hooks")
    has_managed_hooks = False
    has_other_hooks = False
    if not isinstance(hooks, dict):
        return False
    cleaned_hooks: dict[str, object] = {}
    managed_command = str(script_path.resolve())
    for event, entries in hooks.items():
        if isinstance(entries, list):
            filtered: list[object] = []
            for entry in entries:
                if _is_managed_hook_entry(entry, command=managed_command):
                    has_managed_hooks = True
                else:
                    filtered.append(entry)
            if filtered:
                cleaned_hooks[str(event)] = filtered
                has_other_hooks = True
        else:
            cleaned_hooks[str(event)] = entries
            has_other_hooks = True
    if not has_managed_hooks:
        return False
    if has_other_hooks:
        payload["hooks"] = cleaned_hooks
        hooks_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    else:
        hooks_path.unlink()
    return True


def _resolve_guard_cli_command(context: HarnessContext) -> list[str]:
    """Return only the isolated CLI bound to the running Guard distribution."""

    return list(resolve_attested_guard_cli(context).command)


def _uses_top_level_hook_command(guard_cli: list[str]) -> bool:
    if not guard_cli:
        return False
    # hol-guard/plugin-guard entrypoints expose `hook` at the top level (combined-mode
    # hol-guard rewrites `hook` to `guard hook` internally). Only module invocations
    # need an explicit `guard` prefix.
    return Path(guard_cli[0]).name in {"hol-guard", "plugin-guard"}


def _embedded_guard_hook_argv(context: HarnessContext) -> list[str]:
    guard_argv = [
        "hook",
        "--guard-home",
        str(context.guard_home),
        "--harness",
        "cursor",
        "--json",
    ]
    if context.home_dir.resolve() != Path.home().resolve():
        guard_argv.extend(["--home", str(context.home_dir)])
    return guard_argv


def cursor_hook_script_source(
    context: HarnessContext,
    *,
    guard_cli: list[str] | None = None,
) -> str:
    guard_cli = list(guard_cli) if guard_cli is not None else _resolve_guard_cli_command(context)
    guard_argv = _embedded_guard_hook_argv(context)
    if not _uses_top_level_hook_command(guard_cli):
        guard_argv = ["guard", *guard_argv]
    return (
        _HOOK_SCRIPT_TEMPLATE.replace("__GUARD_HOME__", json.dumps(str(context.guard_home.resolve())))
        .replace("__GUARD_CLI__", json.dumps(guard_cli))
        .replace(
            "__GUARD_HOOK_ARGV__",
            json.dumps(guard_argv),
        )
        .replace(
            "__GUARD_INHERIT_ENV_KEYS__",
            json.dumps(list(_INHERIT_ENV_KEYS)),
        )
        .replace(
            "__GUARD_HOOK_TIMEOUT_SECONDS__",
            str(max(_MANAGED_HOOK_TIMEOUT_SECONDS - 3, 1)),
        )
    )


def cursor_native_hook_state(context: HarnessContext) -> dict[str, object]:
    """Verify Cursor registration, scripts, and the current attested CLI identity."""

    try:
        guard_cli = resolve_attested_guard_cli(context)
        expected_source = cursor_hook_script_source(context, guard_cli=list(guard_cli.command))
    except RuntimeError:
        return {
            "protection_active": False,
            "integrity_status": "attestation-unavailable",
            "reason": "guard_cursor_cli_attestation_unavailable",
        }
    hooks_path = cursor_hooks_path(context)
    script_path = cursor_hook_script_path(context)
    managed_script_path = managed_hook_script_path(context)
    state_path = _hooks_state_path(hooks_path, context)
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "protection_active": False,
            "integrity_status": "missing",
            "reason": "guard_cursor_hook_state_missing",
        }
    if not isinstance(state, dict) or state.get("guard_cli_identity") != guard_cli.manifest_payload():
        return {
            "protection_active": False,
            "integrity_status": "tampered",
            "reason": "guard_cursor_cli_identity_mismatch",
        }
    expected_hash = sha256(expected_source.encode("utf-8")).hexdigest()
    if state.get("hook_script_sha256") != expected_hash:
        return {
            "protection_active": False,
            "integrity_status": "stale",
            "reason": "guard_cursor_hook_script_identity_stale",
        }
    for candidate in (script_path, managed_script_path):
        try:
            metadata = candidate.lstat()
            source = candidate.read_text(encoding="utf-8")
        except OSError:
            return {
                "protection_active": False,
                "integrity_status": "missing",
                "reason": "guard_cursor_hook_script_missing",
            }
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or not _hook_script_mode_is_executable(metadata.st_mode)
            or source != expected_source
        ):
            return {
                "protection_active": False,
                "integrity_status": "tampered",
                "reason": "guard_cursor_hook_script_tampered",
            }
    try:
        hooks_payload = _json_object(hooks_path, recover_missing=False)
    except RuntimeError:
        return {
            "protection_active": False,
            "integrity_status": "missing",
            "reason": "guard_cursor_hook_registration_missing",
        }
    hooks = hooks_payload.get("hooks")
    if not isinstance(hooks, dict):
        return {
            "protection_active": False,
            "integrity_status": "tampered",
            "reason": "guard_cursor_hook_registration_mismatch",
        }
    for event_name in _MANAGED_HOOK_EVENTS:
        entries = hooks.get(event_name)
        expected_entry = _managed_hook_entry(context, script_path=script_path, event_name=event_name)
        if not isinstance(entries, list) or sum(entry == expected_entry for entry in entries) != 1:
            return {
                "protection_active": False,
                "integrity_status": "tampered",
                "reason": "guard_cursor_hook_registration_mismatch",
            }
    return {
        "protection_active": True,
        "integrity_status": "valid",
        "reason": None,
        "guard_cli_identity": guard_cli.manifest_payload(),
    }


def _hook_script_mode_is_executable(mode: int) -> bool:
    """Use POSIX execute bits only on platforms where they govern launch."""

    # Keep this compatibility wrapper in the public module so existing test and
    # integration monkeypatches of cursor_hooks.os.name continue to work.
    return os.name == "nt" or bool(mode & stat.S_IXUSR)


__all__ = [
    "HOOK_SCRIPT_NAME",
    "_hook_script_mode_is_executable",
    "_resolve_guard_cli_command",
    "_strip_managed_hook_entries",
    "_validated_hol_guard_src_path",
    "cursor_hook_requires_approval_center_queue",
    "cursor_hook_response_from_guard",
    "cursor_hook_script_source",
    "cursor_hook_should_block",
    "cursor_hook_would_prompt_user",
    "cursor_hooks_path",
    "cursor_native_hook_state",
    "install_cursor_hooks",
    "prepare_cursor_hook_payload",
    "uninstall_cursor_hooks",
]
