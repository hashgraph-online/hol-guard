"""Shared readers for Guard-managed harness state and backup files."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path


def plan_backup_restore(backup_text: str | None, *, target_exists: bool) -> tuple[str, str | None, bool]:
    """Ask the native runtime what uninstall does with a captured backup.

    Returns ``(action, content, restored)``: ``write`` the saved config back,
    ``unlink`` the config Guard created, or ``keep`` the target. ``restored``
    says whether the backup was fully applied, so its state may be removed.
    """

    # Imported here so the hook bridges stay off the native runtime at import time.
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority(
            "harness_backup_restore", {"backup": backup_text, "target_exists": target_exists}
        )
    except NativeRunnerAuthorityError as error:
        raise RuntimeError(f"Backup restore request failed: {error}") from error
    action, content, restored = answer.get("action"), answer.get("content"), answer.get("restored")
    content_ok = isinstance(content, str) if action == "write" else content is None
    if action not in ("write", "unlink", "keep") or not content_ok or not isinstance(restored, bool):
        raise RuntimeError("Backup restore answer is malformed")
    return str(action), content, restored


def restore_from_backup(backup_path: Path, target_path: Path, *, write: Callable[[Path, str], object]) -> bool:
    """Apply the native restore plan for *backup_path* to *target_path*; return whether it was restored."""

    try:
        backup_text: str | None = backup_path.read_text(encoding="utf-8")
    except OSError:
        backup_text = None
    action, content, restored = plan_backup_restore(backup_text, target_exists=target_path.is_file())
    if action == "write" and content is not None:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        write(target_path, content)
    elif action == "unlink":
        target_path.unlink()
    return restored


def load_string_state_payload(
    state_path: Path,
    *,
    keys: tuple[str, ...] = ("managed_config_path", "backup_path", "scope", "workspace_dir"),
) -> dict[str, str]:
    """Load the string-valued fields understood by managed-install adapters."""

    if not state_path.is_file():
        return {}
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {key: value for key in keys if isinstance((value := payload.get(key)), str)}
