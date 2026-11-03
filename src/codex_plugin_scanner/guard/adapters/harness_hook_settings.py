"""Guard's hook groups in the Muse and Devin user settings.

The native ``harness_settings_file`` kind reads the captured settings (JSONC
for Devin, strict JSON for Muse), refuses a file Guard will not rewrite, plans
Guard's hook groups and renders the new settings, the install state and the
manifest notes. This module only moves the bytes and keeps the modes.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Literal

from ..codex_hook_integrity import atomic_write_text

if TYPE_CHECKING:
    from pathlib import Path

    from ..runtime_transition import TransitionFile

HookHarness = Literal["muse", "devin"]
_TIMING_KEYS = {"muse": "bridge_seconds", "devin": "wait_seconds"}


def _ask(
    harness: HookHarness, op: str, content: bytes | None, keys: set[str], **fields: object
) -> tuple[dict[str, object], list[str]]:
    """One answer whose fields are ``keys``, and its notes; only an install can be refused."""

    # Imported here so the hook bridges stay off the native runtime at import time.
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    encoded = None if content is None else base64.b64encode(content).decode("ascii")
    request = {"op": op, "harness": harness, "content": encoded, **fields}
    answer: dict[str, object] = native_runner_authority("harness_settings_file", request)
    refusal = answer.get("refusal")
    if op == "install" and set(answer) == {"refusal"} and isinstance(refusal, str):
        raise ValueError(refusal)
    notes = answer.get("notes")
    text = answer.get("text")
    if (
        set(answer) != keys
        or not isinstance(notes, list)
        or not all(isinstance(note, str) for note in notes)
        or not (isinstance(text, str) or (text is None and op == "uninstall"))
        or not isinstance(answer.get("state", ""), str)
    ):
        raise NativeRunnerAuthorityError("Harness settings answer is malformed")
    return answer, [str(note) for note in notes]


def prepare_settings_install(
    harness: HookHarness,
    *,
    config_path: Path,
    config_before: bytes | None,
    backup_path: Path,
    state_path: Path,
    command: str,
    timing_seconds: int,
) -> tuple[tuple[TransitionFile, ...], list[str]]:
    """The backup, settings and install-state changes and the manifest notes.

    Raises ``ValueError`` with the user-facing message for a settings file
    Guard will not rewrite. ``timing_seconds`` is Muse's bridge deadline or
    Devin's configured approval wait.
    """

    from ..codex_hook_recovery import _snapshot
    from ..runtime_transition import TransitionFile

    fields: dict[str, object] = {"config_path": str(config_path), "command": command}
    fields[_TIMING_KEYS[harness]] = timing_seconds
    answer, notes = _ask(harness, "install", config_before, {"text", "state", "notes"}, **fields)
    backup_before = _snapshot(backup_path)
    state_before = _snapshot(state_path)
    config_mode = config_path.stat().st_mode & 0o777 if config_before is not None else 0o600
    backup_mode = backup_path.stat().st_mode & 0o777 if backup_before is not None else config_mode
    state_mode = state_path.stat().st_mode & 0o777 if state_before is not None else 0o600
    changes = (
        (backup_path, backup_before, backup_before if backup_before is not None else config_before, backup_mode),
        (config_path, config_before, str(answer["text"]).encode("utf-8"), config_mode),
        (state_path, state_before, str(answer["state"]).encode("utf-8"), state_mode),
    )
    files = tuple(
        TransitionFile(path.resolve(strict=False), before, after, before_mode=mode, after_mode=mode)
        for path, before, after, mode in changes
    )
    return files, notes


def plan_settings_uninstall(harness: HookHarness, path: Path) -> tuple[str | None, list[str]]:
    """The pruned settings text (``None`` leaves the file as it is) and the notes.

    A JSONC or unparseable file is never rewritten: pruning would silently
    strip the user's comments or data.
    """

    present = path.is_file()
    content: bytes | None = None
    if present:
        try:
            content = path.read_bytes()
        except OSError:
            content = None
    answer, notes = _ask(harness, "uninstall", content, {"text", "notes"}, present=present)
    text = answer["text"]
    return (text if isinstance(text, str) else None), notes


def write_settings(path: Path, text: str) -> None:
    """Replace the settings at ``path`` (or its symlink target), keeping the mode."""

    target = path.resolve() if path.is_symlink() else path
    mode = target.stat().st_mode & 0o777 if target.exists() else 0o600
    atomic_write_text(target, text, mode=mode)
