"""Interrupt a native harness publication at one file.

The resident publishes a whole plan in one request, so a test can no longer
patch a per-file Python writer to fail partway. This helper publishes the
files ahead of ``path`` through the real native route, runs ``interfere`` in
place of the write of ``path``, restores the earlier files when the
publication owns its rollback, then raises.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_transition_files
from codex_plugin_scanner.guard.runtime_transition import TransitionFile


def _inverse(change: TransitionFile) -> TransitionFile:
    return replace(
        change,
        before=change.after,
        after=change.before,
        before_mode=change.after_mode,
        after_mode=change.before_mode,
    )


def interrupt_publication_at(
    monkeypatch: pytest.MonkeyPatch,
    path: Path,
    error: BaseException,
    interfere: Callable[[TransitionFile], None] | None = None,
) -> None:
    original = native_transition_files.publish_files
    pending = True

    def interrupted(
        files: Sequence[TransitionFile],
        *,
        removals: bool,
        rollback: bool,
        on_write: Callable[[TransitionFile], None] | None,
    ) -> None:
        nonlocal pending
        index = next((i for i, change in enumerate(files) if change.path == path), None)
        if not pending or index is None:
            original(files, removals=removals, rollback=rollback, on_write=on_write)
            return
        pending = False
        written = list(files[:index])
        if written:
            original(written, removals=removals, rollback=False, on_write=on_write)
        if interfere is not None:
            interfere(files[index])
        if rollback and written:
            # The resident restores what it wrote, newest first, when it owns the rollback.
            inverse = [_inverse(change) for change in reversed(written)]
            original(inverse, removals=True, rollback=False, on_write=None)
        raise error

    monkeypatch.setattr(native_transition_files, "publish_files", interrupted)
