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
    from tests.codex_publication_steps import use_stepwise_publication

    # A Codex hook generation publishes inside one runtime op; step it from
    # Python so its file writes go through ``publish_files`` here.
    use_stepwise_publication(monkeypatch)
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


# A subprocess preamble that publishes a harness plan one file at a time
# through ``RuntimeTransition._write_file``, so a crash script can stop the
# process between two files. Restores run newest first, as the resident's do.
STEPWISE_PUBLICATION = r"""
def _stepwise_publication():
    from codex_plugin_scanner.guard import native_transition_files
    from codex_plugin_scanner.guard.runtime_transition import RuntimeTransition, TransitionError

    def publish(files, *, removals, rollback, on_write):
        if any(
            change.kind != "binding" or (not removals and change.after is None and change.before != change.after)
            for change in files
        ):
            raise TransitionError("adapter_install_plan_invalid")
        plan = {"files": [change.payload() for change in files]}
        RuntimeTransition._compare(plan, "before")
        written = []
        try:
            for change in files:
                payload = change.payload()
                RuntimeTransition._compare({"files": [payload]}, "before")
                RuntimeTransition._write_file(payload, "after")
                written.append(payload)
                if on_write is not None:
                    on_write(change)
            RuntimeTransition._compare(plan, "after")
        except BaseException as error:
            if not rollback:
                raise
            restore_error = None
            for payload in reversed(written):
                try:
                    RuntimeTransition._compare({"files": [payload]}, "after")
                    RuntimeTransition._write_file(payload, "before")
                except Exception as failure:
                    restore_error = failure
            if restore_error is not None:
                raise restore_error from error
            raise

    native_transition_files.publish_files = publish
    # The hook generation goes through ``publish_files`` too.
    from codex_plugin_scanner.guard import codex_harness_client as codex
    from tests import codex_install_flow_support as flow
    from tests.codex_publication_steps import install_stepwise_codex, stepwise_publish_hooks

    flow.publish_hooks = stepwise_publish_hooks
    install_stepwise_codex()
"""
