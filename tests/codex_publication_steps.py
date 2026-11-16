"""Publish a Codex hook generation one step at a time, for crash tests.

The runtime's ``publish_hooks`` op prepares the publication record, writes
the files, records the config inode, verifies the live hooks and commits in
one request, so a test cannot stop it between steps. This publisher drives
the same native record ops in the same order from Python, so a test can
patch one step (``codex_hook_recovery.prepare_hook_publication``,
``record_owned_hook_config_publication``, ``commit_hook_publication``,
``_remove_record``, ``native_transition_files.publish_files`` or
``readback``) to fail or end the process there.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.runtime_transition import TransitionFile


def _decoded(value: object) -> bytes | None:
    return None if value is None else base64.b64decode(str(value))


def readback(context: HarnessContext) -> dict[str, object]:
    """The verified live hook state, or the failure the runtime raises."""
    from codex_plugin_scanner.guard.adapters import codex

    state = codex.codex_native_hook_state(context)
    if not state.get("protection_active"):
        reason = str(state.get("integrity_reason") or "codex_hook_integrity_readback_failed")
        raise RuntimeError(f"codex_authoritative_hook_unavailable: Codex hook authentication readback failed: {reason}")
    return state


def stepwise_publish_hooks(
    context: HarnessContext, request: Mapping[str, Any], files: Sequence[TransitionFile]
) -> dict[str, Any]:
    """``publish_hooks``, one native record op at a time."""
    from codex_plugin_scanner.guard import codex_hook_recovery as recovery
    from codex_plugin_scanner.guard import native_transition_files
    from codex_plugin_scanner.guard.codex_hook_integrity import remove_hook_secret_if_unused
    from codex_plugin_scanner.guard.codex_hook_rollback import rollback_file_identity
    from codex_plugin_scanner.guard.runtime_transition import TransitionError

    home, config = context.guard_home, Path(str(request["config"]))
    config_change = files[int(request["config_index"])]
    manifest_change = files[int(request["manifest_index"])]
    receipt_change = files[int(request["receipt_index"])]
    original = _decoded(request["original"])
    key_present = request["key_present"] is True
    if config_change.before != original or config_change.after is None:
        raise TransitionError("adapter_preparation_generation_conflict")
    prepared = False
    written_identity: tuple[int, int, int, int, int] | None = None
    try:
        recovery.prepare_hook_publication(
            home,
            config,
            before_config=config_change.before,
            before_manifest=manifest_change.before,
            after_config=config_change.after,
            after_manifest=_decoded(request["after_manifest"]) or b"",
            key_created=not key_present,
            before_receipt=receipt_change.before,
            after_receipt=receipt_change.after,
        )
        prepared = True

        def remember(change: TransitionFile) -> None:
            nonlocal written_identity
            if change is config_change:
                identity = rollback_file_identity(config)
                if identity is None:
                    raise RuntimeError("codex_hook_config_invalid: Codex configuration vanished after publication.")
                written_identity = identity
                recovery.record_owned_hook_config_publication(home, config, identity)

        native_transition_files.publish_files(files, removals=False, rollback=False, on_write=remember)
        state = readback(context)
        recovery.commit_hook_publication(home)
        return {"state": json.dumps(state)}
    except BaseException as transaction_error:
        try:
            operation_id: str | None = recovery._owned(home)
        except RuntimeError:
            operation_id = None
        aborted = native_transition_files.publication(
            "abort",
            home,
            config=os.path.abspath(config),
            prepared=prepared,
            original=request["original"],
            written=base64.b64encode(config_change.after).decode("ascii"),
            original_identity=request["original_identity"],
            written_identity=list(written_identity) if written_identity else None,
            operation_id=operation_id,
        )
        if not isinstance(aborted, dict):
            raise TransitionError("native_transition_invalid") from transaction_error
        rollback_error: BaseException | None = None
        if aborted.get("rollback_error") is not None:
            rollback_error = native_transition_files._exception(aborted["rollback_error"])
        elif aborted.get("durable") is not True and not key_present:
            remove_hook_secret_if_unused(home)
        if rollback_error is not None:
            raise RuntimeError(
                "Codex hook transaction failed and rollback could not be completed: "
                f"{type(rollback_error).__name__}: {rollback_error}"
            ) from transaction_error
        raise


def use_stepwise_publication(monkeypatch: pytest.MonkeyPatch) -> None:
    """Publish this test's hook generations one step at a time."""
    from codex_plugin_scanner.guard.adapters import codex

    monkeypatch.setattr(codex, "_publish_hooks", stepwise_publish_hooks)


# The same switch for a child process script.
STEPWISE_HOOKS = r"""
from codex_plugin_scanner.guard.adapters import codex as _stepwise_codex
from tests.codex_publication_steps import stepwise_publish_hooks as _stepwise_publish_hooks
_stepwise_codex._publish_hooks = _stepwise_publish_hooks
"""
