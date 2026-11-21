"""The hook waits out a busy approval-authority lock instead of refusing the action."""

from __future__ import annotations

from pathlib import Path

import pytest

import codex_plugin_scanner.guard.hook_review.hook_worker as hook_worker_module
from codex_plugin_scanner.guard.store import GuardStore


def test_prepare_workspace_policy_waits_for_a_busy_approval_authority_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A publish that lost the short approval-authority lock wait clears on the next attempt."""

    wait_deadlines: list[float] = []

    class _Publisher:
        last_error = "native_approval_authority_busy"
        ready = False

        def start(self) -> None:
            return

        def register_workspace(self, workspace: Path | None, *, deadline: float | None = None) -> bool:
            del workspace
            return False

        def wait_until_ready(self, deadline_monotonic: float) -> bool:
            wait_deadlines.append(deadline_monotonic)
            self.ready = len(wait_deadlines) > 1
            return self.ready

        def current_snapshot_binding(self) -> dict[str, object] | None:
            if not self.ready:
                return None
            return {
                "generation": 2,
                "policy_digest": "a" * 64,
                "runtime_identity": "b" * 64,
                "mode": "enforce",
            }

        def close(self) -> None:
            return

    monkeypatch.setattr(hook_worker_module, "get_native_policy_snapshot_publisher", lambda _store: _Publisher())

    worker = hook_worker_module.HookWorker(store=GuardStore(tmp_path / "guard-home"))
    binding = worker.prepare_workspace_policy(tmp_path / "workspace")

    assert binding is not None and binding["generation"] == 2
    assert len(wait_deadlines) == 2
