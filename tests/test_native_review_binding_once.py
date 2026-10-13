"""Native review queueing reuses the pause path's resident review binding."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.test_native_review_exact_action_always import (
    _HARNESS,
    _hook_worker,
    _native_package_intent,  # noqa: F401  (autouse fixture)
    _verdict,
    _wrangler_workspace,
)


def test_native_review_asks_the_resident_for_the_review_binding_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    """Queueing a review reuses the pause path's binding instead of a second resident round trip."""
    from codex_plugin_scanner.guard.daemon import hook_native_review_approval, hook_worker_native

    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    result, receipt = _verdict()
    worker, _store = _hook_worker(tmp_path, monkeypatch, result, receipt)
    bindings: list[str | None] = []
    real = hook_native_review_approval.native_review_binding

    def counting(*args: Any, **kwargs: Any) -> str | None:
        binding = real(*args, **kwargs)
        bindings.append(binding)
        return binding

    monkeypatch.setattr(hook_native_review_approval, "native_review_binding", counting)
    # The Claude permission notice runs after the response is rendered; keep this count on the hook deadline path.
    monkeypatch.setattr(hook_worker_native, "record_claude_permission_notice_for_native_review", lambda *_a, **_k: None)
    response = worker.review_http_payload(
        payload={
            "hook_event_name": "PreToolUse",
            "session_id": "binding-once",
            "tool_use_id": "tool-binding-once",
            "tool_name": "Bash",
            "tool_input": {"command": "npx wrangler --version"},
            "cwd": str(workspace),
        },
        params={},
        default_harness=_HARNESS,
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
    )
    assert response["policy_action"] == "review"
    assert len(bindings) == 1
