"""Source-only posture transitions through real config and publisher barriers."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.daemon import hook_worker as worker_module
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _ack, _status
from .test_hook_worker_acknowledged_posture import _block_edge, _write_posture


def test_worker_posture_follows_publication_and_first_workspace_barriers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = tmp_path / "guard-home"
    _write_posture(guard_home, "protected")
    store = GuardStore(guard_home)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"p" * 32, "source-test-master"))
    accept = True

    def transport(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        # This is a source protocol double. The real compiler, signed snapshot
        # construction, ACK checks and barrier updates run; no native execution
        # or installed authentication is claimed by this test.
        return _ack(payload) if accept else b"invalid source-test acknowledgement"

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=transport)
    # Drive finite publications explicitly; production's readiness deadline and
    # background observer are independently covered by the publisher suite.
    monkeypatch.setattr(publisher, "start", lambda: None)
    monkeypatch.setattr(publisher, "wait_until_ready", lambda _deadline: publisher.is_ready())
    monkeypatch.setattr(worker_module, "get_native_policy_snapshot_publisher", lambda _store: publisher)
    monkeypatch.setattr(worker_module, "native_mode", lambda: "auto")
    worker = HookWorker(store=store, wait_for_native_policy=False)
    native_calls: list[dict[str, object]] = []

    def evaluate(**kwargs: object) -> dict[str, object] | None:
        native_calls.append(kwargs)
        return _block_edge("PreToolUse") if kwargs["policy_snapshot"] is not None else None

    monkeypatch.setattr(worker, "_review_raw_hook_native", evaluate)

    def review(workspace: Path | None = None) -> str:
        native_calls.clear()
        response = worker._review_native_edge(
            payload={"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
            harness="pi",
            event_name="PreToolUse",
            default_harness="pi",
            home_dir=tmp_path,
            guard_home=guard_home,
            workspace=workspace,
            deadline=None,
        )
        assert len(native_calls) == 1
        binding = native_calls[0]["policy_snapshot"]
        assert native_calls[0]["observe_mode"] is (isinstance(binding, dict) and binding.get("mode") == "observe")
        if binding is None:
            assert response["reason_code"] == "native_pre_tool_unavailable"
            return "unavailable"
        return str(response["policy_action"])

    try:
        publisher._publish_once()
        assert publisher.is_ready()
        assert review() == "block"

        # Raw edits do not reinterpret an already acknowledged enforce mode.
        _write_posture(guard_home, "watch")
        assert review() == "block"

        # Public mutations withdraw readiness immediately. Neither an absent
        # ACK nor a failed ACK may apply the requested weaker posture.
        update_guard_settings(guard_home, {"protection_posture": "watch"})
        assert not publisher.is_ready()
        assert review() == "unavailable"
        accept = False
        publisher._publish_once()
        assert not publisher.is_ready()
        assert review() == "unavailable"
        accept = True
        publisher._publish_once()
        assert publisher.is_ready()
        assert review() == "warn"

        # The stronger public transition follows the same ACK boundary.
        update_guard_settings(guard_home, {"protection_posture": "protected"})
        assert not publisher.is_ready()
        assert review() == "unavailable"
        publisher._publish_once()
        assert publisher.is_ready()
        assert review() == "block"

        update_guard_settings(guard_home, {"protection_posture": "watch"})
        publisher._publish_once()
        assert review() == "warn"

        update_guard_settings(guard_home, {"protection_posture": "protected"})
        publisher._publish_once()
        before_workspace = publisher.current_snapshot()
        assert before_workspace is not None

        # Workspace files cannot select mode/posture. Exercise an actually
        # permitted stricter sandbox overlay alongside an ignored attempt to
        # weaken posture; first use withdraws the home-only binding until ACK.
        workspace = tmp_path / "strict-workspace"
        workspace.mkdir()
        (workspace / ".hol-guard.toml").write_text(
            'mode = "observe"\nprotection_posture = "watch"\nsandbox_analysis = "strict"\n'
        )
        assert review(workspace) == "unavailable"
        publisher._publish_once()
        assert publisher.is_ready()
        after_workspace = publisher.current_snapshot()
        assert after_workspace is not None
        assert after_workspace["policy_digest"] != before_workspace["policy_digest"]
        effective_policy = after_workspace["effective_policy"]
        assert isinstance(effective_policy, Mapping)
        assert effective_policy["sandbox_analysis"] == "strict"
        assert after_workspace["mode"] == "enforce"
        assert review(workspace) == "block"
        assert review() == "block"
    finally:
        worker.close()
