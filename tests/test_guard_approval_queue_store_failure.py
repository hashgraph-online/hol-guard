"""A quarantined store must not drop the deny-path approval_requests contract.

When ``queue_blocked_approvals`` raises (e.g. ``sqlite3.OperationalError`` from a
quarantined SQLite store), ``resolve_from_local_queue`` must still emit an
explicit ``approval_requests`` key so downstream consumers never hit ``KeyError``
and the action stays blocked.
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import approvals as approvals_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approvals import approvals_queued_before, queue_blocked_approvals
from codex_plugin_scanner.guard.cli import commands_support_hook_payload as payload_module
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.store import GuardStore


def _detection() -> HarnessDetection:
    artifact = GuardArtifact(
        artifact_id="art-1",
        name="tool",
        harness="claude-code",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="",
    )
    return HarnessDetection(
        harness="claude-code",
        installed=True,
        command_available=True,
        config_paths=("",),
        artifacts=(artifact,),
    )


def test_store_failure_still_emits_approval_requests_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=None)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=guard_home)
    args = argparse.Namespace(harness="claude-code", json=True)

    def failing_queue(**_kwargs):
        raise sqlite3.OperationalError("database is quarantined")

    monkeypatch.setattr(payload_module, "queue_blocked_approvals", failing_queue)
    monkeypatch.setattr(payload_module, "schedule_guard_daemon_ensure", lambda *_a, **_k: "http://127.0.0.1:4455")
    monkeypatch.setattr(payload_module, "_managed_install_for", lambda *_a, **_k: None)
    monkeypatch.setattr(
        payload_module,
        "approval_prompt_flow",
        lambda *_a, **_k: {"tier": "local"},
    )

    # Force the local-queue path (daemon client unavailable).
    def no_daemon(*_a, **_k):
        raise RuntimeError("no daemon")

    monkeypatch.setattr(payload_module, "load_guard_surface_daemon_client", no_daemon)

    resolver = payload_module._headless_approval_resolver(args=args, context=context, store=store, config=config)
    result = resolver(
        _detection(),
        {"artifacts": [{"artifact_id": "art-1", "policy_action": "require-reapproval"}]},
    )

    assert "approval_requests" in result
    assert result["approval_requests"] == []
    assert result["approval_queue_unavailable"] == "OperationalError"


def test_programming_error_in_queue_still_propagates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A bug in queue_blocked_approvals must not be masked by the store guard."""
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=None)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=guard_home)
    args = argparse.Namespace(harness="claude-code", json=True)

    def buggy_queue(**_kwargs):
        raise ValueError("fresh_review_request_id_required")

    monkeypatch.setattr(payload_module, "queue_blocked_approvals", buggy_queue)
    monkeypatch.setattr(payload_module, "schedule_guard_daemon_ensure", lambda *_a, **_k: "http://127.0.0.1:4455")
    monkeypatch.setattr(payload_module, "_managed_install_for", lambda *_a, **_k: None)
    monkeypatch.setattr(
        payload_module,
        "approval_prompt_flow",
        lambda *_a, **_k: {"tier": "local"},
    )

    def no_daemon(*_a, **_k):
        raise RuntimeError("no daemon")

    monkeypatch.setattr(payload_module, "load_guard_surface_daemon_client", no_daemon)

    resolver = payload_module._headless_approval_resolver(args=args, context=context, store=store, config=config)
    with pytest.raises(ValueError, match="fresh_review_request_id_required"):
        resolver(
            _detection(),
            {"artifacts": [{"artifact_id": "art-1", "policy_action": "require-reapproval"}]},
        )


def test_daemon_load_failure_records_category_on_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The daemon-unavailable fallback preserves the exception category."""
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=None)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=guard_home)
    args = argparse.Namespace(harness="claude-code", json=True)

    monkeypatch.setattr(payload_module, "queue_blocked_approvals", lambda **_kwargs: [])
    monkeypatch.setattr(payload_module, "schedule_guard_daemon_ensure", lambda *_a, **_k: "http://127.0.0.1:4455")
    monkeypatch.setattr(payload_module, "_managed_install_for", lambda *_a, **_k: None)
    monkeypatch.setattr(
        payload_module,
        "approval_prompt_flow",
        lambda *_a, **_k: {"tier": "local"},
    )

    class FailingLoadError(RuntimeError):
        pass

    def failing_load(*_a, **_k):
        raise FailingLoadError("daemon transport refused")

    monkeypatch.setattr(payload_module, "load_guard_surface_daemon_client", failing_load)

    resolver = payload_module._headless_approval_resolver(args=args, context=context, store=store, config=config)
    result = resolver(
        _detection(),
        {"artifacts": [{"artifact_id": "art-1", "policy_action": "require-reapproval"}]},
    )

    assert result["daemon_queue_unavailable"] == "FailingLoadError: daemon transport refused"


def test_daemon_plain_runtime_error_preserves_startup_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A plain RuntimeError from ensure_guard_daemon keeps its specific message."""
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=None)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=guard_home)
    args = argparse.Namespace(harness="claude-code", json=True)

    monkeypatch.setattr(payload_module, "queue_blocked_approvals", lambda **_kwargs: [])
    monkeypatch.setattr(payload_module, "schedule_guard_daemon_ensure", lambda *_a, **_k: "http://127.0.0.1:4455")
    monkeypatch.setattr(payload_module, "_managed_install_for", lambda *_a, **_k: None)
    monkeypatch.setattr(
        payload_module,
        "approval_prompt_flow",
        lambda *_a, **_k: {"tier": "local"},
    )

    def unsafe_daemon(*_a, **_k):
        raise RuntimeError("This Guard daemon is quarantined after unconfirmed containment.")

    monkeypatch.setattr(payload_module, "load_guard_surface_daemon_client", unsafe_daemon)

    resolver = payload_module._headless_approval_resolver(args=args, context=context, store=store, config=config)
    result = resolver(
        _detection(),
        {"artifacts": [{"artifact_id": "art-1", "policy_action": "require-reapproval"}]},
    )

    assert result["daemon_queue_unavailable"].startswith("RuntimeError: ")
    assert "quarantined" in result["daemon_queue_unavailable"]


def test_daemon_operation_failure_records_category_on_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """queue_blocked_operation failure records its category on the fallback."""
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=None)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=guard_home)
    args = argparse.Namespace(harness="claude-code", json=True)

    monkeypatch.setattr(payload_module, "queue_blocked_approvals", lambda **_kwargs: [])
    monkeypatch.setattr(payload_module, "schedule_guard_daemon_ensure", lambda *_a, **_k: "http://127.0.0.1:4455")
    monkeypatch.setattr(payload_module, "_managed_install_for", lambda *_a, **_k: None)
    monkeypatch.setattr(
        payload_module,
        "approval_prompt_flow",
        lambda *_a, **_k: {"tier": "local"},
    )

    class OperationError(RuntimeError):
        pass

    class _Client:
        def start_session(self, **_kwargs):
            return {"session_id": "s-1"}

        def queue_blocked_operation(self, **_kwargs):
            raise OperationError("blocked operation rejected")

    monkeypatch.setattr(payload_module, "load_guard_surface_daemon_client", lambda *_a, **_k: _Client())

    resolver = payload_module._headless_approval_resolver(args=args, context=context, store=store, config=config)
    result = resolver(
        _detection(),
        {"artifacts": [{"artifact_id": "art-1", "policy_action": "require-reapproval"}]},
    )

    assert result["daemon_queue_unavailable"] == "OperationError: blocked operation rejected"


@pytest.mark.parametrize(
    "items",
    [
        [],
        ["not-a-dict"],
        [{"artifact_id": "art-1", "policy_action": "allow"}],
        [{"artifact_id": "", "policy_action": "review"}],
    ],
)
def test_queue_without_reviewable_items_never_touches_the_store(items: list[object]) -> None:
    class _UntouchedStore:
        def __getattr__(self, name: str) -> object:
            raise AssertionError(f"store.{name} used without a reviewable item")

    queued = queue_blocked_approvals(
        detection=_detection(),
        evaluation={"artifacts": items},
        store=_UntouchedStore(),  # type: ignore[arg-type]
        approval_center_url="http://127.0.0.1:4781",
        now="not-a-timestamp",
    )

    assert queued == []


def test_queue_failure_keeps_the_requests_written_before_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # No detected artifacts keeps the queue payload free of native risk lookups.
    detection = HarnessDetection(
        harness="claude-code", installed=True, command_available=True, config_paths=("",), artifacts=()
    )

    class _SecondWriteFails:
        def __init__(self) -> None:
            self.writes = 0

        def queue_blocked_approvals(self, _args: dict[str, object]) -> tuple[list[dict[str, object]], Exception | None]:
            self.writes += 1
            if self.writes == 1:
                return [{"request_id": "req-1"}], None
            return [], OSError("disk full")

        def get_approval_request(self, request_id: str) -> dict[str, object]:
            return {"request_id": request_id}

    monkeypatch.setattr(
        approvals_module,
        "continuation_offer_facts",
        lambda *_a, **_k: SimpleNamespace(
            harness="claude-code",
            original_hook_attached=False,
            wait_deadline=None,
            opaque_target_id=None,
            session_target_verified=False,
            metadata={},
        ),
    )

    with pytest.raises(OSError, match="disk full") as raised:
        queue_blocked_approvals(
            detection=detection,
            evaluation={
                "artifacts": [
                    {"artifact_id": "art-1", "policy_action": "require-reapproval"},
                    {"artifact_id": "art-2", "policy_action": "require-reapproval"},
                ]
            },
            store=_SecondWriteFails(),  # type: ignore[arg-type]
            approval_center_url="http://127.0.0.1:4781",
            now="2026-01-01T00:00:00+00:00",
            notify=False,
        )

    assert approvals_queued_before(raised.value) == [{"request_id": "req-1"}]
    assert approvals_queued_before(OSError("unrelated")) == []


def test_store_failure_reply_keeps_requests_queued_before_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=None)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=guard_home)
    args = argparse.Namespace(harness="claude-code", json=True)

    def partly_failing_queue(**_kwargs):
        error = sqlite3.OperationalError("database is locked")
        error.queued_approvals = [{"request_id": "req-1"}]  # type: ignore[attr-defined]
        raise error

    def no_daemon(*_a, **_k):
        raise RuntimeError("no daemon")

    monkeypatch.setattr(payload_module, "queue_blocked_approvals", partly_failing_queue)
    monkeypatch.setattr(payload_module, "schedule_guard_daemon_ensure", lambda *_a, **_k: "http://127.0.0.1:4455")
    monkeypatch.setattr(payload_module, "_managed_install_for", lambda *_a, **_k: None)
    monkeypatch.setattr(payload_module, "approval_prompt_flow", lambda *_a, **_k: {"tier": "local"})
    monkeypatch.setattr(payload_module, "load_guard_surface_daemon_client", no_daemon)

    resolver = payload_module._headless_approval_resolver(args=args, context=context, store=store, config=config)
    result = resolver(
        _detection(),
        {"artifacts": [{"artifact_id": "art-1", "policy_action": "require-reapproval"}]},
    )

    assert [request["request_id"] for request in result["approval_requests"]] == ["req-1"]
    assert result["approval_queue_unavailable"] == "OperationalError"


def test_partial_queue_never_waits_to_resume_the_launch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=None)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=guard_home)
    args = argparse.Namespace(harness="claude-code", json=False)

    def partly_failing_queue(**_kwargs):
        error = sqlite3.OperationalError("database is locked")
        error.queued_approvals = [{"request_id": "req-1"}]  # type: ignore[attr-defined]
        raise error

    def no_daemon(*_a, **_k):
        raise RuntimeError("no daemon")

    def must_not_wait(**_kwargs):
        raise AssertionError("approving req-1 alone must not resume the launch")

    monkeypatch.setattr(payload_module, "queue_blocked_approvals", partly_failing_queue)
    monkeypatch.setattr(payload_module, "schedule_guard_daemon_ensure", lambda *_a, **_k: "http://127.0.0.1:4455")
    monkeypatch.setattr(payload_module, "_managed_install_for", lambda *_a, **_k: None)
    monkeypatch.setattr(payload_module, "approval_prompt_flow", lambda *_a, **_k: {"tier": "native-or-center"})
    monkeypatch.setattr(payload_module, "load_guard_surface_daemon_client", no_daemon)
    monkeypatch.setattr(payload_module, "wait_for_approval_requests", must_not_wait)

    resolver = payload_module._headless_approval_resolver(args=args, context=context, store=store, config=config)
    result = resolver(
        _detection(),
        {
            "blocked": True,
            "artifacts": [
                {"artifact_id": "art-1", "policy_action": "require-reapproval"},
                {"artifact_id": "art-2", "policy_action": "require-reapproval"},
            ],
        },
    )

    assert result["blocked"] is True
    assert result["approval_wait"]["resolved"] is False
    assert result["approval_wait"]["pending_request_ids"] == ["req-1"]
