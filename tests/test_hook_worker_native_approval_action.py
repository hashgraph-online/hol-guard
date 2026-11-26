"""The hook adapter consumes Rust's approval-action classification."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.hook_review import hook_worker_native as native_module
from codex_plugin_scanner.guard.hook_review.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore


def _edge(
    *, requires_approval: bool, recording_only_response: bool = False, local_cli_rule_blocked: bool | None = None
) -> dict[str, Any]:
    edge = {
        "event_name": "PreToolUse",
        "harness": "codex",
        "result": {"decision": "deny", "minimum_action": "review"},
        "harness_response": {"policy_action": "review"},
        "requires_approval": requires_approval,
        "recording_only_response": recording_only_response,
        "exact_command_block": False,
        "containment_route": "none",
    }
    if local_cli_rule_blocked is not None:
        edge["local_cli_rule_blocked"] = local_cli_rule_blocked
        edge["local_cli_rule"] = {
            "blocked": local_cli_rule_blocked,
            "harness_response": {"policy_action": "blocked-by-extension"},
        }
    return edge


def _review(worker: HookWorker, guard_home: Path) -> dict[str, object]:
    response, native = worker._review_native_edge_with_snapshot(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "printf review"}},
        harness="codex",
        event_name="PreToolUse",
        default_harness="codex",
        home_dir=guard_home,
        guard_home=guard_home,
        workspace=guard_home,
        deadline=None,
        policy_snapshot={"mode": "enforce", "generation": 1},
        recording_only=False,
        defer_accepted_recording=True,
    )
    assert native is True
    return response


def _watch_review(worker: HookWorker, guard_home: Path) -> dict[str, object]:
    response, native = worker._review_native_edge_with_snapshot(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "printf review"}},
        harness="codex",
        event_name="PreToolUse",
        default_harness="codex",
        home_dir=guard_home,
        guard_home=guard_home,
        workspace=guard_home,
        deadline=None,
        policy_snapshot={"mode": "enforce", "generation": 1},
        recording_only=True,
        defer_accepted_recording=True,
    )
    assert native is True
    return response


def test_review_action_does_not_get_reclassified_from_minimum_action(
    tmp_path: Path, monkeypatch: Any
) -> None:
    worker = HookWorker(store=GuardStore(tmp_path / "guard"), start_native_policy=False)
    monkeypatch.setattr(
        native_module,
        "native_or_daemon_edge",
        lambda *_args, **_kwargs: (_edge(requires_approval=False), False),
    )
    monkeypatch.setattr(
        native_module,
        "pause_native_pre_tool_for_approval",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Python reclassified the action")),
    )
    try:
        assert _review(worker, tmp_path / "guard") == {"policy_action": "review"}
    finally:
        worker.close()


def test_rust_approval_classification_selects_the_pause_boundary(tmp_path: Path, monkeypatch: Any) -> None:
    worker = HookWorker(store=GuardStore(tmp_path / "guard"), start_native_policy=False)
    monkeypatch.setattr(
        native_module,
        "native_or_daemon_edge",
        lambda *_args, **_kwargs: (_edge(requires_approval=True), False),
    )
    monkeypatch.setattr(native_module, "pause_native_pre_tool_for_approval", lambda *_args, **_kwargs: {"queued": True})
    try:
        assert _review(worker, tmp_path / "guard") == {"queued": True}
    finally:
        worker.close()


def test_rust_recording_only_classification_returns_the_edge_response(tmp_path: Path, monkeypatch: Any) -> None:
    worker = HookWorker(store=GuardStore(tmp_path / "guard"), start_native_policy=False)
    monkeypatch.setattr(
        native_module,
        "native_or_daemon_edge",
        lambda *_args, **_kwargs: (_edge(requires_approval=True, recording_only_response=True), False),
    )
    monkeypatch.setattr(
        native_module,
        "pause_native_pre_tool_for_approval",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Watch response entered approval")),
    )
    try:
        assert _watch_review(worker, tmp_path / "guard") == {"policy_action": "review"}
    finally:
        worker.close()


def test_rust_custom_rule_classification_selects_the_block_response(tmp_path: Path, monkeypatch: Any) -> None:
    worker = HookWorker(store=GuardStore(tmp_path / "guard"), start_native_policy=False)
    monkeypatch.setattr(
        native_module,
        "native_or_daemon_edge",
        lambda *_args, **_kwargs: (_edge(requires_approval=False, local_cli_rule_blocked=True), False),
    )
    monkeypatch.setattr(
        native_module,
        "pause_native_pre_tool_for_approval",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("custom block entered approval")),
    )
    try:
        assert _review(worker, tmp_path / "guard") == {"policy_action": "blocked-by-extension"}
    finally:
        worker.close()
