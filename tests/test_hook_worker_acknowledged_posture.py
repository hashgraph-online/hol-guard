"""Ordinary native delivery follows one acknowledged posture per request."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import config as config_module
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore


def _write_posture(guard_home: Path, posture: str) -> None:
    guard_home.mkdir(parents=True, exist_ok=True)
    mode = "observe" if posture == "watch" else "enforce"
    (guard_home / "config.toml").write_text(f'mode = "{mode}"\nprotection_posture = "{posture}"\n')


def _block_edge(event: str) -> dict[str, object]:
    return {
        "event_name": event,
        "harness": "pi",
        "result": {
            "decision": "deny",
            "minimum_action": "block",
            "model_output_action": "block",
            "policy_action": "block",
            "reason_code": "native_test_block",
            "reason": "Source fixture policy requires a block.",
        },
    }


@pytest.mark.parametrize("event", ["PreToolUse", "PostToolUse"])
@pytest.mark.parametrize("posture", ["protected", "watch"])
@pytest.mark.parametrize("mode", ["enforce", "observe", None])
def test_native_delivery_uses_one_acknowledged_binding_without_config_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str | None,
    posture: str,
    event: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    _write_posture(guard_home, posture)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".hol-guard.toml").write_text('sandbox_analysis = "strict"\n')
    worker = HookWorker(store=GuardStore(guard_home), publish_native_policy=False, wait_for_native_policy=False)
    binding: dict[str, object] = {
        "generation": 7,
        "policy_digest": "a" * 64,
        "runtime_identity": "b" * 64,
        "mode": mode,
    }
    expected_binding = binding if mode is not None else None
    binding_calls = []
    native_calls: list[dict[str, object]] = []
    routes: list[str] = []
    reads = {"loader": 0, "home": 0, "workspace": 0}
    original_loader = config_module.load_guard_config
    original_open = Path.open

    def prepare(scope: Path | None, **kwargs: object) -> dict[str, object] | None:
        binding_calls.append((scope, kwargs))
        return expected_binding

    def evaluate(**kwargs: object) -> dict[str, object] | None:
        native_calls.append(kwargs)
        # Production rejects missing bindings before resident IPC. These
        # synthetic edges exercise delivery only, never installed authority.
        return _block_edge(event) if kwargs["policy_snapshot"] is not None else None

    def loaded(*args: Any, **kwargs: Any) -> Any:
        reads["loader"] += 1
        return original_loader(*args, **kwargs)

    def opened(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == guard_home / "config.toml":
            reads["home"] += 1
        elif path in (workspace / ".hol-guard.toml", workspace / ".ai-plugin-scanner-guard.toml"):
            reads["workspace"] += 1
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(worker, "_native_policy_snapshot", prepare)
    monkeypatch.setattr(worker, "_review_raw_hook_native", evaluate)
    monkeypatch.setattr(worker.metrics, "record_route", routes.append)
    monkeypatch.setattr(config_module, "load_guard_config", loaded)
    monkeypatch.setattr(Path, "open", opened)
    try:
        response = worker._review_native_edge(
            payload={"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}, "tool_response": "fixture output"},
            harness="pi",
            event_name=event,
            default_harness="pi",
            home_dir=tmp_path,
            guard_home=guard_home,
            workspace=workspace,
            deadline=None,
        )
    finally:
        worker.close()
        worker.policy_snapshot_publisher.close()

    assert len(binding_calls) == len(native_calls) == 1
    assert binding_calls == [(workspace, {"deadline": None})]
    assert native_calls[0]["policy_snapshot"] is expected_binding
    assert native_calls[0]["observe_mode"] is (mode == "observe")
    assert reads == {"loader": 0, "home": 0, "workspace": 0}
    if mode is None:
        assert routes == ["native_fail_safe"]
        assert response["reason_code"] == (
            "native_pre_tool_unavailable" if event == "PreToolUse" else "native_post_tool_unavailable"
        )
        assert response["policy_action"] == ("warn" if event == "PreToolUse" else "allow")
    else:
        assert routes == ["native_resident"]
        assert response["policy_action"] == ("warn" if mode == "observe" else "block")


def test_unacknowledged_watch_edit_cannot_skip_enforcing_command_fence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_worker_native as native_module

    guard_home = tmp_path / "guard-home"
    _write_posture(guard_home, "watch")
    worker = HookWorker(store=GuardStore(guard_home), publish_native_policy=False, wait_for_native_policy=False)
    binding = {"mode": "enforce", "command_extensions_bound": True}
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda *_args, **_kwargs: binding)
    fence_inputs: list[Mapping[str, object]] = []

    def unavailable_fence(**kwargs: object) -> Any:
        fence_inputs.append(kwargs)
        raise OSError("source fixture cannot acquire the control lease")

    def unexpected_native(**_kwargs: object) -> None:
        raise AssertionError("an unavailable enforcing lease must not execute native review")

    monkeypatch.setattr(native_module, "native_review_fence", unavailable_fence)
    monkeypatch.setattr(worker, "_review_raw_hook_native", unexpected_native)
    try:
        response = worker._review_native_edge(
            payload={"tool_name": "Bash", "tool_input": {"command": "ollama push fixture"}},
            harness="pi",
            event_name="PreToolUse",
            default_harness="pi",
            home_dir=tmp_path,
            guard_home=guard_home,
            workspace=None,
            deadline=None,
        )
    finally:
        worker.close()
        worker.policy_snapshot_publisher.close()

    assert len(fence_inputs) == 1
    assert fence_inputs[0]["recording_only"] is False
    assert fence_inputs[0]["policy_snapshot"] is binding
    assert response["reason_code"] == "native_command_control_fence_unavailable"
