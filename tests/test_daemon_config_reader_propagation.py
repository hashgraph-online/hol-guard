"""Foundation reader propagation through existing posture and attention paths.

Foundation has no implementation-only native Codex continuation helper. These
regressions preserve its existing approval authority rather than importing it.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.config_source_io import GuardConfigSourceError, capture_guard_config
from codex_plugin_scanner.guard.daemon import hook_worker as worker_module
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.runtime.approval_attention import ApprovalAttentionCoordinator
from codex_plugin_scanner.guard.store import GuardStore

from .test_guard_approval_attention import _queue_operation


def _reject_workspace_reader(guard_home: Path, seen: list[Path]):
    def read(path: Path) -> dict[str, object]:
        seen.append(path)
        if path.parent != guard_home:
            raise GuardConfigSourceError("fixture_workspace_rejected")
        return {}

    return read


def _worker(store: GuardStore, monkeypatch: pytest.MonkeyPatch, reader, **kwargs) -> HookWorker:
    monkeypatch.setattr(worker_module, "native_mode", lambda: "off")
    monkeypatch.setattr(worker_module, "python_oracle_enabled", lambda: False)
    return HookWorker(
        store=store,
        wait_for_native_policy=False,
        publish_native_policy=False,
        config_reader=reader,
        **kwargs,
    )


def test_worker_keeps_explicit_reader_and_capture_with_terminal_posture_rejection(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".hol-guard.toml").write_text('mode = "observe"\nprotection_posture = "watch"\n')
    seen: list[Path] = []
    reader = _reject_workspace_reader(store.guard_home, seen)
    captures = []
    publisher = SimpleNamespace()

    def get_publisher(actual_store, *, config_capture):
        assert actual_store is store
        captures.append(config_capture)
        return publisher

    monkeypatch.setattr(worker_module, "get_native_policy_snapshot_publisher", get_publisher)
    worker = _worker(store, monkeypatch, reader, config_capture=capture_guard_config)
    assert worker.config_reader is reader
    assert worker.policy_snapshot_publisher is publisher
    assert captures == [capture_guard_config]
    with pytest.raises(GuardConfigSourceError, match="fixture_workspace_rejected"):
        worker._load_config(store.guard_home, workspace)
    seen.clear()
    monkeypatch.setattr(
        worker,
        "_review_pre_tool_native",
        lambda *_args, **_kwargs: {
            "decision": "deny",
            "minimum_action": "block",
            "policy_action": "block",
            "reason_code": "native_destructive_command",
            "reason": "Synthetic terminal native block.",
        },
    )
    response = worker._review_pre_tool_http(
        {"tool_name": "Bash", "tool_input": {"command": "rm -rf fixture"}},
        harness="cursor",
        home_dir=tmp_path,
        guard_home=store.guard_home,
        workspace=workspace,
    )
    assert response["policy_action"] == "block"
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert seen == [store.guard_home / "config.toml", workspace / ".ai-plugin-scanner-guard.toml"]


@pytest.mark.parametrize("reject_at_schedule", [True, False])
def test_attention_rejects_workspace_at_schedule_or_delayed_recheck(tmp_path, reject_at_schedule):
    store, runtime, result = _queue_operation(tmp_path, harness="pi", severity="medium")
    now = [100.0]
    opened: list[str] = []
    seen: list[Path] = []
    reject = [reject_at_schedule]

    def read(path: Path) -> dict[str, object]:
        seen.append(path)
        if path.parent == store.guard_home:
            return {"approval_surface_policy": "attention-aware", "approval_browser_delay_seconds": 20}
        if reject[0]:
            raise GuardConfigSourceError("fixture_workspace_rejected")
        return {}

    coordinator = ApprovalAttentionCoordinator(
        store=store,
        runtime=runtime,
        opener=lambda url: opened.append(url) or True,
        clock=lambda: now[0],
        config_reader=read,
    )

    def schedule():
        coordinator.schedule(
            operation_id=result["operation"]["operation_id"],
            requests=result["approval_requests"],
            browser_url="http://127.0.0.1:5474/requests/pending",
        )

    if reject_at_schedule:
        with pytest.raises(GuardConfigSourceError, match="fixture_workspace_rejected"):
            schedule()
    else:
        schedule()
        coordinator.process_due()
        assert opened == []
        now[0] += 20
        reject[0] = True
        seen.clear()
        with pytest.raises(GuardConfigSourceError, match="fixture_workspace_rejected"):
            coordinator.process_due()
    assert seen == [store.guard_home / "config.toml", tmp_path / "workspace" / ".ai-plugin-scanner-guard.toml"]
    assert opened == []
    assert coordinator._pending == {}


def test_child_constructs_scope_before_readiness_and_reuses_it(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.daemon import config_read_scope, hook_process_entrypoint

    guard_home = tmp_path / "guard"
    created = []
    observed = []
    factory = config_read_scope.HookConfigReadScope.for_guard_home

    def create(cls, home):
        scope = factory(home)
        created.append(scope)
        return scope

    def run(_request, **kwargs):
        observed.append(kwargs["config_scope"])
        return {"payload": {}, "reason_code": None}

    messages = iter([("review", {}), ("review", {}), ("stop", None)])
    sent = []

    def send(message):
        assert len(created) == 1
        sent.append(message)

    monkeypatch.setattr(config_read_scope.HookConfigReadScope, "for_guard_home", classmethod(create))
    monkeypatch.setattr(hook_process_entrypoint, "_run_resident_hook_request", run)
    connection = SimpleNamespace(send=send, recv=lambda: next(messages))
    hook_process_entrypoint._hook_evaluator_loop(
        connection, stores={}, hook_workers={}, configured_guard_home=str(guard_home)
    )
    assert sent[0] == ("ready", None)
    assert len(sent) == 3
    assert len(created) == 1
    assert len(observed) == 2 and all(scope is created[0] for scope in observed)


def test_child_scope_construction_failure_never_announces_ready(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.daemon import config_read_scope, hook_process_entrypoint

    sent = []

    def reject(cls, _home):
        raise GuardConfigSourceError("fixture_scope_construction_failed")

    monkeypatch.setattr(config_read_scope.HookConfigReadScope, "for_guard_home", classmethod(reject))
    connection = SimpleNamespace(send=sent.append)
    with pytest.raises(GuardConfigSourceError, match="fixture_scope_construction_failed"):
        hook_process_entrypoint._hook_evaluator_loop(
            connection, stores={}, hook_workers={}, configured_guard_home=str(tmp_path / "guard")
        )
    assert sent == []


def test_child_compatibility_initial_load_keeps_bound_reader(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.cli import commands_hook
    from codex_plugin_scanner.guard.daemon import hook_process_entrypoint
    from codex_plugin_scanner.guard.daemon.config_read_scope import HookConfigReadScope

    store = GuardStore(tmp_path / "guard")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    scope = HookConfigReadScope.for_guard_home(store.guard_home)
    observed = []

    def reject(self, path):
        assert self is scope
        observed.append(path)
        raise GuardConfigSourceError("fixture_child_scope_rejected")

    monkeypatch.setattr(HookConfigReadScope, "read_toml", reject)
    monkeypatch.setattr(hook_process_entrypoint, "_native_mode_requires_rust", lambda: False)
    monkeypatch.setattr(hook_process_entrypoint, "python_oracle_surface_enabled", lambda: True)
    monkeypatch.setattr(worker_module, "runtime_hook_event_name", lambda _payload: "SessionStart")
    monkeypatch.setattr(
        commands_hook, "_run_guard_hook_command", lambda *_args, **_kwargs: pytest.fail("rejected config reached CLI")
    )
    request = {
        "payload": {"hook_event_name": "SessionStart"},
        "harness": "claude-code",
        "home_dir": str(tmp_path),
        "guard_home": str(store.guard_home),
        "workspace": str(workspace),
    }
    with pytest.raises(GuardConfigSourceError, match="fixture_child_scope_rejected"):
        hook_process_entrypoint._run_resident_hook_request(
            request,
            stores={str(store.guard_home): store},
            hook_workers={},
            configured_guard_home=str(store.guard_home),
            config_scope=scope,
        )
    assert observed == [store.guard_home / "config.toml"]


def test_server_safe_roots_and_guard_home_use_construction_scope(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.daemon.config_read_scope import HookConfigReadScope
    from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler, _HookPathValidationError

    original, other = tmp_path / "original", tmp_path / "other"
    original.mkdir()
    other.mkdir()
    scope = HookConfigReadScope.for_guard_home(original)
    daemon = SimpleNamespace(hook_config_scope=scope, store=SimpleNamespace(guard_home=other))
    handler = object.__new__(_GuardDaemonHandler)
    monkeypatch.setattr(handler, "_daemon_server", lambda: daemon)
    assert handler._hook_safe_roots() is scope.allowed_roots
    assert handler._validated_hook_guard_home(str(original)) == str(scope.canonical_home)
    with pytest.raises(_HookPathValidationError):
        handler._validated_hook_guard_home(str(other))
