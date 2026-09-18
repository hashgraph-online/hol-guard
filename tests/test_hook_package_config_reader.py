"""Explicit hook readers reach package policy and local approval reloads."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config as config_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook_native_authority as native_hook
from codex_plugin_scanner.guard.cli import commands_hook_runtime_eval as runtime_hook
from codex_plugin_scanner.guard.cli.commands_support_observe_queue import queue_observe_mode_request
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.config_source_io import CapturedGuardConfig, GuardConfigSourceError
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as package_eval
from codex_plugin_scanner.guard.runtime.package_intent_common import (
    PackageIntent,
    build_package_request_artifact,
    js_target,
)
from codex_plugin_scanner.guard.runtime.runner import GuardSyncNotConfiguredError
from codex_plugin_scanner.guard.runtime.workspace_path_guard import WorkspaceInputSnapshotError
from codex_plugin_scanner.guard.store import GuardStore


def _artifact(*, lockfile: bool = False) -> GuardArtifact:
    return build_package_request_artifact(
        "codex",
        PackageIntent(
            package_manager="npm",
            intent_kind="install",
            command_tokens=("npm", "install", "reader-fixture@^1.0.0"),
            redacted_command="npm install reader-fixture@^1.0.0",
            targets=(js_target("reader-fixture@^1.0.0"),),
            manifest_paths=(),
            lockfile_paths=("package-lock.json",) if lockfile else (),
            flags=(),
            notes=(),
        ),
        config_path="codex.json",
        source_scope="project",
    )


def _paths(store: GuardStore, workspace: Path) -> list[Path]:
    return [
        store.guard_home / "config.toml",
        workspace / ".ai-plugin-scanner-guard.toml",
        workspace / ".hol-guard.toml",
    ]


@pytest.mark.parametrize("route", ["unidentified", "incomplete", "snapshot_error"])
@pytest.mark.parametrize("scoped", [False, True])
def test_public_package_boundary_retains_default_and_scoped_policy(tmp_path, monkeypatch, route, scoped):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    reads = []

    def read(path):
        reads.append(path)
        # The existing loader keeps this home-only policy out of workspace overrides.
        return {"security_level": "strict"} if path.parent == store.guard_home else {}

    if scoped:
        monkeypatch.setattr(config_module, "_read_toml", lambda _path: pytest.fail("unscoped config read"))
    monkeypatch.setattr(package_eval, "_urlopen_json_with_timeout_retry", lambda **_kwargs: {"versions": []})
    if route == "incomplete":
        (workspace / "package-lock.json").write_text("{broken", encoding="utf-8")
    elif route == "snapshot_error":

        def rejected_input(*_args, **_kwargs):
            raise WorkspaceInputSnapshotError(
                "package-lock.json", "fixture_changed_input", source_hash="a" * 64, bytes_observed=12, byte_limit=10
            )

        monkeypatch.setattr(package_eval, "_evaluation_targets", rejected_input)
    result = package_eval.evaluate_package_request_artifact(
        artifact=_artifact(lockfile=route == "incomplete"),
        store=store,
        workspace_dir=workspace,
        now="2026-05-19T00:00:00Z",
        config_reader=read if scoped else None,
    )
    assert result.decision == ("block" if scoped else "ask")
    assert reads == (_paths(store, workspace) if scoped else [])
    assert package_eval._LOCKFILE_PARSE_CACHE.get() is None


def test_cloud_unpaid_failure_consults_scoped_current_policy_once(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    reads = []

    def read(path):
        reads.append(path)
        return {"security_level": "strict"}

    def missing_auth(*_args, **_kwargs):
        raise GuardSyncNotConfiguredError("fixture")

    monkeypatch.setattr(package_eval, "_resolve_guard_sync_auth_context", missing_auth)
    monkeypatch.setattr(
        package_eval, "resolve_package_firewall_entitlement", lambda _store: {"reason": "paid_guard_cloud_required"}
    )
    monkeypatch.setattr(config_module, "_read_toml", lambda _path: pytest.fail("unscoped config read"))
    result, fallback = package_eval._evaluate_with_cloud(
        artifact=_artifact(),
        targets=package_eval._targets_from_artifact(_artifact()),
        workspace_dir=workspace,
        workspace_id="fixture-workspace",
        workspace_fingerprint="fixture-fingerprint",
        bundle_meta=None,
        bundle_defer_eligible=False,
        bundle_decision=None,
        store=store,
        config_reader=read,
    )
    assert result is not None and result.decision == "block"
    assert fallback is None
    assert reads == _paths(store, workspace)


def test_runtime_package_boundary_propagates_reader_rejection(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    reads = []

    def reject(path):
        reads.append(path)
        raise GuardConfigSourceError("fixture_reader_rejected")

    monkeypatch.setattr(package_eval, "_urlopen_json_with_timeout_retry", lambda **_kwargs: {"versions": []})
    monkeypatch.setattr(config_module, "_read_toml", lambda _path: pytest.fail("unscoped config read"))
    with pytest.raises(GuardConfigSourceError, match="fixture_reader_rejected"):
        runtime_hook._evaluate_runtime_artifact_hook(
            argparse.Namespace(harness="codex", json=True),
            action_envelope=None,
            config=GuardConfig(guard_home=store.guard_home, workspace=workspace),
            context=HarnessContext(tmp_path, workspace, store.guard_home),
            data_flow_signals=(),
            guard_home=store.guard_home,
            payload={"hook_event_name": "PreToolUse"},
            runtime_artifact=_artifact(),
            runtime_workspace=workspace,
            store=store,
            config_reader=reject,
        )
    assert reads == [store.guard_home / "config.toml"]
    assert package_eval._LOCKFILE_PARSE_CACHE.get() is None


def test_native_worker_and_grok_wait_receive_reader_and_unchanged_budget(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    events = []

    def read(path):
        events.append(("read", path))
        return {"approval_wait_timeout_seconds": 17}

    def capture(_path):
        return CapturedGuardConfig(b"", None)

    class Worker:
        def __init__(self, **kwargs):
            assert kwargs["config_reader"] is read
            assert kwargs["config_capture"] is capture
            assert kwargs["wait_for_native_policy"] is False
            assert kwargs["publish_native_policy"] is False
            events.append(("worker",))

        def review_http_payload(self, **_kwargs):
            return {"policy_action": "review"}

        def close(self):
            events.append(("close",))

    class Writer:
        def __init__(self, **_kwargs):
            pass

        def stop(self, *, timeout_seconds):
            assert timeout_seconds == 0.25
            events.append(("stop",))

    def wait(result, **kwargs):
        assert kwargs["timeout_seconds"] == 17
        events.append(("wait",))
        return result

    monkeypatch.setattr(native_hook, "HookWorker", Worker)
    monkeypatch.setattr(native_hook, "RuntimeHookEvidenceWriter", Writer)
    monkeypatch.setattr(native_hook, "_native_mode_requires_rust", lambda: True)
    monkeypatch.setattr(native_hook, "apply_grok_pretool_approval_wait", wait)
    monkeypatch.setattr(native_hook, "_emit", lambda *_args: None)
    monkeypatch.setattr(config_module, "_read_toml", lambda _path: pytest.fail("unscoped config read"))
    result = native_hook.try_native_or_source_ref_hook(
        argparse.Namespace(harness="grok", json=True),
        config=None,
        context=HarnessContext(tmp_path, workspace, store.guard_home),
        payload={"hook_event_name": "PreToolUse"},
        runtime_workspace=workspace,
        store=store,
        config_reader=read,
        config_capture=capture,
    )
    assert result == 0
    assert events == [
        ("worker",),
        ("close",),
        ("stop",),
        *[("read", path) for path in _paths(store, workspace)],
        ("wait",),
    ]


def test_observe_queue_preserves_reader_through_real_local_approval(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard import approvals

    store = GuardStore(tmp_path / "guard-home")
    readers = []
    original = approvals.continuation_offer_payload

    def read(_path):
        return {}

    def bind(*args, **kwargs):
        readers.append(kwargs["config_reader"])
        return original(*args, **kwargs)

    monkeypatch.setattr(approvals, "continuation_offer_payload", bind)
    queued = queue_observe_mode_request(
        action_envelope=None,
        artifact=_artifact(),
        artifact_hash="fixture-hash",
        changed_fields=["package_request"],
        executable_action="allow",
        observed_policy_action="block",
        redaction_level="full",
        risk_summary="Fixture observation",
        scanner_evidence=(),
        store=store,
        config_reader=read,
    )
    assert len(queued) == 1
    assert readers == [read]
    assert queued[0]["policy_action"] == "require-reapproval"
