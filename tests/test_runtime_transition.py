from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    require_high_risk,
    update_settings,
)
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity
from codex_plugin_scanner.guard.runtime_transition import (
    RuntimeTransition,
    TransitionError,
    TransitionFile,
    TransitionInstall,
    TransitionPlan,
    assert_transition_mutation_allowed,
)
from codex_plugin_scanner.guard.runtime_transition_admission import (
    NativeProtectionAdmission,
    _seal_verified_admission,
)


class FixtureAuthority:
    def __init__(self):
        self.key = os.urandom(32)

    def _policy_integrity_secret_material(self, *, create):
        assert create is False
        return self.key, "isolated-policy-key"


@pytest.fixture
def transition(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from codex_plugin_scanner.guard.cli import commands_lifecycle_gate

    home = tmp_path / "guard-home"
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: home)
    bindings = tmp_path / "bindings.json"
    pointer = tmp_path / "current.json"
    bindings.write_bytes(b"previous hooks")
    pointer.write_bytes(b"previous pointer")
    bindings.chmod(0o600)
    pointer.chmod(0o600)
    previous = {
        "version": "3.12.3",
        "source_commit": "a" * 40,
        "target": "fixture",
        "format": "onefile",
        "sha256": "a" * 64,
        "generation": "a" * 64,
        "path": str(tmp_path / "previous-core"),
    }
    candidate = {
        **previous,
        "version": "3.13.1",
        "format": "onedir",
        "generation": "b" * 64,
        "path": str(tmp_path / "candidate-core"),
    }
    native_runtimes = {}
    native_files = []
    for side in ("predecessor", "candidate"):
        path = tmp_path / (side + "-native-runtime")
        data = side.encode()
        path.write_bytes(data)
        path.chmod(0o700)
        metadata = path.stat()
        native_runtimes[side] = {
            "path": str(path),
            "size": len(data),
            "mtime_ns": metadata.st_mtime_ns,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        native_files.append(
            TransitionFile.artifact_dependency(
                {
                    **native_runtimes[side],
                    "mode": 0o700,
                    "owner_uid": metadata.st_uid,
                    "role": "artifact",
                }
            )
        )
    plan = TransitionPlan(
        "fixture-operation",
        home,
        previous,
        candidate,
        (
            TransitionFile(bindings, b"previous hooks", b"candidate hooks"),
            TransitionFile(pointer, b"previous pointer", b"candidate pointer", kind="selection"),
            *native_files,
        ),
        time.time() + 60,
        native_runtimes=native_runtimes,
    )
    runtime = RuntimeTransition(home, FixtureAuthority())
    with codex_install_transaction(home, bindings, actor="runtime-test"):
        yield runtime, plan, bindings, pointer


def begin(runtime, plan):
    runtime.begin(plan, authority_home=plan.guard_home, grant=None)


@pytest.mark.parametrize("operation", ["activate", "recover"])
def test_coordinator_excludes_cross_home_writers_for_every_binding_target(transition, tmp_path, operation):
    from concurrent.futures import ThreadPoolExecutor

    from codex_plugin_scanner.guard.runtime_transition_coordinator import RuntimeTransitionCoordinator

    runtime, original, *_ = transition
    config = tmp_path / "other-config" / "config.toml"
    config.parent.mkdir()
    config.write_bytes(b"previous config")
    config.chmod(0o600)
    plan = replace(original, files=(*original.files, TransitionFile(config, b"previous config", b"candidate config")))
    foreign_home = tmp_path / "foreign-guard"

    def competing_publication():
        with codex_install_transaction(foreign_home, config, actor="foreign-writer", deadline=time.monotonic() + 0.15):
            return "admitted"

    class Driver:
        def stop(self, artifact, *, deadline_monotonic):
            with ThreadPoolExecutor(max_workers=1) as executor:
                competing = executor.submit(competing_publication)
                with pytest.raises(TimeoutError, match="Codex lifecycle transaction deadline exceeded"):
                    competing.result(timeout=5)
            assert not foreign_home.exists(), "refuse the competing owner before any home publication"

        def start(self, artifact, *, deadline_monotonic):
            pass

        def observe_protection(self, artifact, operation_id, *, deadline_monotonic):
            return proof(plan, artifact["generation"])

    coordinator = RuntimeTransitionCoordinator(runtime, Driver())
    if operation == "activate":
        result = coordinator.activate(plan, authority_home=plan.guard_home, grant=None)
        assert result.phase == "Committed"
        assert config.read_bytes() == b"candidate config"
    else:
        begin(runtime, plan)
        runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
        result = coordinator.recover(plan.operation_id, deadline_monotonic=time.monotonic() + 5)
        assert result.phase == "FailedWithVerifiedRollback"
        assert config.read_bytes() == b"previous config"


@pytest.mark.parametrize("operation", ["activate", "recover"])
def test_busy_binding_target_refuses_before_lifecycle_or_transition_mutation(transition, tmp_path, operation):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from codex_plugin_scanner.guard.runtime_transition_coordinator import RuntimeTransitionCoordinator

    runtime, original, bindings, pointer = transition
    config = tmp_path / "busy-config" / "config.toml"
    config.parent.mkdir()
    config.write_bytes(b"previous config")
    config.chmod(0o600)
    plan = replace(original, files=(*original.files, TransitionFile(config, b"previous config", b"candidate config")))
    if operation == "recover":
        begin(runtime, plan)
        runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    before = {path: path.read_bytes() if path.exists() else None for path in (runtime.path, bindings, pointer, config)}
    ready, release = Event(), Event()

    def foreign_writer():
        with codex_install_transaction(tmp_path / "foreign-guard", config, actor="foreign-writer"):
            ready.set()
            assert release.wait(timeout=5)

    class Driver:
        def stop(self, *args, **kwargs):
            pytest.fail("busy target must refuse before daemon retirement")

        def start(self, *args, **kwargs):
            pytest.fail("busy target must refuse before daemon launch")

        def observe_protection(self, *args, **kwargs):
            pytest.fail("busy target must refuse before protection observation")

    with ThreadPoolExecutor(max_workers=1) as executor:
        writer = executor.submit(foreign_writer)
        try:
            assert ready.wait(timeout=3)
            coordinator = RuntimeTransitionCoordinator(runtime, Driver())
            with pytest.raises(TransitionError, match="configuration_target_busy"):
                if operation == "activate":
                    coordinator.activate(plan, authority_home=plan.guard_home, grant=None)
                else:
                    coordinator.recover(plan.operation_id, deadline_monotonic=time.monotonic() + 3)
            assert {path: path.read_bytes() if path.exists() else None for path in before} == before
        finally:
            release.set()
            writer.result(timeout=5)


def test_recovery_plan_reconstructs_signed_subject_without_forward_grant(transition):
    runtime, plan, *_ = transition
    begin(runtime, plan)
    reopened = RuntimeTransition(runtime.home, runtime.authority)
    recovered = reopened.recovery_plan(plan.operation_id)
    assert recovered.payload() == plan.payload()
    assert recovered.subject() == plan.subject()
    assert reopened._forward_grant is None
    with pytest.raises(TransitionError, match="operation_superseded"):
        reopened.recovery_plan("another-operation")


def test_recovery_plan_rejects_changed_signed_subject(transition):
    runtime, plan, *_ = transition
    begin(runtime, plan)
    record = runtime._read(plan.operation_id)
    record["authorized_subject"] = "f" * 64
    runtime._write(record)
    with pytest.raises(TransitionError, match="plan_context_mismatch"):
        runtime.recovery_plan(plan.operation_id)


def test_inverse_budget_expires_inside_artifact_hash_without_grant(transition, monkeypatch):
    import codex_plugin_scanner.guard.runtime_transition as module

    runtime, plan, bindings, _ = transition
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    deadline = time.monotonic() + 10
    actual_read = os.read

    def expire_after_read(descriptor, size):
        chunk = actual_read(descriptor, size)
        monkeypatch.setattr(module.time, "monotonic", lambda: deadline + 1)
        return chunk

    monkeypatch.setattr(module.os, "read", expire_after_read)
    with module.inverse_recovery_budget(deadline), pytest.raises(TransitionError, match="deadline_exceeded"):
        runtime.restore_files(plan.operation_id, first_cause="interrupted")
    assert runtime.status(plan.operation_id).phase == "RecoveryRequired"
    assert bindings.read_bytes() == b"candidate hooks"
    assert module._INVERSE_DEADLINE.get() is None


def test_desktop_transition_status_is_authenticated_and_redacted(transition, monkeypatch, tmp_path):
    import argparse
    import io
    import uuid

    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.cli import desktop_runtime_transition as module

    runtime, plan, *_ = transition
    plan = replace(plan, operation_id=str(uuid.uuid4()))
    begin(runtime, plan)
    monkeypatch.setattr(module, "RuntimeTransition", lambda *args, **kwargs: runtime)
    context = HarnessContext(tmp_path, None, runtime.home)
    args = argparse.Namespace(
        desktop_command="transition-status", operation_id=plan.operation_id, deadline_epoch=time.time() + 10
    )
    output = io.StringIO()
    assert (
        module.run_desktop_runtime_transition(args, context=context, store=runtime.authority, output_stream=output) == 0
    )
    payload = json.loads(output.getvalue())
    assert payload["phase"] == "AuthorizedForExactTransition"
    assert set(payload) == {"schema", "operation_id", "phase", "first_cause", "recovery_causes", "artifact_generation"}
    assert payload["artifact_generation"] == plan.candidate["generation"]
    assert "previous hooks" not in output.getvalue()
    assert str(runtime.home) not in output.getvalue()
    args.operation_id = str(uuid.uuid4())
    output = io.StringIO()
    assert (
        module.run_desktop_runtime_transition(args, context=context, store=runtime.authority, output_stream=output) == 1
    )
    assert json.loads(output.getvalue())["reason_code"] == "operation_superseded"


def test_desktop_transition_observer_refuses_uncovered_harness(transition, tmp_path):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.cli.desktop_runtime_transition import _codex_observer

    runtime, plan, *_ = transition
    store, plan = with_install_store(runtime, plan, [])
    with pytest.raises(TransitionError, match="installed_hook_observer_unavailable"):
        _codex_observer(plan, HarnessContext(tmp_path, None, plan.guard_home), store)


def test_desktop_transition_observer_uses_recorded_binding_and_native_identity(transition, monkeypatch, tmp_path):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.cli import desktop_runtime_transition as module

    runtime, plan, bindings, _ = transition
    plan = core_dependencies(plan)
    previous = install_row("codex", "previous")
    candidate = install_row("codex", "candidate")
    for snapshot in (previous, candidate):
        snapshot["manifest"]["managed_hook_config_path"] = str(bindings)
    plan = replace(plan, managed_installs=(TransitionInstall("codex", previous, candidate),))
    store, plan = with_install_store(runtime, plan, list(plan.managed_installs))
    calls = []

    def observe(**kwargs):
        calls.append(kwargs)
        return proof(plan, kwargs["artifact_generation"], installed=True)

    monkeypatch.setattr(module, "observe_configured_codex_hook", observe)
    observer = module._codex_observer(plan, HarnessContext(tmp_path, None, plan.guard_home), store)
    deadline = time.monotonic() + 10
    observer(plan.predecessor, {}, plan.operation_id, deadline_monotonic=deadline)
    assert len(calls) == 1
    call = calls[0]
    assert call["config_path"] == bindings and call["guard_home"] == plan.guard_home
    assert call["workspace"] == tmp_path and call["deadline_monotonic"] == deadline
    assert call["expected_runtime"].sha256 == plan.native_runtimes["predecessor"]["sha256"]
    assert call["receipt_store"] is store
    with pytest.raises(TransitionError, match="plan_context_mismatch"):
        observer(plan.predecessor, {}, "another-operation", deadline_monotonic=deadline)
    assert len(calls) == 1


@pytest.mark.parametrize("failure", [None, "stop", "observe", "expired"])
def test_reopened_coordinator_recovers_only_inverse_with_one_deadline(transition, failure):
    from codex_plugin_scanner.guard.runtime_transition_coordinator import RuntimeTransitionCoordinator

    runtime, plan, bindings, pointer = transition
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    runtime.publish(plan.operation_id, "HooksPrepared")
    runtime.prepare_recovery(plan.operation_id, first_cause="original_failure")
    reopened = RuntimeTransition(runtime.home, runtime.authority)
    events = []
    deadline = time.monotonic() + (0 if failure == "expired" else 10)

    class Driver:
        def stop(self, artifact, *, deadline_monotonic):
            assert artifact == plan.candidate and deadline_monotonic == deadline
            events.append("stop_candidate")
            if failure == "stop":
                raise TransitionError("candidate_retirement_unconfirmed")

        def start(self, artifact, *, deadline_monotonic):
            assert artifact == plan.predecessor and deadline_monotonic == deadline
            assert bindings.read_bytes() == b"previous hooks"
            assert pointer.read_bytes() == b"previous pointer"
            events.append("start_previous")

        def observe_protection(self, artifact, operation_id, *, deadline_monotonic):
            assert artifact == plan.predecessor and operation_id == plan.operation_id
            assert deadline_monotonic == deadline
            events.append("observe_previous")
            if failure == "observe":
                raise TransitionError("installed_hook_proof_missing")
            return proof(plan, plan.predecessor["generation"])

    coordinator = RuntimeTransitionCoordinator(reopened, Driver())
    if failure == "expired":
        with pytest.raises(TransitionError, match="deadline_exceeded"):
            coordinator.recover(plan.operation_id, deadline_monotonic=deadline)
        assert events == []
        assert bindings.read_bytes() == b"candidate hooks"
        return
    status = coordinator.recover(plan.operation_id, deadline_monotonic=deadline)
    assert status.first_cause == "original_failure"
    assert reopened._forward_grant is None
    if failure is None:
        assert status.phase == "FailedWithVerifiedRollback"
        assert events == ["stop_candidate", "start_previous", "observe_previous"]
        with pytest.raises(TransitionError, match="terminal_transition"):
            coordinator.recover(plan.operation_id, deadline_monotonic=deadline)
    else:
        assert status.phase == "RecoveryRequired"
        assert status.recovery_causes[-1]["code"] == (
            "candidate_retirement_unconfirmed" if failure == "stop" else "installed_hook_proof_missing"
        )
        if failure == "stop":
            assert events == ["stop_candidate"]


@pytest.mark.parametrize("side", ["candidate", "predecessor"])
def test_daemon_binding_uses_planned_executable_digest_instead_of_artifact_archive(transition, side):
    from codex_plugin_scanner.guard.daemon.live_identity import DaemonArtifactBinding

    _, plan, *_ = transition
    artifact = plan.candidate if side == "candidate" else plan.predecessor
    with pytest.raises(TransitionError, match="daemon_artifact_dependency_missing"):
        DaemonArtifactBinding.from_transition_plan(plan, side)
    path = Path(artifact["path"])
    data = b"isolated planned executable"
    path.write_bytes(data)
    path.chmod(0o700)
    digest = hashlib.sha256(data).hexdigest()
    dependency = TransitionFile.artifact_dependency(
        {
            "path": str(path),
            "mode": 0o700,
            "sha256": digest,
            "size": len(data),
            "owner_uid": path.stat().st_uid,
            "role": "artifact",
        }
    )
    plan = replace(plan, files=(*plan.files, dependency))
    binding = DaemonArtifactBinding.from_transition_plan(plan, side)
    assert binding.executable_sha256 == digest and binding.executable_sha256 != artifact["sha256"]
    assert binding.executable == path and binding.package_version == artifact["version"]


def proof(plan, generation, *, installed=False):
    # Trusted protocol fixture only. Producer and integration tests separately
    # require actual Rust decisions. This bypass is never a production input.
    side = "candidate" if generation == plan.candidate["generation"] else "predecessor"
    identity = plan.native_runtimes[side]
    native = NativeRuntimeIdentity(Path(identity["path"]), identity["size"], identity["mtime_ns"], identity["sha256"])
    return _seal_verified_admission(
        NativeProtectionAdmission(
            plan.operation_id,
            generation,
            native,
            1,
            "a" * 64,
            {"unit_protocol_fixture": "allow"},
            {"unit_protocol_fixture": "deny"},
            plan.guard_home.resolve(),
            time.monotonic(),
            {"schema": "hol-guard.installed-hook-evidence.v1", "harness": "codex", "unit_protocol_fixture": True}
            if installed
            else None,
        )
    )


def install_row(harness, generation):
    return {
        "harness": harness,
        "active": True,
        "workspace": None,
        "manifest": {"generation": generation},
        "updated_at": "2026-09-30T00:00:00Z",
    }


def with_install_store(runtime, plan, changes):
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(runtime.home)
    for change in changes:
        if change.before is not None:
            row = change.before
            store.set_managed_install(
                row["harness"], row["active"], row["workspace"], row["manifest"], row["updated_at"]
            )
    runtime.install_store = store
    return store, replace(plan, managed_installs=tuple(changes))


@pytest.mark.parametrize("previous_exists", [False, True])
def test_install_rows_publish_and_restore_with_files(transition, previous_exists):
    runtime, plan, bindings, pointer = transition
    before = install_row("codex", "previous") if previous_exists else None
    after = install_row("codex", "candidate")
    store, plan = with_install_store(runtime, plan, [TransitionInstall("codex", before, after)])
    unrelated = install_row("claude", "unrelated")
    store.set_managed_install("claude", True, None, unrelated["manifest"], unrelated["updated_at"])
    begin(runtime, plan)
    with pytest.raises(TransitionError, match="pending_transition"):
        store.set_managed_install("codex", False, None, {}, "foreign")
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    assert store.get_managed_install("codex") == after
    runtime.publish(plan.operation_id, "HooksPrepared")
    runtime.restore_files(plan.operation_id, first_cause="candidate failed")
    assert store.get_managed_install("codex") == before
    assert store.get_managed_install("claude") == unrelated
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"
    runtime.finish_rollback(plan.operation_id, functional_proof=proof(plan, plan.predecessor["generation"]))
    runtime.retire(plan.operation_id)


def test_foreign_install_row_preserves_all_files_and_rows(transition):
    runtime, plan, bindings, pointer = transition
    changes = [
        TransitionInstall(harness, install_row(harness, "previous"), install_row(harness, "candidate"))
        for harness in ("codex", "claude")
    ]
    store, plan = with_install_store(runtime, plan, changes)
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    runtime.publish(plan.operation_id, "HooksPrepared")
    # Represent a non-cooperating writer. The production API rejects pending transitions.
    with store._connect() as connection:
        connection.execute("update managed_installs set updated_at = 'foreign' where harness = 'claude'")
    with pytest.raises(TransitionError, match="managed_install_generation_changed"):
        runtime.restore_files(plan.operation_id, first_cause="candidate failed")
    assert bindings.read_bytes() == b"candidate hooks"
    assert pointer.read_bytes() == b"candidate pointer"
    assert store.get_managed_install("codex") == changes[0].after
    assert store.get_managed_install("claude")["updated_at"] == "foreign"
    assert runtime._read(plan.operation_id)["phase"] == "RecoveryRequired"


def test_interrupted_file_publication_rolls_back_rows_then_recovers(transition, monkeypatch):
    import codex_plugin_scanner.guard.runtime_transition as module

    runtime, plan, bindings, pointer = transition
    before, after = install_row("codex", "previous"), install_row("codex", "candidate")
    store, plan = with_install_store(runtime, plan, [TransitionInstall("codex", before, after)])
    begin(runtime, plan)
    real_write = module.atomic_write_bytes

    def interrupted_write(path, data, **kwargs):
        real_write(path, data, **kwargs)
        if path == bindings:
            raise OSError("interrupted after durable file publication")

    monkeypatch.setattr(module, "atomic_write_bytes", interrupted_write)
    with pytest.raises(OSError, match="interrupted"):
        runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    assert bindings.read_bytes() == b"candidate hooks"
    assert store.get_managed_install("codex") == before
    monkeypatch.setattr(module, "atomic_write_bytes", real_write)
    runtime.restore_files(plan.operation_id, first_cause="publication interrupted")
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"
    assert store.get_managed_install("codex") == before


def test_shared_launcher_preparation_has_no_home_side_effects(tmp_path: Path):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.shims import prepare_guard_shim

    ctx = HarnessContext(home_dir=tmp_path, workspace_dir=None, guard_home=tmp_path / "new-guard")
    prepared = prepare_guard_shim("gemini", ctx)
    assert not ctx.guard_home.exists()
    assert len(prepared.files) == 2
    assert all(change.before is None and change.after for change in prepared.files)


def test_prepared_launchers_join_signed_publication_and_exact_inverse(transition):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.shims import install_guard_shim, prepare_guard_shim

    runtime, plan, _, _ = transition
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=None, guard_home=runtime.home)
    previous = install_guard_shim("gemini", ctx)
    posix = Path(previous["shim_path"])
    windows = Path(previous["windows_shim_path"])
    old_posix, old_windows = posix.read_bytes(), windows.read_bytes()
    candidate_ctx = replace(ctx, workspace_dir=ctx.home_dir / "candidate-workspace")
    prepared = prepare_guard_shim("gemini", candidate_ctx)
    assert posix.read_bytes() == old_posix and windows.read_bytes() == old_windows
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    assert posix.read_bytes() == prepared.files[0].after
    assert windows.read_bytes() == prepared.files[1].after
    assert b"candidate-workspace" in posix.read_bytes()
    runtime.restore_files(plan.operation_id, first_cause="candidate protection failed")
    assert posix.read_bytes() == old_posix and windows.read_bytes() == old_windows


def test_prepared_launcher_refuses_symlink_before_any_write(tmp_path: Path):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
    from codex_plugin_scanner.guard.shims import prepare_guard_shim

    ctx = HarnessContext(home_dir=tmp_path, workspace_dir=None, guard_home=tmp_path / "guard")
    outside = tmp_path / "unrelated"
    outside.write_bytes(b"user content")
    shim = ctx.guard_home / "bin/guard-gemini"
    shim.parent.mkdir(parents=True)
    shim.symlink_to(outside)
    with pytest.raises(CodexHookIntegrityError):
        prepare_guard_shim("gemini", ctx)
    assert outside.read_bytes() == b"user content"
    assert not shim.with_suffix(".cmd").exists()


def test_native_claude_binding_plan_restores_user_hooks_and_launchers(transition):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter

    runtime, plan, _, _ = transition
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=None, guard_home=runtime.home)
    settings = ctx.home_dir / ".claude/settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps(
            {"theme": "user-theme", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "user-stop-hook"}]}]}}
        )
    )
    settings.chmod(0o600)
    adapter = ClaudeCodeHarnessAdapter()
    adapter.install(ctx)
    previous = settings.read_bytes()
    prepared = adapter.prepare_install(replace(ctx, workspace_dir=ctx.home_dir / "candidate-workspace"))
    assert settings.read_bytes() == previous
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    candidate = settings.read_bytes()
    assert b"candidate-workspace" in candidate
    assert json.loads(candidate)["theme"] == "user-theme"
    assert b"user-stop-hook" in candidate
    with pytest.raises(TransitionError, match="pending_transition"):
        adapter.refresh_runtime_hook_urls(ctx)
    assert settings.read_bytes() == candidate
    runtime.restore_files(plan.operation_id, first_cause="candidate protected hook failed")
    assert settings.read_bytes() == previous
    for change in prepared.files:
        assert change.path.read_bytes() == change.before


def test_native_kimi_plan_restores_config_and_launchers_after_rebind(transition):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.kimi import KimiHarnessAdapter

    runtime, plan, _, _ = transition
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=None, guard_home=runtime.home)
    config = ctx.home_dir / ".kimi-code/config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('# user configuration\nmodel = "user-model"\n')
    config.chmod(0o600)
    adapter = KimiHarnessAdapter()
    adapter.install(ctx)
    previous = config.read_bytes()
    prepared = adapter.prepare_install(replace(ctx, workspace_dir=ctx.home_dir / "candidate-workspace"))
    assert config.read_bytes() == previous
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    assert b"candidate-workspace" in config.read_bytes()
    assert b"user-model" in config.read_bytes()
    runtime.restore_files(plan.operation_id, first_cause="failure after Kimi hook rebind")
    for change in prepared.files:
        assert change.path.read_bytes() == change.before
    assert config.read_bytes() == previous
    assert config.stat().st_mode & 0o777 == 0o600


def test_prepared_native_install_preserves_foreign_edit_before_any_publication(transition):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.kimi import KimiHarnessAdapter

    runtime, _, _, _ = transition
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=None, guard_home=runtime.home)
    config = ctx.home_dir / ".kimi-code/config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('model = "previous"\n')
    prepared = KimiHarnessAdapter().prepare_install(ctx)
    config.write_text('model = "foreign user edit"\n')
    with pytest.raises(TransitionError, match="generation_changed"):
        prepared.publish(ctx.guard_home)
    assert config.read_text() == 'model = "foreign user edit"\n'
    assert not (ctx.guard_home / "bin").exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("files", [None]),
        ("managed_installs", ["invalid"]),
        ("deadline_monotonic", True),
        ("deadline_monotonic", float("inf")),
        ("forward_expires_monotonic", "later"),
        ("candidate", {}),
        ("recovery_causes", "invalid"),
    ],
)
def test_authenticated_record_shape_failure_preserves_state_and_bindings(transition, field, value):
    runtime, plan, bindings, pointer = transition
    begin(runtime, plan)
    payload = runtime._read(plan.operation_id)
    payload[field] = value
    runtime._write(payload)
    record = runtime.path.read_bytes()
    with pytest.raises(TransitionError):
        runtime.restore_files(plan.operation_id, first_cause="candidate failed")
    assert runtime.path.read_bytes() == record
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"


@pytest.mark.parametrize(
    "field,value",
    [
        ("no_follow", "false"),
        ("after_mode", True),
        ("path", "relative"),
        ("expected_digest", False),
        ("expected_digest", "a" * 64),
    ],
)
def test_authenticated_invalid_file_contract_refuses_publication(transition, field, value):
    runtime, plan, bindings, pointer = transition
    begin(runtime, plan)
    payload = runtime._read(plan.operation_id)
    payload["files"][0][field] = value
    runtime._write(payload)
    with pytest.raises(TransitionError):
        runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"


@pytest.mark.parametrize("previous_exists", [False, True])
def test_openclaw_complete_plan_recovers_overlay_hook_manifest_and_launchers(transition, previous_exists):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.openclaw import OpenClawHarnessAdapter

    runtime, plan, _, _ = transition
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=None, guard_home=runtime.home)
    adapter = OpenClawHarnessAdapter()
    if previous_exists:
        adapter.install(ctx)
    prepared = adapter.prepare_install(replace(ctx, workspace_dir=ctx.home_dir / "candidate-workspace"))
    assert len(prepared.files) == 5
    assert sum(change.no_follow for change in prepared.files) == 3
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    assert all(change.path.read_bytes() == change.after for change in prepared.files)
    runtime.restore_files(plan.operation_id, first_cause="failure after OpenClaw rebind")
    for change in prepared.files:
        if change.before is None:
            assert not change.path.exists()
        else:
            assert change.path.read_bytes() == change.before
            assert change.path.stat().st_mode & 0o777 == change.before_mode


@pytest.mark.parametrize("previous_exists", [False, True])
def test_grok_plan_restores_config_hooks_state_and_backup_lifetime(transition, previous_exists):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter

    runtime, plan, _, _ = transition
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=None, guard_home=runtime.home)
    adapter = GrokHarnessAdapter()
    config = ctx.home_dir / ".grok/managed_config.toml"
    config.parent.mkdir(parents=True)
    config.write_text("# user setting\n[ui]\nsimple_mode = true\n")
    config.chmod(0o600)
    if previous_exists:
        adapter.install(ctx)
    backup = adapter._backup_path(ctx, "managed_config.toml")
    previous_backup = backup.stat() if backup.exists() else None
    prepared = adapter.prepare_install(replace(ctx, workspace_dir=ctx.home_dir / "candidate-workspace"))
    assert len(prepared.files) == 9
    assert config.read_bytes() == next(change.before for change in prepared.files if change.path == config)
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    assert b"candidate-workspace" in config.read_bytes()
    assert b"simple_mode = true" in config.read_bytes()
    if previous_backup is not None:
        assert backup.stat().st_ino == previous_backup.st_ino
        assert backup.stat().st_mtime_ns == previous_backup.st_mtime_ns
    runtime.restore_files(plan.operation_id, first_cause="failure after Grok rebind")
    for change in prepared.files:
        if change.before is None:
            assert not change.path.exists()
        else:
            assert change.path.read_bytes() == change.before
    if previous_backup is not None:
        assert backup.stat().st_ino == previous_backup.st_ino
        assert backup.stat().st_mtime_ns == previous_backup.st_mtime_ns


@pytest.mark.parametrize("previous_exists", [False, True])
@pytest.mark.parametrize("harness", ["zcode", "devin"])
def test_native_json_plan_restores_config_state_and_backup_lifetime(transition, previous_exists, harness):
    from codex_plugin_scanner.guard.adapters import get_adapter
    from codex_plugin_scanner.guard.adapters.base import HarnessContext

    runtime, plan, _, _ = transition
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=None, guard_home=runtime.home)
    adapter = get_adapter(harness)
    config = ctx.home_dir / (".zcode/cli/config.json" if harness == "zcode" else ".config/devin/config.json")
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"mcp": {"user": {"command": "user-tool"}}, "plugins": {"user": True}}))
    config.chmod(0o600)
    if previous_exists:
        adapter.install(ctx)
    _, backup, _ = adapter._managed_state_paths(ctx)
    previous_backup = backup.stat() if backup.exists() else None
    prepared = adapter.prepare_install(replace(ctx, workspace_dir=ctx.home_dir / "candidate-workspace"))
    assert len(prepared.files) == 5
    assert config.read_bytes() == next(change.before for change in prepared.files if change.path == config)
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    assert b"candidate-workspace" in config.read_bytes()
    assert json.loads(config.read_bytes())["mcp"]["user"]["command"] == "user-tool"
    if previous_backup is not None:
        assert backup.stat().st_ino == previous_backup.st_ino
        assert backup.stat().st_mtime_ns == previous_backup.st_mtime_ns
    runtime.restore_files(plan.operation_id, first_cause=f"failure after {harness} rebind")
    for change in prepared.files:
        if change.before is None:
            assert not change.path.exists()
        else:
            assert change.path.read_bytes() == change.before
            assert change.path.stat().st_mode & 0o777 == change.before_mode
    if previous_backup is not None:
        assert backup.stat().st_ino == previous_backup.st_ino
        assert backup.stat().st_mtime_ns == previous_backup.st_mtime_ns


@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.parametrize("previous_exists", [False, True])
def test_pi_family_plan_restores_extension_settings_and_user_entries(transition, harness, previous_exists):
    from codex_plugin_scanner.guard.adapters import get_adapter
    from codex_plugin_scanner.guard.adapters.base import HarnessContext

    runtime, plan, _, _ = transition
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=None, guard_home=runtime.home)
    adapter = get_adapter(harness)
    settings = ctx.home_dir / f".{harness}/agent/settings.json"
    extension = settings.parent / "extensions/hol-guard.ts"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"extensions": ["user-extension.ts", "npm:user-extension"], "user": True}))
    settings.chmod(0o600)
    if previous_exists:
        adapter.install(ctx)
    prepared = adapter.prepare_install(ctx)
    assert len(prepared.files) == 4
    assert settings.read_bytes() == next(change.before for change in prepared.files if change.path == settings)
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    payload = json.loads(settings.read_bytes())
    assert payload["user"] is True
    assert payload["extensions"] == ["user-extension.ts", "npm:user-extension", str(extension)]
    assert f'"--harness", "{harness}"' in extension.read_text()
    runtime.restore_files(plan.operation_id, first_cause=f"failure after {harness} rebind")
    for change in prepared.files:
        if change.before is None:
            assert not change.path.exists()
        else:
            assert change.path.read_bytes() == change.before
            assert change.path.stat().st_mode & 0o777 == change.before_mode


@pytest.mark.parametrize("harness", ["kimi", "grok", "zcode", "devin"])
@pytest.mark.parametrize("helper_exists", [False, True])
def test_frozen_helper_participates_in_signed_inverse(transition, monkeypatch, harness, helper_exists):
    from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge
    from codex_plugin_scanner.guard.adapters import get_adapter
    from codex_plugin_scanner.guard.adapters.base import HarnessContext

    runtime, plan, _, _ = transition
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=None, guard_home=runtime.home)
    helper = ctx.guard_home / f"managed/bounded-hooks/{harness}.py"
    if helper_exists:
        helper.parent.mkdir(parents=True)
        helper.write_bytes(b"previous helper generation")
        helper.chmod(0o640)
    monkeypatch.setattr(bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bridge, "isolated_cursor_hook_python", lambda: sys.executable)
    monkeypatch.setattr(bridge, "_trusted_desktop_hook_proxy_command", lambda *args: None)
    prepared = get_adapter(harness).prepare_install(ctx)
    assert helper.exists() == helper_exists
    if helper_exists:
        assert helper.read_bytes() == b"previous helper generation"
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    assert helper.stat().st_mode & 0o777 == 0o600
    assert helper.read_bytes() != b"previous helper generation"
    runtime.restore_files(plan.operation_id, first_cause="failure after frozen helper publication")
    for change in prepared.files:
        if change.before is None:
            assert not change.path.exists()
        else:
            assert change.path.read_bytes() == change.before
            assert change.path.stat().st_mode & 0o777 == change.before_mode


@pytest.mark.parametrize("previous_exists", [False, True])
def test_opencode_plan_restores_config_overlay_plugins_launchers_and_backup(transition, previous_exists):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.opencode import OpenCodeHarnessAdapter

    runtime, plan, _, _ = transition
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=None, guard_home=runtime.home)
    adapter = OpenCodeHarnessAdapter()
    config = ctx.home_dir / ".config/opencode/opencode.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps({"mcp": {"user": {"type": "local", "command": ["node", "user.js"]}}, "user_setting": True})
    )
    config.chmod(0o640)
    if previous_exists:
        adapter.install(ctx)
    backup = adapter._backup_path(ctx)
    previous_backup = backup.stat() if backup.exists() else None
    prepared = adapter.prepare_install(replace(ctx, workspace_dir=ctx.home_dir / "candidate-workspace"))
    assert len(prepared.files) == 11
    assert config.read_bytes() == next(change.before for change in prepared.files if change.path == config)
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    payload = json.loads(config.read_bytes())
    assert payload["user_setting"] is True
    assert "hol-guard::user" in payload["mcp"]
    if previous_backup is not None:
        assert backup.stat().st_ino == previous_backup.st_ino
        assert backup.stat().st_mtime_ns == previous_backup.st_mtime_ns
    runtime.restore_files(plan.operation_id, first_cause="failure after OpenCode rebind")
    for change in prepared.files:
        if change.before is None:
            assert not change.path.exists()
        else:
            assert change.path.read_bytes() == change.before
            assert change.path.stat().st_mode & 0o777 == change.before_mode
    if previous_backup is not None:
        assert backup.stat().st_ino == previous_backup.st_ino
        assert backup.stat().st_mtime_ns == previous_backup.st_mtime_ns


def test_opencode_foreign_source_config_prevents_any_transition_publication(transition):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.opencode import OpenCodeHarnessAdapter

    runtime, plan, bindings, pointer = transition
    workspace = runtime.home.parent / "workspace"
    workspace.mkdir()
    source = workspace / "opencode.jsonc"
    source.write_text('{ // user config\n"mcp": {"user": {"type": "local", "command": ["node", "user.js"]}}}')
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=workspace, guard_home=runtime.home)
    prepared = OpenCodeHarnessAdapter().prepare_install(ctx)
    dependency = next(change for change in prepared.files if change.path == source)
    assert dependency.before == dependency.after == source.read_bytes()
    source.write_text('{"user_edit": true}')
    plan = replace(plan, files=(*plan.files, *prepared.files))
    with pytest.raises(TransitionError, match="generation_changed"):
        begin(runtime, plan)
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"
    assert all(not change.path.exists() for change in prepared.files if change.before is None)


@pytest.mark.parametrize("workspace_enabled", [False, True])
@pytest.mark.parametrize("previous_exists", [False, True])
@pytest.mark.parametrize("frozen", [False, True])
def test_copilot_plan_restores_native_bindings_and_preserves_authority(
    transition,
    monkeypatch,
    workspace_enabled,
    previous_exists,
    frozen,
):
    from codex_plugin_scanner.guard.adapters.adapter_state_integrity import authenticate_adapter_state
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter

    runtime, plan, _, _ = transition
    workspace = runtime.home.parent / "workspace" if workspace_enabled else None
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=workspace, guard_home=runtime.home)
    adapter = CopilotHarnessAdapter()
    authenticate_adapter_state(runtime.home, harness="copilot", payload={"enrollment": "fixture"})
    authority = runtime.home / "managed/adapter-state.key"
    authority_before = authority.stat()
    for target in adapter._target_mcp_paths(ctx):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('{"user_setting": true, "mcpServers": {"user": {"command": "node", "args": ["user.js"]}}}')
        target.chmod(0o640)
    if previous_exists:
        adapter.install(ctx)
    if frozen:
        from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge

        monkeypatch.setattr(bridge.sys, "frozen", True, raising=False)
        monkeypatch.setattr(bridge, "isolated_cursor_hook_python", lambda: sys.executable)
        monkeypatch.setattr(bridge, "_trusted_desktop_hook_proxy_command", lambda *args: None)
    prepared = adapter.prepare_install(ctx)
    assert len(prepared.files) == (12 if workspace_enabled else 7) + int(frozen)
    dependency = next(change for change in prepared.files if change.path == authority)
    assert dependency.before is dependency.after is None
    assert dependency.expected_digest is not None
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    # The signed durable record pins identity and does not retain secret bytes.
    record = json.loads(runtime.path.read_bytes())
    key_record = next(change for change in record["files"] if change["path"] == str(authority))
    assert key_record["before"] is key_record["after"] is None
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    for change in prepared.files:
        if change.expected_digest is None:
            assert (change.path.read_bytes() if change.path.exists() else None) == change.after
    runtime.restore_files(plan.operation_id, first_cause="failure after Copilot native rebind")
    for change in prepared.files:
        if change.expected_digest is None:
            if change.before is None:
                assert not change.path.exists()
            else:
                assert change.path.read_bytes() == change.before
                assert change.path.stat().st_mode & 0o777 == change.before_mode
    assert authority.stat().st_ino == authority_before.st_ino
    assert authority.stat().st_mtime_ns == authority_before.st_mtime_ns


@pytest.mark.parametrize("after_publication", [False, True])
def test_changed_copilot_authority_prevents_any_transition_mutation(transition, after_publication):
    from codex_plugin_scanner.guard.adapters.adapter_state_integrity import authenticate_adapter_state
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter

    runtime, plan, bindings, pointer = transition
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=None, guard_home=runtime.home)
    authenticate_adapter_state(runtime.home, harness="copilot", payload={"enrollment": "fixture"})
    prepared = CopilotHarnessAdapter().prepare_install(ctx)
    plan = replace(plan, files=(*plan.files, *prepared.files))
    if after_publication:
        begin(runtime, plan)
        runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    before_files = {
        change.path: (change.path.read_bytes() if change.path.exists() else None)
        for change in prepared.files
        if change.expected_digest is None
    }
    authority = runtime.home / "managed/adapter-state.key"
    authority.write_bytes(b"foreign authority generation")
    with pytest.raises(TransitionError, match="generation_changed"):
        if after_publication:
            runtime.restore_files(plan.operation_id, first_cause="candidate protection failed")
        else:
            begin(runtime, plan)
    assert bindings.read_bytes() == (b"candidate hooks" if after_publication else b"previous hooks")
    assert pointer.read_bytes() == b"previous pointer"
    assert authority.read_bytes() == b"foreign authority generation"
    for path, content in before_files.items():
        assert (path.read_bytes() if path.exists() else None) == content
    if after_publication:
        state = runtime._read(plan.operation_id)
        assert state["phase"] == "RecoveryRequired"
        assert state["first_cause"] == "candidate protection failed"
        assert state["recovery_causes"] == [{"code": "generation_changed", "errno": None}]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"expected_digest": "not-a-digest"},
        {"expected_digest": "a" * 64, "after": b"new authority"},
        {"expected_digest": "a" * 64, "after_mode": 0o640},
        {"expected_digest": "a" * 64, "no_follow": False},
        {"expected_digest": "a" * 64, "kind": "selection"},
    ],
)
def test_authority_dependency_rejects_mutating_or_invalid_contracts(tmp_path, kwargs):
    fields = {"path": tmp_path / "authority", "before": None, "after": None, "no_follow": True, **kwargs}
    with pytest.raises(TransitionError, match="authority_dependency_invalid"):
        TransitionFile(**fields).payload()


@pytest.mark.parametrize("previous_exists", [False, True])
@pytest.mark.parametrize("legacy", ["none", "user", "managed", "backup"])
def test_cursor_editor_plan_restores_native_and_legacy_bindings(transition, previous_exists, legacy):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
    from codex_plugin_scanner.guard.adapters.cursor_hook_config import (
        HOOK_SCRIPT_NAME,
        _hooks_backup_path,
        _hooks_state_path,
    )
    from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source
    from codex_plugin_scanner.guard.adapters.cursor_native_approval import ensure_cursor_hook_attestation_secret

    runtime, plan, _, _ = transition
    workspace = runtime.home.parent / "workspace"
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=workspace, guard_home=runtime.home)
    ensure_cursor_hook_attestation_secret(runtime.home)
    adapter = CursorHarnessAdapter()
    config = ctx.home_dir / ".cursor/mcp.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"user_setting": true, "mcpServers": {"user": {"command": "node", "args": ["user.js"]}}}')
    config.chmod(0o640)
    if previous_exists:
        adapter.install(ctx)
    legacy_hooks = workspace / ".cursor/hooks.json"
    legacy_script = workspace / ".cursor/hooks" / HOOK_SCRIPT_NAME
    if legacy != "none":
        legacy_hooks.parent.mkdir(parents=True, exist_ok=True)
        user_entry = {"command": "user-review.sh"}
        entries = [user_entry]
        if legacy in {"managed", "backup"}:
            legacy_script.parent.mkdir(parents=True, exist_ok=True)
            legacy_script.write_text(
                cursor_hook_script_source(ctx, guard_cli=["/previous/core"], recovery_command=["true"])
            )
            legacy_script.chmod(0o750)
            entries.append({"command": str(legacy_script.resolve())})
        legacy_hooks.write_text(json.dumps({"version": 1, "hooks": {"beforeShellExecution": entries}}))
        legacy_hooks.chmod(0o640)
        if legacy == "backup":
            backup = _hooks_backup_path(legacy_hooks, ctx)
            backup.parent.mkdir(parents=True, exist_ok=True)
            backup.write_text(json.dumps({"existed": True, "content": '{"original_user_hooks": true}'}))
            _hooks_state_path(legacy_hooks, ctx).write_text('{"legacy_state": true}')
    prepared = adapter.prepare_install(ctx)
    assert len(prepared.files) == 14
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    if legacy == "managed":
        assert json.loads(legacy_hooks.read_bytes())["hooks"]["beforeShellExecution"] == [{"command": "user-review.sh"}]
    if legacy == "backup":
        assert json.loads(legacy_hooks.read_bytes()) == {"original_user_hooks": True}
    if legacy in {"managed", "backup"}:
        assert not legacy_script.exists()
    runtime.restore_files(plan.operation_id, first_cause="failure after Cursor editor rebind")
    for change in prepared.files:
        if change.expected_digest is None:
            assert (change.path.read_bytes() if change.path.exists() else None) == change.before
            if change.before is not None:
                assert change.path.stat().st_mode & 0o777 == change.before_mode


def test_cursor_foreign_workspace_config_prevents_any_transition_publication(transition):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
    from codex_plugin_scanner.guard.adapters.cursor_native_approval import ensure_cursor_hook_attestation_secret

    runtime, plan, bindings, pointer = transition
    workspace = runtime.home.parent / "workspace"
    source = workspace / ".cursor/mcp.json"
    source.parent.mkdir(parents=True)
    source.write_text('{"mcpServers": {"user": {"command": "node", "args": ["user.js"]}}}')
    ctx = HarnessContext(home_dir=runtime.home.parent, workspace_dir=workspace, guard_home=runtime.home)
    ensure_cursor_hook_attestation_secret(runtime.home)
    prepared = CursorHarnessAdapter().prepare_install(ctx)
    dependency = next(change for change in prepared.files if change.path == source)
    assert dependency.before == dependency.after == source.read_bytes()
    source.write_text('{"foreign_user_edit": true}')
    with pytest.raises(TransitionError, match="generation_changed"):
        begin(runtime, replace(plan, files=(*plan.files, *prepared.files)))
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"
    assert all(
        not change.path.exists()
        for change in prepared.files
        if change.before is None and change.expected_digest is None
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell profiles")
@pytest.mark.parametrize("surface", ["cli", "all"])
@pytest.mark.parametrize("profile_exists", [False, True])
def test_cursor_all_surfaces_restore_launchers_and_shell_profile(transition, monkeypatch, surface, profile_exists):
    from codex_plugin_scanner.guard import shims
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
    from codex_plugin_scanner.guard.adapters.cursor_native_approval import ensure_cursor_hook_attestation_secret

    runtime, plan, _, _ = transition
    ctx = HarnessContext(home_dir=runtime.home.parent, guard_home=runtime.home, workspace_dir=None)
    if surface == "all":
        ensure_cursor_hook_attestation_secret(runtime.home)
    monkeypatch.setattr(shims, "_is_transient_path", lambda path: False)
    monkeypatch.setenv("SHELL", "/bin/zsh")
    profile = ctx.home_dir / ".zshrc"
    if profile_exists:
        profile.write_text('export USER_SETTING="keep me"\n')
        profile.chmod(0o640)
    prepared = CursorHarnessAdapter().prepare_install(ctx, surface=surface)
    assert len(prepared.files) == (5 if surface == "cli" else 14)
    assert all(
        change.path.name
        in {".zshrc", "guard-cursor", "guard-cursor.cmd", "guard-cursor-agent", "guard-cursor-agent.cmd"}
        for change in prepared.files
        if surface == "cli"
    )
    assert (profile.read_text() if profile.exists() else None) == (
        'export USER_SETTING="keep me"\n' if profile_exists else None
    )
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    assert profile.read_text().count(shims._GUARD_PROFILE_MARKER) == 1
    if profile_exists:
        assert 'export USER_SETTING="keep me"' in profile.read_text()
    assert (runtime.home / "bin/guard-cursor-agent").is_file()
    assert (runtime.home / "bin/guard-cursor.cmd").is_file()
    runtime.restore_files(plan.operation_id, first_cause="failure after Cursor CLI profile publication")
    for change in prepared.files:
        if change.expected_digest is None:
            assert (change.path.read_bytes() if change.path.exists() else None) == change.before
            if change.before is not None:
                assert change.path.stat().st_mode & 0o777 == change.before_mode


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell profiles")
def test_cursor_foreign_profile_prevents_any_transition_publication(transition, monkeypatch):
    from codex_plugin_scanner.guard import shims
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter

    runtime, plan, bindings, pointer = transition
    ctx = HarnessContext(home_dir=runtime.home.parent, guard_home=runtime.home, workspace_dir=None)
    monkeypatch.setattr(shims, "_is_transient_path", lambda path: False)
    monkeypatch.setenv("SHELL", "/bin/zsh")
    profile = ctx.home_dir / ".zshrc"
    profile.write_text("original user profile\n")
    prepared = CursorHarnessAdapter().prepare_install(ctx, surface="cli")
    profile.write_text("foreign user profile\n")
    with pytest.raises(TransitionError, match="generation_changed"):
        begin(runtime, replace(plan, files=(*plan.files, *prepared.files)))
    assert profile.read_text() == "foreign user profile\n"
    assert not (runtime.home / "bin").exists()
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"


def test_full_phase_order_requires_candidate_hook_and_restores_both_files(transition):
    runtime, plan, bindings, pointer = transition
    begin(runtime, plan)
    assert runtime.publish(plan.operation_id, "AuthorizedForExactTransition") == "HooksPrepared"
    assert bindings.read_bytes() == b"candidate hooks"
    assert pointer.read_bytes() == b"previous pointer"
    assert runtime.publish(plan.operation_id, "HooksPrepared") == "Switching"
    with pytest.raises(TransitionError, match="functional_proof_missing"):
        runtime.advance(plan.operation_id, "Switching")
    assert (
        runtime.advance(plan.operation_id, "Switching", functional_proof=proof(plan, plan.candidate["generation"]))
        == "CandidateFunctional"
    )
    runtime.restore_files(plan.operation_id, first_cause="candidate hook later failed")
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"
    assert runtime._read(plan.operation_id)["phase"] == "RestoringPrevious"
    with pytest.raises(TransitionError, match="functional_proof_missing"):
        runtime.finish_rollback(plan.operation_id, functional_proof=proof(plan, "wrong-generation"))
    runtime.finish_rollback(plan.operation_id, functional_proof=proof(plan, plan.predecessor["generation"]))
    assert runtime._read(plan.operation_id)["phase"] == "FailedWithVerifiedRollback"


@pytest.mark.parametrize("rollback", [False, True])
@pytest.mark.parametrize(
    "fault",
    [
        "boolean",
        "serialized",
        "constructed",
        "modified_receipt",
        "wrong_home",
        "wrong_runtime",
        "wrong_generation",
        "wrong_operation",
        "stale",
        "future",
    ],
)
def test_completion_rejects_unproven_or_mismatched_native_observation(transition, rollback, fault):
    runtime, plan, bindings, pointer = transition
    begin(runtime, plan)
    if rollback:
        runtime.restore_files(plan.operation_id, first_cause="fixture failure")
        generation = plan.predecessor["generation"]
        expected_phase = "RestoringPrevious"
    else:
        runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
        runtime.publish(plan.operation_id, "HooksPrepared")
        generation = plan.candidate["generation"]
        expected_phase = "Switching"
    valid = proof(plan, generation)
    if fault == "boolean":
        invalid = {"operation_id": plan.operation_id, "generation": generation, "protected_hook": True}
    elif fault == "serialized":
        invalid = valid.payload()
    elif fault == "constructed":
        invalid = replace(valid)
    elif fault == "modified_receipt":
        valid.allow_receipt["unit_protocol_fixture"] = "tampered"
        invalid = valid
    else:
        changes = {
            "wrong_home": {"guard_home": plan.guard_home.parent},
            "wrong_runtime": {"runtime_identity": replace(valid.runtime_identity, sha256="0" * 64)},
            "wrong_generation": {"artifact_generation": "foreign"},
            "wrong_operation": {"operation_id": "foreign"},
            "stale": {"observed_monotonic": runtime._read(plan.operation_id)["functional_started_monotonic"] - 1},
            "future": {"observed_monotonic": time.monotonic() + 100},
        }
        invalid = _seal_verified_admission(replace(valid, **changes[fault]))
    original_files = bindings.read_bytes(), pointer.read_bytes()
    with pytest.raises(TransitionError, match="functional_proof_missing"):
        if rollback:
            runtime.finish_rollback(plan.operation_id, functional_proof=invalid)
        else:
            runtime.advance(plan.operation_id, expected_phase, functional_proof=invalid)
    assert runtime._read(plan.operation_id)["phase"] == expected_phase
    assert (bindings.read_bytes(), pointer.read_bytes()) == original_files


def test_admission_validation_records_only_the_snapshot_it_verified(transition, monkeypatch):
    from codex_plugin_scanner.guard import runtime_transition_admission as admission

    _runtime, plan, *_ = transition
    valid = proof(plan, plan.candidate["generation"])
    original = admission._admission_bytes

    def capture_then_mutate(observation):
        encoded = original(observation)
        observation.allow_receipt["unit_protocol_fixture"] = "foreign edit after capture"
        return encoded

    monkeypatch.setattr(admission, "_admission_bytes", capture_then_mutate)
    captured = admission.verified_admission_payload(valid)
    assert captured["allow_receipt"] == {"unit_protocol_fixture": "allow"}
    with pytest.raises(TransitionError, match="functional_proof_missing"):
        admission.verified_admission_payload(valid)


@pytest.mark.parametrize("failure", [None, "stop_previous", "start_candidate", "observe_candidate", "selection"])
def test_core_coordinator_restores_bindings_and_selection_after_each_failure(transition, monkeypatch, failure):
    from codex_plugin_scanner.guard.runtime_transition_coordinator import RuntimeTransitionCoordinator

    runtime, plan, bindings, pointer = transition
    events, deadlines = [], []

    class Driver:
        def stop(self, artifact, *, deadline_monotonic):
            side = "candidate" if artifact == plan.candidate else "previous"
            if side == "candidate":
                state = runtime._read(plan.operation_id)
                assert state["phase"] == "RestoringPrevious" and state["first_cause"] is not None
            events.append("stop_" + side)
            deadlines.append(deadline_monotonic)
            if failure == "stop_previous" and side == "previous":
                raise TransitionError("injected_stop_failure")

        def start(self, artifact, *, deadline_monotonic):
            side = "candidate" if artifact == plan.candidate else "previous"
            events.append("start_" + side)
            deadlines.append(deadline_monotonic)
            if failure == "start_candidate" and side == "candidate":
                raise TransitionError("injected_start_failure")

        def observe_protection(self, artifact, operation_id, *, deadline_monotonic):
            side = "candidate" if artifact == plan.candidate else "previous"
            events.append("observe_" + side)
            deadlines.append(deadline_monotonic)
            assert operation_id == plan.operation_id
            if failure == "observe_candidate" and side == "candidate":
                raise TransitionError("injected_hook_failure")
            return proof(plan, artifact["generation"])

    if failure == "selection":
        publish = runtime.publish

        def failed_selection(operation_id, phase):
            if phase == "HooksPrepared":
                raise TransitionError("injected_selection_failure")
            return publish(operation_id, phase)

        monkeypatch.setattr(runtime, "publish", failed_selection)
    result = RuntimeTransitionCoordinator(runtime, Driver()).activate(plan, authority_home=plan.guard_home, grant=None)
    assert len(set(deadlines)) == 1
    assert runtime._read(plan.operation_id)["deadline_monotonic"] <= deadlines[0]
    if failure is None:
        assert result.phase == "Committed" and result.first_cause is None
        assert events == ["stop_previous", "start_candidate", "observe_candidate"]
        assert bindings.read_bytes() == b"candidate hooks" and pointer.read_bytes() == b"candidate pointer"
    else:
        assert result.phase == "FailedWithVerifiedRollback" and result.first_cause is not None
        assert events[-2:] == ["start_previous", "observe_previous"]
        if failure in {"start_candidate", "observe_candidate"}:
            assert "stop_candidate" in events
        assert bindings.read_bytes() == b"previous hooks" and pointer.read_bytes() == b"previous pointer"


def core_dependencies(plan):
    dependencies = []
    for side, artifact in (("candidate", plan.candidate), ("predecessor", plan.predecessor)):
        path = Path(artifact["path"])
        data = (side + " isolated executable").encode()
        path.write_bytes(data)
        path.chmod(0o700)
        dependencies.append(
            TransitionFile.artifact_dependency(
                {
                    "path": str(path),
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "mode": 0o700,
                    "owner_uid": path.stat().st_uid,
                    "role": "artifact",
                }
            )
        )
    return replace(plan, files=(*plan.files, *dependencies))


@pytest.mark.parametrize(
    "failure",
    [None, "start_candidate", "observe_candidate", "foreign_generation", "pending_owner", "isolated_native_proof"],
)
def test_transition_daemon_driver_composes_exact_lifecycle_and_inverse(transition, monkeypatch, failure):
    from codex_plugin_scanner.guard import runtime_transition_daemon as module
    from codex_plugin_scanner.guard.runtime_transition_coordinator import RuntimeTransitionCoordinator

    runtime, plan, bindings, pointer = transition
    plan = core_dependencies(plan)
    current, events, deadlines, dead = {}, [], [], set()

    def observe(artifact, identity, operation_id, *, deadline_monotonic):
        side = "candidate" if artifact == plan.candidate else "predecessor"
        assert identity == current and operation_id == plan.operation_id
        events.append("observe_" + side)
        deadlines.append(deadline_monotonic)
        if failure == "observe_candidate" and side == "candidate":
            raise TransitionError("candidate_hook_failed")
        return proof(
            plan,
            artifact["generation"],
            installed=failure != "isolated_native_proof" or side == "predecessor",
        )

    driver = module.TransitionDaemonDriver(runtime, plan, home_dir=plan.guard_home.parent, observe_hook=observe)

    def state(side, pid):
        binding = driver.bindings[side]
        return {
            "executable": str(binding.executable),
            "source_root": str(binding.executable),
            "runtime_fingerprint": binding.executable_sha256,
            "package_version": binding.package_version,
            "pid": pid,
            "state_id": side,
            "daemon_url": "http://127.0.0.1:1234",
        }

    current.update(state("predecessor", 123))
    monkeypatch.setattr(module, "load_authenticated_daemon_state", lambda _home: dict(current) if current else None)
    monkeypatch.setattr(module.manager, "_guard_daemon_start_in_progress", lambda _home: False)
    monkeypatch.setattr(
        module.manager,
        "load_authenticated_guard_daemon_pending_launch",
        lambda _home: {"pid": 999} if failure == "pending_owner" else None,
    )
    monkeypatch.setattr(module.manager, "load_authenticated_guard_daemon_start_progress", lambda _home: None)
    monkeypatch.setattr(module, "process_start_token", lambda _pid, **_kwargs: "fixture-start")
    monkeypatch.setattr(module.manager, "_guard_daemon_pid_is_proven_dead", lambda pid: pid in dead)

    def retire(pid, *, expected_guard_home, expected_start_token, deadline_monotonic):
        assert expected_guard_home == runtime.home and expected_start_token == "fixture-start"
        events.append("stop_candidate" if pid == 456 else "stop_predecessor")
        deadlines.append(deadline_monotonic)
        dead.add(pid)
        return True

    def clear(_home, *, expected_state):
        assert expected_state == current
        current.clear()
        return True

    def ensure(_home, *, home_dir, executable, deadline_monotonic, background_maintenance):
        assert _home == runtime.home and home_dir == plan.guard_home.parent and background_maintenance is False
        side = "candidate" if executable == driver.bindings["candidate"].executable else "predecessor"
        events.append("start_" + side)
        deadlines.append(deadline_monotonic)
        pid = 456 if side == "candidate" else 789
        current.update(state(side, pid))
        if side == "candidate" and failure == "start_candidate":
            raise TransitionError("candidate_start_failed")
        if side == "candidate" and failure == "foreign_generation":
            current["runtime_fingerprint"] = "c" * 64
        return current["daemon_url"]

    monkeypatch.setattr(module.manager, "_retire_guard_daemon_pid", retire)
    monkeypatch.setattr(module.manager, "_clear_authenticated_guard_daemon_state_if_current", clear)
    monkeypatch.setattr(module.manager, "ensure_guard_daemon", ensure)
    monkeypatch.setattr(
        module,
        "verified_live_guard_daemon_identity",
        lambda _home, *, expected_artifact, deadline_monotonic: (
            dict(current) if expected_artifact.matches(current) else None
        ),
    )
    result = RuntimeTransitionCoordinator(runtime, driver).activate(plan, authority_home=plan.guard_home, grant=None)
    assert len(set(deadlines)) == (0 if failure == "pending_owner" else 1)
    if failure is None:
        assert result.phase == "Committed" and result.first_cause is None
        assert events == ["stop_predecessor", "start_candidate", "observe_candidate"]
        assert bindings.read_bytes() == b"candidate hooks" and pointer.read_bytes() == b"candidate pointer"
    else:
        if failure == "pending_owner":
            assert bindings.read_bytes() == b"previous hooks" and pointer.read_bytes() == b"previous pointer"
            assert result.phase == "RecoveryRequired" and result.first_cause == "daemon_retirement_incomplete"
            assert events == [], "do not retire or adopt while another launch remains unresolved"
        elif failure == "foreign_generation":
            assert bindings.read_bytes() == b"candidate hooks" and pointer.read_bytes() == b"candidate pointer"
            assert result.phase == "RecoveryRequired" and result.first_cause == "daemon_generation_changed"
            assert events == ["stop_predecessor", "start_candidate"], "do not stop an unplanned generation"
        else:
            assert bindings.read_bytes() == b"previous hooks" and pointer.read_bytes() == b"previous pointer"
            assert result.phase == "FailedWithVerifiedRollback"
            if failure == "isolated_native_proof":
                assert result.first_cause == "installed_hook_proof_missing"
            assert events[-3:] == ["stop_candidate", "start_predecessor", "observe_predecessor"]


@pytest.mark.parametrize("healthy", [True, False])
def test_recovery_candidate_retirement_preserves_exact_predecessor(transition, monkeypatch, healthy):
    from codex_plugin_scanner.guard import runtime_transition_daemon as module

    runtime, plan, *_ = transition
    plan = core_dependencies(plan)
    begin(runtime, plan)
    runtime.prepare_recovery(plan.operation_id, first_cause="interrupted_before_launch")
    driver = module.TransitionDaemonDriver(
        runtime, plan, home_dir=plan.guard_home.parent, observe_hook=lambda *args, **kwargs: None
    )
    binding = driver.bindings["predecessor"]
    state = {
        "executable": str(binding.executable),
        "source_root": str(binding.executable),
        "runtime_fingerprint": binding.executable_sha256,
        "package_version": binding.package_version,
        "pid": 123,
    }
    monkeypatch.setattr(module, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(module.manager, "load_authenticated_guard_daemon_pending_launch", lambda _home: None)
    monkeypatch.setattr(module.manager, "load_authenticated_guard_daemon_start_progress", lambda _home: None)
    monkeypatch.setattr(driver, "_live", lambda side, deadline: state if healthy else None)

    def forbidden_retire(*args, **kwargs):
        pytest.fail("retained predecessor must never be retired as the candidate")

    monkeypatch.setattr(module.manager, "_retire_guard_daemon_pid", forbidden_retire)
    if healthy:
        driver.stop(plan.candidate, deadline_monotonic=time.monotonic() + 10)
    else:
        with pytest.raises(TransitionError, match="daemon_identity_unavailable"):
            driver.stop(plan.candidate, deadline_monotonic=time.monotonic() + 10)


def test_exact_daemon_steps_require_matching_subject_phase_and_completed_inverse(transition):
    runtime, plan, *_ = transition
    begin(runtime, plan)
    with pytest.raises(TransitionError, match="plan_context_mismatch"):
        runtime.authorize_daemon_step(plan.operation_id, subject="foreign", side="predecessor", action="stop")
    with pytest.raises(TransitionError, match="daemon_step_not_authorized"):
        runtime.authorize_daemon_step(plan.operation_id, subject=plan.subject(), side="predecessor", action="stop")
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    runtime.authorize_daemon_step(plan.operation_id, subject=plan.subject(), side="predecessor", action="stop")
    runtime.prepare_recovery(plan.operation_id, first_cause="candidate failed")
    runtime.authorize_daemon_step(plan.operation_id, subject=plan.subject(), side="candidate", action="stop")
    with pytest.raises(TransitionError, match="inverse_not_restored"):
        runtime.authorize_daemon_step(plan.operation_id, subject=plan.subject(), side="predecessor", action="start")
    runtime.restore_files(plan.operation_id, first_cause="second cause")
    runtime.authorize_daemon_step(plan.operation_id, subject=plan.subject(), side="predecessor", action="start")
    assert runtime.status(plan.operation_id).first_cause == "candidate failed"


@pytest.mark.parametrize("failure", ["candidate_stop", "previous_start", "previous_observation"])
def test_core_coordinator_records_runtime_recovery_failures_without_claiming_restoration(transition, failure):
    from codex_plugin_scanner.guard.runtime_transition_coordinator import RuntimeTransitionCoordinator

    runtime, plan, bindings, pointer = transition
    events = []

    class Driver:
        def stop(self, artifact, *, deadline_monotonic):
            if artifact == plan.candidate and failure == "candidate_stop":
                raise TransitionError("candidate_retirement_failed")

        def start(self, artifact, *, deadline_monotonic):
            events.append(artifact["generation"])
            if artifact == plan.candidate:
                raise TransitionError("first_candidate_start_failure")
            if failure == "previous_start":
                raise TransitionError("previous_start_failed")

        def observe_protection(self, artifact, operation_id, *, deadline_monotonic):
            if failure == "previous_observation":
                raise TransitionError("previous_protection_failed")
            return proof(plan, artifact["generation"])

    result = RuntimeTransitionCoordinator(runtime, Driver()).activate(plan, authority_home=plan.guard_home, grant=None)
    assert result.phase == "RecoveryRequired"
    assert result.first_cause == "first_candidate_start_failure"
    assert (
        result.recovery_causes[-1]["code"]
        == {
            "candidate_stop": "candidate_retirement_failed",
            "previous_start": "previous_start_failed",
            "previous_observation": "previous_protection_failed",
        }[failure]
    )
    if failure == "candidate_stop":
        assert bindings.read_bytes() == b"candidate hooks" and pointer.read_bytes() == b"candidate pointer", (
            "a potentially live candidate must retain its binding and selection generation"
        )
        assert events == [plan.candidate["generation"]], "do not start a competing predecessor"
    else:
        assert bindings.read_bytes() == b"previous hooks" and pointer.read_bytes() == b"previous pointer"
    with pytest.raises(TransitionError, match="nonterminal_transition"):
        runtime.retire(plan.operation_id)

    if failure == "candidate_stop":
        recovery_deadline = time.monotonic() + 10
        recovery_events = []

        class RecoveryDriver:
            def stop(self, artifact, *, deadline_monotonic):
                assert deadline_monotonic == recovery_deadline
                assert artifact == plan.candidate
                assert bindings.read_bytes() == b"candidate hooks"
                assert pointer.read_bytes() == b"candidate pointer"
                recovery_events.append("candidate_retired")

            def start(self, artifact, *, deadline_monotonic):
                assert deadline_monotonic == recovery_deadline
                assert artifact == plan.predecessor
                assert bindings.read_bytes() == b"previous hooks"
                assert pointer.read_bytes() == b"previous pointer"
                recovery_events.append("previous_started")

            def observe_protection(self, artifact, operation_id, *, deadline_monotonic):
                assert deadline_monotonic == recovery_deadline
                assert operation_id == plan.operation_id
                recovery_events.append("previous_observed")
                return proof(plan, artifact["generation"])

        reopened = RuntimeTransition(runtime.home, runtime.authority)
        restored = RuntimeTransitionCoordinator(reopened, RecoveryDriver()).recover(
            plan.operation_id,
            deadline_monotonic=recovery_deadline,
        )
        assert restored.phase == "FailedWithVerifiedRollback"
        assert restored.first_cause == "first_candidate_start_failure"
        assert recovery_events == ["candidate_retired", "previous_started", "previous_observed"]
        assert reopened._forward_grant is None


@pytest.mark.parametrize("refusal", ["approval", "deadline"])
def test_core_coordinator_refuses_before_publication_or_lifecycle_calls(transition, refusal):
    from codex_plugin_scanner.guard.runtime_transition_coordinator import RuntimeTransitionCoordinator

    runtime, plan, bindings, pointer = transition
    if refusal == "approval":
        password = "isolated-coordinator-authorization-password"
        update_settings(plan.guard_home, {"enabled": True, "new_password": password, "confirm_password": password})
        error = ApprovalGateError
    else:
        plan = replace(plan, deadline_epoch=time.time() - 1)
        error = TransitionError

    class Driver:
        def stop(self, *args, **kwargs):
            pytest.fail("a refused transition must not stop a runtime")

        def start(self, *args, **kwargs):
            pytest.fail("a refused transition must not launch a runtime")

        def observe_protection(self, *args, **kwargs):
            pytest.fail("a refused transition must not launch a hook probe")

    with pytest.raises(error):
        RuntimeTransitionCoordinator(runtime, Driver()).activate(plan, authority_home=plan.guard_home, grant=None)
    assert not runtime.path.exists()
    assert bindings.read_bytes() == b"previous hooks" and pointer.read_bytes() == b"previous pointer"


@pytest.mark.parametrize("boundary", ["stop_previous", "start_candidate"])
def test_core_coordinator_expiry_never_launches_cleanup_with_a_fresh_budget(transition, monkeypatch, boundary):
    from codex_plugin_scanner.guard import runtime_transition_coordinator as module

    runtime, plan, bindings, pointer = transition
    events = []

    class Driver:
        def stop(self, artifact, *, deadline_monotonic):
            events.append("stop_previous" if artifact == plan.predecessor else "stop_candidate")
            if boundary == "stop_previous":
                monkeypatch.setattr(module.time, "monotonic", lambda: deadline_monotonic + 1)

        def start(self, artifact, *, deadline_monotonic):
            events.append("start_candidate")
            monkeypatch.setattr(module.time, "monotonic", lambda: deadline_monotonic + 1)

        def observe_protection(self, *args, **kwargs):
            pytest.fail("an expired operation must not launch a hook probe")

    result = module.RuntimeTransitionCoordinator(runtime, Driver()).activate(
        plan,
        authority_home=plan.guard_home,
        grant=None,
    )
    assert result.phase == "RecoveryRequired" and result.first_cause == "deadline_exceeded"
    assert events == (["stop_previous"] if boundary == "stop_previous" else ["stop_previous", "start_candidate"])
    assert bindings.read_bytes() == b"candidate hooks"
    assert pointer.read_bytes() == (b"previous pointer" if boundary == "stop_previous" else b"candidate pointer")


def test_prepare_recovery_failure_still_retires_the_candidate(transition, monkeypatch):
    from codex_plugin_scanner.guard.runtime_transition_coordinator import RuntimeTransitionCoordinator

    runtime, plan, *_ = transition
    events = []

    class Driver:
        def stop(self, artifact, *, deadline_monotonic):
            events.append("stop_candidate" if artifact == plan.candidate else "stop_predecessor")

        def start(self, artifact, *, deadline_monotonic):
            events.append("start_candidate")
            raise TransitionError("candidate_start_failed")

        def observe_protection(self, *_args, **_kwargs):
            pytest.fail("observation is not reached")

    def broken(_operation_id, *, first_cause):
        events.append(first_cause)
        raise OSError("journal unavailable")

    monkeypatch.setattr(runtime, "prepare_recovery", broken)
    result = RuntimeTransitionCoordinator(runtime, Driver()).activate(
        plan,
        authority_home=plan.guard_home,
        grant=None,
    )
    assert events == ["stop_predecessor", "start_candidate", "candidate_start_failed", "stop_candidate"]
    assert result.phase == "RecoveryRequired"
    assert result.first_cause == "candidate_start_failed"
    assert any(cause["code"] == "OSError" for cause in result.recovery_causes)


def test_prepare_recovery_failure_stays_visible_when_recording_is_rejected(transition, monkeypatch):
    from codex_plugin_scanner.guard.runtime_transition_coordinator import RuntimeTransitionCoordinator

    runtime, plan, *_ = transition
    events = []

    class Driver:
        def stop(self, artifact, *, deadline_monotonic):
            events.append("stop_candidate" if artifact == plan.candidate else "stop_predecessor")

        def start(self, artifact, *, deadline_monotonic):
            events.append("start_candidate")
            raise TransitionError("candidate_start_failed")

        def observe_protection(self, *_args, **_kwargs):
            pytest.fail("observation is not reached")

    def broken(_operation_id, *, first_cause):
        raise OSError("journal unavailable")

    def refuse(*_args, **_kwargs):
        raise TransitionError("recovery_owner_changed")

    monkeypatch.setattr(runtime, "prepare_recovery", broken)
    monkeypatch.setattr(runtime, "record_recovery_failure", refuse)
    with pytest.raises(OSError, match="journal unavailable") as caught:
        RuntimeTransitionCoordinator(runtime, Driver()).activate(
            plan,
            authority_home=plan.guard_home,
            grant=None,
        )
    assert events == ["stop_predecessor", "start_candidate", "stop_candidate"]
    assert isinstance(caught.value.__cause__, TransitionError)
    assert caught.value.__cause__.reason == "recovery_owner_changed"


def test_transition_begin_dependency_wait_consumes_original_coordinator_deadline(transition, monkeypatch):
    from codex_plugin_scanner.guard import runtime_transition as module

    runtime, plan, bindings, pointer = transition
    deadline = time.monotonic() + 1
    compare = runtime._compare

    def delayed_compare(*args, **kwargs):
        compare(*args, **kwargs)
        monkeypatch.setattr(module.time, "monotonic", lambda: deadline + 1)

    monkeypatch.setattr(runtime, "_compare", delayed_compare)
    with pytest.raises(TransitionError, match="deadline_exceeded"):
        runtime.begin(plan, authority_home=plan.guard_home, grant=None, deadline_monotonic=deadline)
    assert not runtime.path.exists()
    assert bindings.read_bytes() == b"previous hooks" and pointer.read_bytes() == b"previous pointer"


def test_core_coordinator_records_inverse_failure_once_with_original_cause(transition, monkeypatch):
    from codex_plugin_scanner.guard.runtime_transition_coordinator import RuntimeTransitionCoordinator

    runtime, plan, bindings, pointer = transition
    original_compare = runtime._compare

    def fail_inverse(payload, side, *, inverse=False):
        if inverse:
            raise TransitionError("inverse_comparison_failed")
        return original_compare(payload, side, inverse=inverse)

    monkeypatch.setattr(runtime, "_compare", fail_inverse)

    class Driver:
        def stop(self, *args, **kwargs):
            pass

        def start(self, artifact, *, deadline_monotonic):
            assert artifact == plan.candidate, "failed inverse must not start the predecessor"
            raise TransitionError("candidate_start_failed")

        def observe_protection(self, *args, **kwargs):
            pytest.fail("failed inverse must not launch a hook probe")

    result = RuntimeTransitionCoordinator(runtime, Driver()).activate(plan, authority_home=plan.guard_home, grant=None)
    assert result.phase == "RecoveryRequired" and result.first_cause == "candidate_start_failed"
    assert [cause["code"] for cause in result.recovery_causes] == ["inverse_comparison_failed"]
    assert bindings.read_bytes() == b"candidate hooks" and pointer.read_bytes() == b"candidate pointer"


@pytest.mark.parametrize("fault", ["missing", "foreign_digest", "foreign_size", "partial"])
def test_native_runtime_bindings_require_both_signed_readonly_dependencies(transition, fault):
    runtime, plan, *_ = transition
    bindings = {side: dict(identity) for side, identity in plan.native_runtimes.items()}
    if fault == "missing":
        invalid = replace(plan, files=plan.files[:2])
    elif fault == "partial":
        bindings.pop("predecessor")
        invalid = replace(plan, native_runtimes=bindings)
    else:
        field, value = ("sha256", "0" * 64) if fault == "foreign_digest" else ("size", 10000)
        bindings["candidate"][field] = value
        invalid = replace(plan, native_runtimes=bindings)
    with pytest.raises(TransitionError, match=r"native_runtime_(dependency_missing|bindings_invalid)"):
        begin(runtime, invalid)
    assert not runtime.path.exists()


@pytest.mark.usefixtures("native_hook_force")
@pytest.mark.parametrize("rollback", [False, True])
def test_actual_native_admission_drives_protocol_completion(transition, tmp_path, rollback):
    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status
    from codex_plugin_scanner.guard.runtime_transition_admission import probe_native_protection
    from codex_plugin_scanner.guard.store import GuardStore

    runtime, plan, *_ = transition
    identity = native_runtime_status().identity
    assert identity is not None
    binding = {
        "path": str(identity.path),
        "size": identity.size,
        "mtime_ns": identity.mtime_ns,
        "sha256": identity.sha256,
    }
    metadata = identity.path.stat()
    dependency = TransitionFile.artifact_dependency(
        {
            **binding,
            "owner_uid": metadata.st_uid,
            "mode": metadata.st_mode & 0o777,
            "role": "artifact",
        }
    )
    plan = replace(
        plan, files=(*plan.files[:2], dependency), native_runtimes={"candidate": binding, "predecessor": binding}
    )
    store = GuardStore(plan.guard_home)
    worker = HookWorker(store=store, wait_for_native_policy=False)
    workspace, home = tmp_path / "probe-workspace", tmp_path / "probe-home"
    workspace.mkdir()
    home.mkdir()
    try:
        begin(runtime, plan)
        if rollback:
            runtime.restore_files(plan.operation_id, first_cause="fixture failure")
            generation = plan.predecessor["generation"]
        else:
            runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
            runtime.publish(plan.operation_id, "HooksPrepared")
            generation = plan.candidate["generation"]
        observation = probe_native_protection(
            worker=worker,
            operation_id=plan.operation_id,
            artifact_generation=generation,
            expected_runtime=identity,
            home_dir=home,
            workspace=workspace,
            deadline_monotonic=runtime._read(plan.operation_id)["deadline_monotonic"],
        )
        if rollback:
            runtime.finish_rollback(plan.operation_id, functional_proof=observation)
        else:
            runtime.advance(plan.operation_id, "Switching", functional_proof=observation)
            runtime.advance(plan.operation_id, "CandidateFunctional", functional_proof=observation)
        state = runtime._read(plan.operation_id)
        assert state["phase"] == ("FailedWithVerifiedRollback" if rollback else "Committed")
        recorded = state["rollback_functional_proof" if rollback else "functional_proof"]
        assert recorded["allow_receipt"]["authority"] == "rust"
        assert recorded["allow_receipt"]["decision"] == "allow"
        assert recorded["deny_receipt"]["decision"] == "deny"
        assert recorded["runtime_identity"] == binding
        runtime.retire(plan.operation_id)
    finally:
        worker.close()
        assert close_native_residents(store.guard_home, deadline_monotonic=time.monotonic() + 3)


def test_committed_transition_cannot_be_reversed(transition):
    runtime, plan, _bindings, pointer = transition
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    runtime.publish(plan.operation_id, "HooksPrepared")
    for phase in ("Switching", "CandidateFunctional"):
        runtime.advance(plan.operation_id, phase, functional_proof=proof(plan, plan.candidate["generation"]))
    with pytest.raises(TransitionError, match="terminal_transition"):
        runtime.restore_files(plan.operation_id, first_cause="stale updater")
    assert pointer.read_bytes() == b"candidate pointer"


def test_phase_cannot_advance_before_planned_bytes_are_published(transition):
    runtime, plan, *_ = transition
    begin(runtime, plan)
    with pytest.raises(TransitionError, match="generation_changed"):
        runtime.advance(plan.operation_id, "AuthorizedForExactTransition")


def test_only_terminal_receipt_can_retire_and_reopen_install_admission(transition):
    runtime, plan, bindings, pointer = transition
    begin(runtime, plan)
    with pytest.raises(TransitionError, match="nonterminal_transition"):
        runtime.retire(plan.operation_id)
    runtime.restore_files(plan.operation_id, first_cause="failed before switching")
    runtime.finish_rollback(plan.operation_id, functional_proof=proof(plan, plan.predecessor["generation"]))
    runtime.retire(plan.operation_id)
    assert not runtime.path.exists()
    assert runtime.path.with_name("runtime-transition.previous.json").exists()
    assert_transition_mutation_allowed(plan.guard_home)
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"


def test_interrupted_publication_has_a_durable_inverse(transition, monkeypatch):
    from codex_plugin_scanner.guard import runtime_transition as module

    runtime, plan, bindings, pointer = transition
    begin(runtime, plan)
    original_write = module.atomic_write_bytes

    def interrupted_write(path, payload, **kwargs):
        original_write(path, payload, **kwargs)
        if path == bindings.resolve():
            raise OSError("injected publication interruption")

    with monkeypatch.context() as patch:
        patch.setattr(module, "atomic_write_bytes", interrupted_write)
        with pytest.raises(OSError, match="interruption"):
            runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    reopened = RuntimeTransition(plan.guard_home, runtime.authority)
    reopened.restore_files(plan.operation_id, first_cause="publication interrupted")
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"


def test_foreign_generation_preserved_with_original_and_recovery_causes(transition):
    runtime, plan, bindings, pointer = transition
    begin(runtime, plan)
    bindings.write_bytes(b"candidate hooks")
    pointer.write_bytes(b"a newer pointer")
    with pytest.raises(TransitionError, match="generation_changed"):
        runtime.restore_files(plan.operation_id, first_cause="first activation failure")
    assert bindings.read_bytes() == b"candidate hooks"
    assert pointer.read_bytes() == b"a newer pointer"
    state = runtime._read(plan.operation_id)
    assert state["phase"] == "RecoveryRequired"
    assert state["first_cause"] == "first activation failure"
    assert state["recovery_causes"] == [{"code": "generation_changed", "errno": None}]


def test_stale_operation_cannot_restore_or_advance(transition):
    runtime, plan, *_ = transition
    begin(runtime, plan)
    with pytest.raises(TransitionError, match="operation_superseded"):
        runtime.restore_files("earlier-operation", first_cause="stale completion")
    with pytest.raises(TransitionError, match="phase_changed"):
        runtime.advance(plan.operation_id, "Switching")


def test_restart_can_only_restore_signed_inverse_not_replay_forward(transition, monkeypatch):
    from codex_plugin_scanner.guard import runtime_transition as module

    runtime, plan, bindings, pointer = transition
    begin(runtime, plan)
    bindings.write_bytes(b"candidate hooks")
    pointer.write_bytes(b"candidate pointer")
    monkeypatch.setattr(module, "current_process_identity", lambda: {"pid": 42, "startToken": "replacement"})
    with pytest.raises(TransitionError, match="forward_owner_changed"):
        runtime.advance(plan.operation_id, "AuthorizedForExactTransition")
    reopened = RuntimeTransition(plan.guard_home, runtime.authority)
    reopened.restore_files(plan.operation_id, first_cause="updater exited")
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"


def test_tampered_journal_cannot_restore_bytes(transition):
    runtime, plan, bindings, *_ = transition
    begin(runtime, plan)
    state = json.loads(runtime.path.read_text())
    state["files"][0]["before"] = "ZXZpbA=="
    runtime.path.write_text(json.dumps(state))
    with pytest.raises(TransitionError, match="record_unauthenticated"):
        runtime.restore_files(plan.operation_id, first_cause="rollback")
    assert bindings.read_bytes() == b"previous hooks"


def test_pending_transition_excludes_unowned_installs(transition):
    runtime, plan, *_ = transition
    begin(runtime, plan)
    with pytest.raises(TransitionError, match="pending_transition"):
        assert_transition_mutation_allowed(plan.guard_home)


def test_exact_gate_grant_cannot_authorize_changed_candidate_or_plan(transition):
    runtime, plan, *_ = transition
    password = "isolated-transition-fixture-password"
    update_settings(plan.guard_home, {"enabled": True, "new_password": password, "confirm_password": password})
    grant = require_high_risk(
        plan.guard_home,
        purpose="protection_lifecycle",
        approval_gate_input=ApprovalGateInput(password=password),
        action="runtime.transition",
        scope="local-protection",
        subject=plan.subject(),
    )
    changed = replace(plan, candidate={**plan.candidate, "generation": "c" * 64})
    with pytest.raises(ApprovalGateError):
        runtime.begin(changed, authority_home=plan.guard_home, grant=grant)
    assert not runtime.path.exists()
    runtime.begin(plan, authority_home=plan.guard_home, grant=grant)
    assert "password" not in runtime.path.read_text()
    assert grant.grant_id not in runtime.path.read_text()


def test_expired_forward_window_does_not_prevent_exact_inverse(transition, monkeypatch):
    from codex_plugin_scanner.guard import runtime_transition as module

    runtime, plan, bindings, *_ = transition
    begin(runtime, plan)
    bindings.write_bytes(b"candidate hooks")
    deadline = runtime._read(plan.operation_id)["deadline_monotonic"]
    monkeypatch.setattr(module.time, "time", lambda: plan.deadline_epoch - 3600)
    monkeypatch.setattr(module.time, "monotonic", lambda: deadline + 1)
    with pytest.raises(TransitionError, match="deadline_exceeded"):
        runtime.advance(plan.operation_id, "AuthorizedForExactTransition")
    runtime.restore_files(plan.operation_id, first_cause="deadline")
    assert bindings.read_bytes() == b"previous hooks"


def test_alternate_disabled_home_cannot_bypass_canonical_approval_gate(transition):
    runtime, plan, *_ = transition
    password = "isolated-canonical-transition-password"
    update_settings(plan.guard_home, {"enabled": True, "new_password": password, "confirm_password": password})
    with pytest.raises(TransitionError, match="approval_authority_mismatch"):
        runtime.begin(plan, authority_home=plan.guard_home.parent / "unguarded-home", grant=None)
    assert not runtime.path.exists()


def test_revoked_grant_and_reopened_object_cannot_publish_from_signed_record(transition):
    from codex_plugin_scanner.guard import approval_gate

    runtime, plan, bindings, pointer = transition
    password = "isolated-transition-revocation-password"
    update_settings(plan.guard_home, {"enabled": True, "new_password": password, "confirm_password": password})
    grant = require_high_risk(
        plan.guard_home,
        purpose="protection_lifecycle",
        approval_gate_input=ApprovalGateInput(password=password),
        action="runtime.transition",
        scope="local-protection",
        subject=plan.subject(),
    )
    runtime.begin(plan, authority_home=plan.guard_home, grant=grant)
    reopened = RuntimeTransition(plan.guard_home, runtime.authority)
    with pytest.raises(ApprovalGateError):
        reopened.publish(plan.operation_id, "AuthorizedForExactTransition")
    approval_gate._invalidate_active_grants(plan.guard_home)
    with pytest.raises(ApprovalGateError):
        runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"
    reopened.restore_files(plan.operation_id, first_cause="grant revoked")


def test_plan_cannot_replace_its_own_record_or_shared_hook_key(transition):
    runtime, plan, *_ = transition
    for target in (runtime.path, plan.guard_home / "managed/codex/hook-manifest.key"):
        invalid = replace(plan, files=(TransitionFile(target, None, b"unauthorized authority bytes"), *plan.files[2:]))
        with pytest.raises(TransitionError, match="authority_target_forbidden"):
            runtime.begin(invalid, authority_home=plan.guard_home, grant=None)
    assert not runtime.path.exists()


CRASH_TRANSITION = r"""
import os, sys, time
from pathlib import Path
from codex_plugin_scanner.guard import runtime_transition as module
from codex_plugin_scanner.guard.cli import commands_lifecycle_gate
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
root = Path(sys.argv[1])
phase = sys.argv[2]
home = root / "guard-home"
commands_lifecycle_gate.canonical_lifecycle_home = lambda: home
class FixtureAuthority:
    def __init__(self):
        self.key = bytes.fromhex(sys.stdin.read())
    def _policy_integrity_secret_material(self, *, create):
        assert create is False
        return self.key, "isolated-policy-key"
artifact = {"version": "3.12.3", "source_commit": "a" * 40, "target": "fixture",
            "format": "onefile", "sha256": "a" * 64, "generation": "a" * 64,
            "path": str(root / "previous-core")}
plan = module.TransitionPlan("crashed-operation", home, artifact,
    {**artifact, "path": str(root / "candidate-core"), "generation": "b" * 64},
    (module.TransitionFile(root / "bindings", b"previous bindings", b"candidate bindings"),
     module.TransitionFile(root / "pointer", b"previous pointer", b"candidate pointer", kind="selection")),
    time.time() + 60)
from dataclasses import replace
from codex_plugin_scanner.guard.store import GuardStore
store = GuardStore(home)
before = {"harness": "codex", "active": True, "workspace": None,
          "manifest": {"generation": "previous"}, "updated_at": "2026-09-30T00:00:00Z"}
after = {**before, "manifest": {"generation": "candidate"}}
store.set_managed_install("codex", True, None, before["manifest"], before["updated_at"])
plan = replace(plan, managed_installs=(module.TransitionInstall("codex", before, after),))
original_write = module.atomic_write_bytes
def crash_after_write(path, payload, **kwargs):
    original_write(path, payload, **kwargs)
    if path == root / phase:
        os._exit(17)
module.atomic_write_bytes = crash_after_write
with codex_install_transaction(home, root / "bindings", actor="crash-fixture"):
    runtime = module.RuntimeTransition(home, FixtureAuthority(), install_store=store)
    runtime.begin(plan, authority_home=home, grant=None)
    if phase == "prepared":
        os._exit(17)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    runtime.publish(plan.operation_id, "HooksPrepared")
raise RuntimeError("crash boundary was not reached")
"""


@pytest.mark.parametrize("phase", ["prepared", "bindings", "pointer"])
def test_real_process_exit_releases_owner_and_recovers_transition_pair(tmp_path: Path, phase: str):
    root = tmp_path.resolve()
    home = root / "guard-home"
    bindings = root / "bindings"
    pointer = root / "pointer"
    bindings.write_bytes(b"previous bindings")
    pointer.write_bytes(b"previous pointer")
    bindings.chmod(0o600)
    pointer.chmod(0o600)
    authority = FixtureAuthority()
    result = subprocess.run(
        [sys.executable, "-c", CRASH_TRANSITION, str(root), phase],
        input=authority.key.hex().encode(),
        capture_output=True,
        timeout=15,
        env={**os.environ, "HOME": str(root), "USERPROFILE": str(root)},
    )
    assert result.returncode == 17, result.stderr.decode(errors="replace")
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(home)
    assert store.get_managed_install("codex") == install_row("codex", "candidate" if phase == "pointer" else "previous")
    with codex_install_transaction(home, bindings, actor="restart-recovery"):
        reopened = RuntimeTransition(home, authority, install_store=store)
        expected_phase = "HooksPrepared" if phase == "pointer" else "AuthorizedForExactTransition"
        with pytest.raises(TransitionError, match="forward_owner_changed"):
            reopened.advance("crashed-operation", expected_phase)
        reopened.restore_files("crashed-operation", first_cause="updater exited")
        reopened.restore_files("crashed-operation", first_cause="a repeated observation")
        assert reopened._read("crashed-operation")["first_cause"] == "updater exited"
    assert bindings.read_bytes() == b"previous bindings"
    assert pointer.read_bytes() == b"previous pointer"
    assert store.get_managed_install("codex") == install_row("codex", "previous")


def test_production_driver_restores_bindings_when_candidate_start_fails(transition):
    """A4: candidate start and predecessor restart both fail on the production driver.

    The executable is a real spawned program that exits. Admission, state
    authentication, and the coordinator stay on the production path. The
    result keeps the original start failure and the rollback start failure.
    """
    from codex_plugin_scanner.guard.runtime_transition_coordinator import RuntimeTransitionCoordinator
    from codex_plugin_scanner.guard.runtime_transition_daemon import TransitionDaemonDriver

    runtime, plan, bindings, pointer = transition
    script = b"#!/bin/sh\nexit 1\n"
    dependencies = []
    for _side, artifact in (("candidate", plan.candidate), ("predecessor", plan.predecessor)):
        path = Path(artifact["path"])
        path.write_bytes(script)
        path.chmod(0o700)
        dependencies.append(
            TransitionFile.artifact_dependency(
                {
                    "path": str(path),
                    "size": len(script),
                    "sha256": hashlib.sha256(script).hexdigest(),
                    "mode": 0o700,
                    "owner_uid": path.stat().st_uid,
                    "role": "artifact",
                }
            )
        )
    plan = replace(
        plan,
        files=(*plan.files, *dependencies),
        deadline_epoch=time.time() + 8,
    )

    def observe(artifact, daemon_identity, operation_id, *, deadline_monotonic):
        del daemon_identity, operation_id, deadline_monotonic
        raise AssertionError(f"hook observation without a live daemon: {artifact['generation']}")

    driver = TransitionDaemonDriver(
        runtime,
        plan,
        home_dir=plan.guard_home.parent,
        observe_hook=observe,
    )
    started = time.monotonic()
    result = RuntimeTransitionCoordinator(runtime, driver).activate(
        plan,
        authority_home=plan.guard_home,
        grant=None,
        deadline_monotonic=started + 8,
    )
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"
    assert result.phase == "RecoveryRequired"
    assert result.first_cause == "daemon_start_failed"
    assert any(item.get("code") == "daemon_start_failed" for item in result.recovery_causes)
    print(
        "A4 production driver phase="
        f"{result.phase} first_cause={result.first_cause} recovery={list(result.recovery_causes)}"
    )
