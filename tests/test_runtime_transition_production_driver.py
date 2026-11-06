"""A1-A5, restart, adoption, and stale-admission races on the production driver.

The daemon executable is the reviewed onedir fixture when a live identity is
required. Hook decisions come from observe_configured_codex_hook or
probe_native_protection. Admission, state authentication, and grants are the
production objects.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    require_high_risk,
    update_settings,
)
from codex_plugin_scanner.guard.cli.desktop_runtime_transition import run_desktop_runtime_transition
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.daemon.live_identity import verified_live_guard_daemon_identity
from codex_plugin_scanner.guard.daemon.manager import (
    _guard_daemon_pid_is_proven_dead,
    _retire_guard_daemon_pid,
    ensure_guard_daemon,
    load_authenticated_daemon_state,
)
from codex_plugin_scanner.guard.live_process_identity import process_start_token
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity, native_runtime_status
from codex_plugin_scanner.guard.runtime_transition import (
    RuntimeTransition,
    TransitionError,
    TransitionFile,
    TransitionInstall,
    TransitionPlan,
)
from codex_plugin_scanner.guard.runtime_transition_admission import probe_native_protection
from codex_plugin_scanner.guard.runtime_transition_codex_observer import observe_configured_codex_hook
from codex_plugin_scanner.guard.runtime_transition_coordinator import RuntimeTransitionCoordinator
from codex_plugin_scanner.guard.runtime_transition_daemon import TransitionDaemonDriver
from codex_plugin_scanner.guard.store import GuardStore

from .test_runtime_transition import core_dependencies, transition  # noqa: F401


def packaged_executable() -> Path:
    configured = os.environ.get("HOL_GUARD_PACKAGED_EXECUTABLE")
    if not configured:
        pytest.skip("HOL_GUARD_PACKAGED_EXECUTABLE is unset")
    path = Path(configured)
    if not path.is_file():
        pytest.skip("HOL_GUARD_PACKAGED_EXECUTABLE is not a file")
    return path


CRASH_PHASES = (
    "authorized",
    "hooks-prepared",
    "switching",
    "candidate-functional",
    "restoring",
    "inverse-restored",
    "previous-functional",
)
CRASH_TRANSITION = r"""
import hashlib, json, os, sys, time
from pathlib import Path
phase, root_text, operation_id, native_text = sys.argv[1:]
root = Path(root_text)
native_path = Path(native_text)
home = root / "home"
guard = root / "guard-home"
home.mkdir(mode=0o700, exist_ok=True)
guard.mkdir(mode=0o700, exist_ok=True)
from codex_plugin_scanner.guard.cli import commands_lifecycle_gate
commands_lifecycle_gate.canonical_lifecycle_home = lambda: guard
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.native_runtime import native_runtime_status
from codex_plugin_scanner.guard.runtime_transition import (
    RuntimeTransition, TransitionFile, TransitionInstall, TransitionPlan,
)
from codex_plugin_scanner.guard.runtime_transition_admission import probe_native_protection
from codex_plugin_scanner.guard.store import GuardStore

def dependency(path: Path):
    data = path.read_bytes()
    metadata = path.stat()
    return TransitionFile.artifact_dependency({
        "path": str(path.resolve()), "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "mode": metadata.st_mode & 0o777, "owner_uid": metadata.st_uid, "role": "artifact",
    })

def executable(name: str) -> Path:
    path = root / name
    path.write_bytes(b"#!/bin/sh\nexit 1\n")
    path.chmod(0o700)
    return path

config = root / "config.toml"
pointer = root / "current.json"
config.write_bytes(b"previous hooks\n")
pointer.write_bytes(b"previous pointer\n")
config.chmod(0o600)
pointer.chmod(0o600)
previous_exec = executable("previous-core")
candidate_exec = executable("candidate-core")
identity = native_runtime_status().identity
if identity is None:
    raise SystemExit("native runtime identity unavailable")
native = {"path": str(identity.path), "size": identity.size, "mtime_ns": identity.mtime_ns, "sha256": identity.sha256}
before_row = {"harness": "codex", "active": True, "workspace": None,
              "manifest": {"generation": "previous", "managed_hook_config_path": str(config.resolve())},
              "updated_at": "2026-09-30T00:00:00Z"}
after_row = {"harness": "codex", "active": True, "workspace": None,
             "manifest": {"generation": "candidate", "managed_hook_config_path": str(config.resolve())},
             "updated_at": "2026-09-30T00:00:01Z"}
store = GuardStore(guard)
store.set_managed_install("codex", True, None, before_row["manifest"], before_row["updated_at"])
predecessor_generation = "a" * 64
candidate_generation = "b" * 64

def artifact(path: Path, version: str, generation: str):
    return {"version": version, "source_commit": "c" * 40, "target": "fixture", "format": "onefile",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "generation": generation,
            "path": str(path.resolve())}

plan = TransitionPlan(
    operation_id, guard, artifact(previous_exec, "3.16.1", predecessor_generation),
    artifact(candidate_exec, "3.16.2", candidate_generation),
    (TransitionFile(config, b"previous hooks\n", b"candidate hooks\n"),
     TransitionFile(pointer, b"previous pointer\n", b"candidate pointer\n", kind="selection"),
     dependency(previous_exec), dependency(candidate_exec), dependency(Path(identity.path))),
    time.time() + 50,
    managed_installs=(TransitionInstall("codex", before_row, after_row),),
    native_runtimes={"candidate": native, "predecessor": native},
)
worker = HookWorker(store=store, wait_for_native_policy=False)

def proof(generation: str):
    observed = probe_native_protection(
        worker=worker, operation_id=operation_id, artifact_generation=generation, expected_runtime=identity,
        home_dir=home, workspace=home, deadline_monotonic=time.monotonic() + 20,
    )
    (root / "native-decisions.json").write_text(json.dumps({
        "allow": observed.allow_receipt["decision"], "deny": observed.deny_receipt["decision"],
        "authority": observed.allow_receipt["authority"],
    }))
    return observed

def finish():
    close_native_residents(guard, deadline_monotonic=time.monotonic() + 3)
    os._exit(17)

try:
    with codex_install_transaction(guard, config, actor="crash-boundary"):
        runtime = RuntimeTransition(guard, store, install_store=store)
        runtime.begin(plan, authority_home=guard, grant=None)
        if phase == "authorized":
            finish()
        runtime.publish(operation_id, "AuthorizedForExactTransition")
        if phase == "hooks-prepared":
            finish()
        runtime.publish(operation_id, "HooksPrepared")
        if phase == "switching":
            finish()
        runtime.advance(operation_id, "Switching", functional_proof=proof(candidate_generation))
        if phase == "candidate-functional":
            finish()
        runtime.prepare_recovery(operation_id, first_cause="candidate_hook_failed")
        if phase == "restoring":
            finish()
        runtime.restore_files(operation_id, first_cause="candidate_hook_failed")
        if phase == "inverse-restored":
            finish()
        original = runtime._write
        def crash_after_previous(payload):
            original(payload)
            if payload.get("phase") == "PreviousFunctional":
                finish()
        runtime._write = crash_after_previous
        runtime.finish_rollback(operation_id, functional_proof=proof(predecessor_generation))
    raise SystemExit("crash boundary was not reached")
finally:
    close_native_residents(guard, deadline_monotonic=time.monotonic() + 3)
"""


def _retire_isolated_daemon(guard: Path) -> None:
    state = load_authenticated_daemon_state(guard)
    if not isinstance(state, dict) or type(state.get("pid")) is not int:
        return
    pid = state["pid"]
    deadline = time.monotonic() + 10
    token = process_start_token(pid, deadline_monotonic=deadline)
    if token is not None:
        _retire_guard_daemon_pid(
            pid,
            expected_guard_home=guard,
            expected_start_token=token,
            deadline_monotonic=deadline,
        )
    if not _guard_daemon_pid_is_proven_dead(pid):
        os.kill(pid, signal.SIGTERM)


def _packaged_version(executable: Path) -> str:
    metadata = next(executable.parent.glob("_internal/hol_guard-*.dist-info/METADATA"))
    for line in metadata.read_text().splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError("packaged version missing")


def _artifact(path: Path, version: str, generation: str, package_format: str) -> dict[str, str]:
    return {
        "version": version,
        "source_commit": hashlib.sha256(path.name.encode()).hexdigest()[:40],
        "target": "darwin",
        "format": package_format,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "generation": generation,
        "path": str(path.resolve()),
    }


def _dependency(path: Path) -> TransitionFile:
    metadata = path.stat()
    return TransitionFile.artifact_dependency(
        {
            "path": str(path.resolve()),
            "size": metadata.st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mode": metadata.st_mode & 0o777,
            "owner_uid": metadata.st_uid,
            "role": "artifact",
        }
    )


def _native_binding(identity: NativeRuntimeIdentity) -> dict[str, object]:
    return {"path": str(identity.path), "size": identity.size, "mtime_ns": identity.mtime_ns, "sha256": identity.sha256}


def _bundled_runtime(executable: Path) -> NativeRuntimeIdentity:
    path = executable.parent / "_internal" / "codex_plugin_scanner" / "_native" / "hol-guard-runtime"
    metadata = path.stat()
    return NativeRuntimeIdentity(
        path.resolve(),
        metadata.st_size,
        metadata.st_mtime_ns,
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def _guard(monkeypatch: pytest.MonkeyPatch, guard: Path) -> None:
    from codex_plugin_scanner.guard.cli import commands_lifecycle_gate

    guard.mkdir(mode=0o700, exist_ok=True)
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: guard)


@pytest.mark.usefixtures("native_hook_force")
def test_rebind_then_unauthenticated_daemon_state_restores_bindings(transition):  # noqa: F811
    """A1: publication succeeds, then stopping the old daemon fails closed."""

    runtime, plan, bindings, pointer = transition
    plan = core_dependencies(replace(plan, deadline_epoch=time.time() + 30))
    state_path = runtime.home / "daemon-state.json"
    state_path.write_bytes(b'{"unauthenticated":true}\n')
    state_path.chmod(0o600)

    def observe(artifact, daemon_identity, operation_id, *, deadline_monotonic):
        del artifact, daemon_identity, operation_id, deadline_monotonic
        raise AssertionError("protection observation ran without an authenticated daemon")

    driver = TransitionDaemonDriver(runtime, plan, home_dir=plan.guard_home.parent, observe_hook=observe)
    result = RuntimeTransitionCoordinator(runtime, driver).activate(
        plan,
        authority_home=plan.guard_home,
        grant=None,
        deadline_monotonic=time.monotonic() + 20,
    )
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"
    assert result.phase == "RecoveryRequired"
    assert result.first_cause == "daemon_identity_unavailable"
    assert any(item.get("code") == "daemon_identity_unavailable" for item in result.recovery_causes)
    assert result.phase not in {"Committed", "FailedWithVerifiedRollback"}
    print(f"A1 phase={result.phase} first_cause={result.first_cause} recovery={list(result.recovery_causes)}")


@pytest.mark.usefixtures("native_hook_force")
def test_enrollment_and_structural_admission_leave_the_active_runtime(transition):  # noqa: F811
    """A5: expected approval enrollment and a structural binding failure stay distinct."""

    runtime, original, bindings, pointer = transition
    plan = core_dependencies(replace(original, deadline_epoch=time.time() + 30))
    password = "isolated-transition-enrollment"
    update_settings(plan.guard_home, {"enabled": True, "new_password": password, "confirm_password": password})

    def observe(*args, **kwargs):
        del args, kwargs
        raise AssertionError("enrollment reached lifecycle")

    driver = TransitionDaemonDriver(runtime, plan, home_dir=plan.guard_home.parent, observe_hook=observe)
    with pytest.raises(ApprovalGateError) as enrollment:
        RuntimeTransitionCoordinator(runtime, driver).activate(
            plan,
            authority_home=plan.guard_home,
            grant=None,
            deadline_monotonic=time.monotonic() + 15,
        )
    structural = replace(plan, native_runtimes={})
    with pytest.raises(TransitionError) as structural_error:
        RuntimeTransitionCoordinator(runtime, driver).activate(
            structural,
            authority_home=plan.guard_home,
            grant=None,
            deadline_monotonic=time.monotonic() + 15,
        )
    assert enrollment.value.code == "approval_gate_required"
    assert structural_error.value.reason == "native_runtime_bindings_missing"
    assert enrollment.value.code != structural_error.value.reason
    assert bindings.read_bytes() == b"previous hooks"
    assert pointer.read_bytes() == b"previous pointer"
    assert not runtime.path.exists()
    print(f"A5 enrollment={enrollment.value.code} structural={structural_error.value.reason}")


@pytest.mark.usefixtures("native_hook_force")
def test_stale_native_admission_cannot_overwrite_a_newer_transition(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A stale native allow/deny result cannot finish or replace a newer operation."""

    guard = tmp_path / "guard-home"
    home = tmp_path / "home"
    _guard(monkeypatch, guard)
    home.mkdir(mode=0o700)
    bindings = tmp_path / "bindings.json"
    pointer = tmp_path / "current.json"
    bindings.write_bytes(b"previous hooks")
    pointer.write_bytes(b"previous pointer")
    bindings.chmod(0o600)
    pointer.chmod(0o600)
    identity = native_runtime_status().identity
    assert identity is not None
    native = _native_binding(identity)
    previous = tmp_path / "previous-core"
    candidate = tmp_path / "candidate-core"
    previous.write_bytes(b"#!/bin/sh\nexit 1\n")
    candidate.write_bytes(b"#!/bin/sh\nexit 1\n")
    previous.chmod(0o700)
    candidate.chmod(0o700)
    operation_id = str(uuid.uuid4())
    stale_operation = str(uuid.uuid4())
    candidate_generation = "b" * 64
    plan = TransitionPlan(
        operation_id,
        guard,
        _artifact(previous, "3.16.1", "a" * 64, "onefile"),
        _artifact(candidate, "3.16.2", candidate_generation, "onefile"),
        (
            TransitionFile(bindings, b"previous hooks", b"candidate hooks"),
            TransitionFile(pointer, b"previous pointer", b"candidate pointer", kind="selection"),
            _dependency(previous),
            _dependency(candidate),
            _dependency(identity.path),
        ),
        time.time() + 40,
        native_runtimes={"candidate": native, "predecessor": native},
    )
    store = GuardStore(guard)
    worker = HookWorker(store=store, wait_for_native_policy=False)
    runtime = RuntimeTransition(guard, store, install_store=store)
    try:
        stale = probe_native_protection(
            worker=worker,
            operation_id=stale_operation,
            artifact_generation=candidate_generation,
            expected_runtime=identity,
            home_dir=home,
            workspace=home,
            deadline_monotonic=time.monotonic() + 20,
        )
        assert stale.allow_receipt["decision"] == "allow"
        assert stale.deny_receipt["decision"] == "deny"
        assert stale.allow_receipt["authority"] == "rust"
        with codex_install_transaction(guard, bindings, actor="newer-transition"):
            runtime.begin(plan, authority_home=guard, grant=None)
            runtime.publish(operation_id, "AuthorizedForExactTransition")
            runtime.publish(operation_id, "HooksPrepared")
            with pytest.raises(TransitionError, match="functional_proof_missing"):
                runtime.advance(operation_id, "Switching", functional_proof=stale)
            assert runtime.status(operation_id).phase == "Switching"
            assert bindings.read_bytes() == b"candidate hooks"
            with pytest.raises(TransitionError, match="operation_superseded"):
                runtime.status(stale_operation)
            newer_phase = runtime.status(operation_id).phase
            assert newer_phase == "Switching"
        print(
            "A-warmup stale_proof=functional_proof_missing "
            f"newer_phase={newer_phase} allow={stale.allow_receipt['decision']} "
            f"deny={stale.deny_receipt['decision']}"
        )
    finally:
        worker.close()
        close_native_residents(guard, deadline_monotonic=time.monotonic() + 3)


@pytest.mark.usefixtures("native_hook_force")
def test_live_predecessor_is_adopted_and_not_reused_as_the_candidate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Adoption keeps a matching live daemon; a different generation is not adopted."""

    assert packaged_executable().is_file()
    guard = tmp_path / "guard-home"
    home = tmp_path / "home"
    _guard(monkeypatch, guard)
    home.mkdir(mode=0o700)
    bindings = tmp_path / "bindings.json"
    pointer = tmp_path / "current.json"
    bindings.write_bytes(b"previous hooks")
    pointer.write_bytes(b"previous pointer")
    bindings.chmod(0o600)
    pointer.chmod(0o600)
    candidate = tmp_path / "candidate-core"
    candidate.write_bytes(b"#!/bin/sh\nexit 1\n")
    candidate.chmod(0o700)
    identity = native_runtime_status().identity
    assert identity is not None
    native = _native_binding(identity)
    version = _packaged_version(packaged_executable())
    operation_id = str(uuid.uuid4())
    plan = TransitionPlan(
        operation_id,
        guard,
        _artifact(packaged_executable(), version, "a" * 64, "onedir"),
        _artifact(candidate, "0.0.0", "b" * 64, "onefile"),
        (
            TransitionFile(bindings, b"previous hooks", b"candidate hooks"),
            TransitionFile(pointer, b"previous pointer", b"candidate pointer", kind="selection"),
            _dependency(packaged_executable()),
            _dependency(candidate),
            _dependency(identity.path),
        ),
        time.time() + 40,
        native_runtimes={"candidate": native, "predecessor": native},
    )
    store = GuardStore(guard)
    runtime = RuntimeTransition(guard, store, install_store=store)

    def observe(artifact, daemon_identity, operation_id, *, deadline_monotonic):
        del artifact, daemon_identity, operation_id, deadline_monotonic
        raise AssertionError("adoption does not claim protection from process identity")

    driver = TransitionDaemonDriver(runtime, plan, home_dir=home, observe_hook=observe)
    try:
        ensure_guard_daemon(
            guard,
            home_dir=home,
            executable=packaged_executable(),
            deadline_monotonic=time.monotonic() + 25,
            background_maintenance=False,
        )
        _retire_isolated_daemon(guard)
        with codex_install_transaction(guard, bindings, actor="adoption"):
            runtime.begin(plan, authority_home=guard, grant=None)
            runtime.publish(operation_id, "AuthorizedForExactTransition")
            runtime.publish(operation_id, "HooksPrepared")
        ensure_guard_daemon(
            guard,
            home_dir=home,
            executable=packaged_executable(),
            deadline_monotonic=time.monotonic() + 25,
            background_maintenance=False,
        )
        live = verified_live_guard_daemon_identity(
            guard,
            expected_artifact=driver.bindings["predecessor"],
            deadline_monotonic=time.monotonic() + 10,
        )
        assert live is not None
        pid = live["pid"]
        with codex_install_transaction(guard, bindings, actor="adoption-start"):
            with pytest.raises(TransitionError, match="daemon_generation_changed"):
                driver.start(plan.candidate, deadline_monotonic=time.monotonic() + 10)
            assert (
                verified_live_guard_daemon_identity(
                    guard,
                    expected_artifact=driver.bindings["predecessor"],
                    deadline_monotonic=time.monotonic() + 5,
                )["pid"]
                == pid
            )
            runtime.prepare_recovery(operation_id, first_cause="candidate_generation_rejected")
            runtime.restore_files(operation_id, first_cause="candidate_generation_rejected")
            driver.start(plan.predecessor, deadline_monotonic=time.monotonic() + 10)
        adopted = verified_live_guard_daemon_identity(
            guard,
            expected_artifact=driver.bindings["predecessor"],
            deadline_monotonic=time.monotonic() + 5,
        )
        assert adopted is not None and adopted["pid"] == pid
        assert bindings.read_bytes() == b"previous hooks"
        assert pointer.read_bytes() == b"previous pointer"
        print(f"A-adopt rejected_candidate=daemon_generation_changed adopted_predecessor_pid={pid}")
    finally:
        _retire_isolated_daemon(guard)


@pytest.mark.usefixtures("native_hook_force")
def test_candidate_start_failure_restores_configured_hook_allow_and_deny(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """A2: candidate start fails and the restored hook still allows and denies."""

    assert packaged_executable().is_file()
    guard = tmp_path / "guard-home"
    home = tmp_path / "hook-home"
    workspace = tmp_path / "hook-workspace"
    _guard(monkeypatch, guard)
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    context = HarnessContext(home, workspace, guard, home_override_explicit=True, workspace_override_explicit=True)
    store = GuardStore(guard)
    adapter = CodexHarnessAdapter()
    manifest = adapter.install(context)
    store.set_managed_install("codex", True, str(workspace), manifest, "isolated-production-driver")
    identity = _bundled_runtime(packaged_executable())
    candidate = tmp_path / "candidate-core"
    candidate.write_bytes(b"#!/bin/sh\nexit 1\n")
    candidate.chmod(0o700)
    pointer = tmp_path / "current.json"
    pointer.write_bytes(b"previous pointer")
    pointer.chmod(0o600)
    version = _packaged_version(packaged_executable())
    operation_id = str(uuid.uuid4())
    proofs: list[object] = []

    def observe(artifact, daemon_identity, observed_operation, *, deadline_monotonic):
        del daemon_identity
        observation = observe_configured_codex_hook(
            operation_id=observed_operation,
            artifact_generation=str(artifact["generation"]),
            expected_runtime=identity,
            guard_home=guard,
            config_path=home / ".codex" / "config.toml",
            workspace=workspace,
            deadline_monotonic=deadline_monotonic,
            receipt_store=store,
        )
        proofs.append(observation)
        return observation

    try:
        ensure_guard_daemon(
            guard,
            home_dir=home,
            executable=packaged_executable(),
            deadline_monotonic=time.monotonic() + 25,
            background_maintenance=False,
        )
        _retire_isolated_daemon(guard)
        before_row = store.get_managed_install("codex")
        assert before_row is not None
        prepared = adapter.prepare_install(context)
        assert any(change.before != change.after for change in prepared.files)
        before_files = {change.path: change.before for change in prepared.files if change.expected_digest is None}
        after_row = {**before_row, "manifest": prepared.manifest, "updated_at": "candidate-production-driver"}
        native = _native_binding(identity)
        selection = TransitionFile(pointer, b"previous pointer", b"candidate pointer", kind="selection")
        plan = TransitionPlan(
            operation_id,
            guard,
            _artifact(packaged_executable(), version, "a" * 64, "onedir"),
            _artifact(candidate, "0.0.0", "b" * 64, "onefile"),
            (
                *prepared.files,
                selection,
                _dependency(packaged_executable()),
                _dependency(candidate),
                _dependency(identity.path),
            ),
            time.time() + 58,
            managed_installs=(TransitionInstall("codex", before_row, after_row),),
            native_runtimes={"candidate": native, "predecessor": native},
        )
        password = "isolated-production-driver-password"
        update_settings(guard, {"enabled": True, "new_password": password, "confirm_password": password})
        grant = require_high_risk(
            guard,
            purpose="protection_lifecycle",
            approval_gate_input=ApprovalGateInput(password=password),
            action="runtime.transition",
            scope="local-protection",
            subject=plan.subject(),
        )
        runtime = RuntimeTransition(guard, store, install_store=store)
        driver = TransitionDaemonDriver(runtime, plan, home_dir=home, observe_hook=observe)
        result = RuntimeTransitionCoordinator(runtime, driver).activate(
            plan,
            authority_home=guard,
            grant=grant,
            deadline_monotonic=time.monotonic() + 55,
        )
        assert result.phase == "FailedWithVerifiedRollback", (result.first_cause, result.recovery_causes)
        assert result.first_cause == "daemon_start_failed"
        assert len(proofs) == 1
        proof = proofs[0]
        assert proof.allow_receipt["decision"] == "allow"
        assert proof.deny_receipt["decision"] == "deny"
        assert proof.allow_receipt["authority"] == "rust"
        assert proof.allow_receipt["request_id"] != proof.deny_receipt["request_id"]
        for path, before in before_files.items():
            assert (path.read_bytes() if path.exists() else None) == before
        assert pointer.read_bytes() == b"previous pointer"
        assert store.get_managed_install("codex") == before_row
        print(
            "A2 phase="
            f"{result.phase} first_cause={result.first_cause} allow={proof.allow_receipt['decision']} "
            f"deny={proof.deny_receipt['decision']} authority={proof.allow_receipt['authority']}"
        )
    finally:
        _retire_isolated_daemon(guard)
        close_native_residents(guard, deadline_monotonic=time.monotonic() + 5)


@pytest.mark.usefixtures("native_hook_force")
@pytest.mark.parametrize("phase", CRASH_PHASES)
def test_restart_after_each_persisted_phase_recovers_through_the_production_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
):
    """A3: kill after each durable phase, then recover through the production CLI."""

    root = tmp_path.resolve()
    guard = root / "guard-home"
    _guard(monkeypatch, guard)
    operation_id = str(uuid.uuid4())
    native = os.environ["HOL_GUARD_NATIVE_BINARY"]
    completed = subprocess.run(
        [sys.executable, "-c", CRASH_TRANSITION, phase, str(root), operation_id, native],
        capture_output=True,
        timeout=90,
        env={**os.environ, "HOME": str(root), "USERPROFILE": str(root), "HOL_GUARD_HOME": str(guard)},
    )
    assert completed.returncode == 17, completed.stderr.decode(errors="replace")
    decisions = None
    if phase in {"candidate-functional", "restoring", "inverse-restored", "previous-functional"}:
        decisions = json.loads((root / "native-decisions.json").read_text())
        assert decisions["allow"] == "allow"
        assert decisions["deny"] == "deny"
        assert decisions["authority"] == "rust"
    newer = root / "newer-bindings"
    newer.write_bytes(b"newer operation")
    context = HarnessContext(root / "home", None, guard, home_override_explicit=True)
    store = GuardStore(guard)
    output = io.StringIO()
    code = run_desktop_runtime_transition(
        argparse_namespace(operation_id),
        context=context,
        store=store,
        output_stream=output,
    )
    recovered = json.loads(output.getvalue())
    assert code == 1
    assert recovered["phase"] == "RecoveryRequired"
    assert recovered["first_cause"]
    assert recovered["recovery_causes"]
    assert (root / "config.toml").read_bytes() == b"previous hooks\n"
    assert (root / "current.json").read_bytes() == b"previous pointer\n"
    again = io.StringIO()
    second = run_desktop_runtime_transition(
        argparse_namespace(operation_id),
        context=context,
        store=store,
        output_stream=again,
    )
    repeated = json.loads(again.getvalue())
    assert second == 1
    assert repeated["phase"] == "RecoveryRequired"
    assert repeated["first_cause"] == recovered["first_cause"]
    assert (root / "config.toml").read_bytes() == b"previous hooks\n"
    assert newer.read_bytes() == b"newer operation"
    with codex_install_transaction(guard, root / "config.toml", actor="stale-operation"):
        reopened = RuntimeTransition(guard, store, install_store=store)
        with pytest.raises(TransitionError, match="operation_superseded"):
            reopened.restore_files(str(uuid.uuid4()), first_cause="stale completion")
    assert newer.read_bytes() == b"newer operation"
    assert (root / "config.toml").read_bytes() == b"previous hooks\n"
    print(
        f"A3 phase={phase} result_phase={recovered['phase']} first_cause={recovered['first_cause']} "
        f"recovery={recovered['recovery_causes']}"
        + (
            ""
            if decisions is None
            else f" allow={decisions['allow']} deny={decisions['deny']} authority={decisions['authority']}"
        )
    )


def argparse_namespace(operation_id: str):
    import argparse

    return argparse.Namespace(
        desktop_command="transition-recover",
        operation_id=operation_id,
        deadline_epoch=time.time() + 50,
    )
