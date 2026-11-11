"""Signed inverse qualification with real configured Codex/native decisions.

Artifact metadata remains a fixture. The owned-process case replaces real
daemon processes; this is not installed Desktop or signed-release qualification.
Hook argv, publication, store and proof are real.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import tempfile
import time
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from ci.guard_daemon_harness import GuardDaemonServer
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, require_high_risk, update_settings
from codex_plugin_scanner.guard.native_daemon_manage import _guard_daemon_pid_is_proven_dead
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.native_runtime import native_runtime_status
from codex_plugin_scanner.guard.runtime_transition import (
    RuntimeTransition,
    TransitionError,
    TransitionFile,
    TransitionInstall,
)
from codex_plugin_scanner.guard.runtime_transition_codex_observer import observe_configured_codex_hook
from codex_plugin_scanner.guard.runtime_transition_coordinator import RuntimeTransitionCoordinator
from codex_plugin_scanner.guard.runtime_transition_native_capture import (
    NativeCaptureError,
    _child_pids,
    _process_snapshot,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_daemon_state_signing import load_authenticated_daemon_state

from .test_runtime_transition import transition  # noqa: F401 -- isolated owner/authority fixture


def _descendant_pids(pid, deadline):
    """Every process below ``pid``: the daemon runs its native workers under
    its worker host, not as its own children."""

    found, frontier = [], [pid]
    while frontier:
        children = []
        for parent in frontier:
            try:
                children.extend(_child_pids(parent, deadline))
            except NativeCaptureError:
                continue
        found.extend(children)
        frontier = children
    return found


class OwnedDaemonLifecycle:
    """Runs the production daemon (``daemon-serve``) as a real owned process."""

    def __init__(self, home, guard, native_path):
        self.home, self.guard, self.native_path = home, guard, native_path
        self.child = None
        self.stop_requested = False
        self.pids, self.retired = [], []
        self.native_retired = []

    def start(self, deadline):
        from codex_plugin_scanner.guard.cli.daemon_serve import launch_configuration

        assert self.child is None
        self.log = tempfile.TemporaryFile()  # noqa: SIM115 -- closed with the child
        config = launch_configuration(self.guard, 0, user_home=self.home)
        config["workers"] = True
        # A pytest home idles out after seconds; this daemon lives across the transition.
        config["idle_timeout_seconds"] = None
        environment = {
            **os.environ,
            "HOME": str(self.home),
            "USERPROFILE": str(self.home),
            "HOL_GUARD_HOME": str(self.guard),
        }
        child = subprocess.Popen(
            [str(self.native_path), "daemon-serve", "--guard-home", str(config["guard_home"]), "--port", "0"],
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            # A full stderr pipe would stall the daemon; nothing drains it
            # until stop.
            stderr=self.log,
            start_new_session=True,
        )
        self.child = child
        self.stop_requested = False
        assert child.stdin is not None and child.stdout is not None
        child.stdin.write(json.dumps(config, separators=(",", ":")).encode("utf-8") + b"\n")
        child.stdin.flush()
        announced = child.stdout.readline()
        if announced and time.monotonic() < deadline:
            assert json.loads(announced)["pid"] == child.pid
            state = load_authenticated_daemon_state(self.guard)
            assert state is not None and state["pid"] == child.pid
            self.pids.append(child.pid)
            return
        raise RuntimeError(f"Owned daemon startup did not complete; exit={child.poll()}")

    def stop(self, deadline):
        assert self.child is not None
        child = self.child
        native = []
        while time.monotonic() < deadline:
            for pid in _descendant_pids(child.pid, deadline):
                try:
                    snapshot = _process_snapshot(pid, deadline)
                except NativeCaptureError:
                    # Startup/exit cannot provide usable process evidence.
                    # Wait for a stable cohort under the same caller deadline.
                    continue
                if snapshot.executable == self.native_path:
                    native.append(snapshot)
            if native:
                break
            time.sleep(0.01)
        assert native, "Capture actual native policy workers before retiring the daemon"
        assert all(snapshot.uid == os.getuid() for snapshot in native)
        self.stop_requested = True
        # `hol-guard daemon stop` retires the daemon with SIGTERM.
        child.send_signal(signal.SIGTERM)
        child.communicate(timeout=max(0.01, deadline - time.monotonic()))
        self.log.seek(0)
        assert child.returncode in {0, -signal.SIGTERM}, self.log.read()[-4000:]
        assert _guard_daemon_pid_is_proven_dead(child.pid)
        while time.monotonic() < deadline and not all(_guard_daemon_pid_is_proven_dead(item.pid) for item in native):
            time.sleep(0.01)
        assert all(_guard_daemon_pid_is_proven_dead(item.pid) for item in native)
        self.native_retired.extend(item.pid for item in native)
        self.retired.append(child.pid)
        self.child = None

    def cleanup(self):
        if self.child is None:
            return
        child = self.child
        try:
            if child.poll() is None and not self.stop_requested:
                child.send_signal(signal.SIGTERM)
            child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            child.terminate()
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)
        assert _guard_daemon_pid_is_proven_dead(child.pid)
        self.child = None


@pytest.mark.usefixtures("native_hook_force")
@pytest.mark.parametrize("owned_daemon_processes", [False, True])
def test_configured_native_inverse_restores_binding_store_and_selection(
    transition,  # noqa: F811 -- pytest fixture injection
    tmp_path,
    owned_daemon_processes,
):
    fixture_runtime, fixture_plan, _bindings, pointer = transition
    home, workspace = tmp_path / "hook-home", tmp_path / "hook-workspace"
    home.mkdir()
    workspace.mkdir()
    context = HarnessContext(home, None, fixture_runtime.home, home_override_explicit=True)
    store = GuardStore(context.guard_home)
    adapter = CodexHarnessAdapter()
    manifest = adapter.install(context)
    store.set_managed_install("codex", True, None, manifest, "isolated-native-inverse")
    identity = native_runtime_status().identity
    assert identity is not None
    metadata = identity.path.stat()
    native = {
        "path": str(identity.path),
        "size": identity.size,
        "mtime_ns": identity.mtime_ns,
        "sha256": identity.sha256,
    }
    dependency = TransitionFile.artifact_dependency(
        {
            **native,
            "owner_uid": metadata.st_uid,
            "mode": metadata.st_mode & 0o777,
            "role": "artifact",
        }
    )
    selection = next(change for change in fixture_plan.files if change.kind == "selection")
    runtime = RuntimeTransition(context.guard_home, store, install_store=store)
    password = "isolated-configured-native-inverse-password"
    update_settings(context.guard_home, {"enabled": True, "new_password": password, "confirm_password": password})
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, home_dir=home)
    lifecycle = OwnedDaemonLifecycle(home, context.guard_home, identity.path) if owned_daemon_processes else None
    events, proofs = [], []

    class Driver:
        def stop(self, artifact, *, deadline_monotonic):
            assert time.monotonic() < deadline_monotonic
            events.append(("stop", artifact["generation"]))
            if lifecycle is not None:
                lifecycle.stop(deadline_monotonic)

        def start(self, artifact, *, deadline_monotonic):
            assert time.monotonic() < deadline_monotonic
            events.append(("start", artifact["generation"]))
            if lifecycle is not None:
                lifecycle.start(deadline_monotonic)

        def observe_protection(self, artifact, operation_id, *, deadline_monotonic):
            observation = observe_configured_codex_hook(
                operation_id=operation_id,
                artifact_generation=artifact["generation"],
                expected_runtime=identity,
                guard_home=context.guard_home,
                config_path=home / ".codex/config.toml",
                workspace=workspace,
                deadline_monotonic=deadline_monotonic,
                receipt_store=store,
            )
            proofs.append(observation)
            if artifact == plan.candidate:
                assert pointer.read_bytes() == selection.after
                assert store.list_managed_installs()[0] == after_row
                raise TransitionError("injected_after_real_candidate_protection")
            assert pointer.read_bytes() == selection.before
            assert store.list_managed_installs()[0] == before_row
            return observation

    try:
        if lifecycle is None:
            daemon.start()
        else:
            lifecycle.start(time.monotonic() + 20)
        # Startup may refresh launchers; capture the actual running generation.
        before_row = store.list_managed_installs()[0]
        prepared = adapter.prepare_install(context)
        assert any(change.before != change.after for change in prepared.files), "exercise actual binding publication"
        before_files = {change.path: change.before for change in prepared.files if change.expected_digest is None}
        after_row = {**before_row, "manifest": prepared.manifest, "updated_at": "candidate-fixture"}
        plan = replace(
            fixture_plan,
            operation_id=str(uuid.uuid4()),
            files=(*prepared.files, selection, dependency),
            managed_installs=(TransitionInstall("codex", before_row, after_row),),
            native_runtimes={"candidate": native, "predecessor": native},
            deadline_epoch=time.time() + 60,
        )
        grant = require_high_risk(
            context.guard_home,
            purpose="protection_lifecycle",
            approval_gate_input=ApprovalGateInput(password=password),
            action="runtime.transition",
            scope="local-protection",
            subject=plan.subject(),
        )
        assert grant is not None
        result = RuntimeTransitionCoordinator(runtime, Driver()).activate(
            plan,
            authority_home=context.guard_home,
            grant=grant,
        )
        assert result.phase == "FailedWithVerifiedRollback", (result.first_cause, result.recovery_causes, events)
        # first_cause is whichever forward protection check failed first. The
        # intended trigger is the injected post-candidate error; but on the
        # owned-daemon param the real receipt validation inside
        # observe_configured_codex_hook can raise admission_protection_failed
        # before the injection point. Either is a legitimate forward failure.
        assert result.first_cause in {
            "injected_after_real_candidate_protection",
            "admission_protection_failed",
        }
        assert password not in runtime.path.read_text() and grant.grant_id not in runtime.path.read_text()
        assert len(proofs) == 2
        assert all(proof.allow_receipt["authority"] == "rust" for proof in proofs)
        assert all(
            proof.allow_receipt["decision"] == "allow" and proof.deny_receipt["decision"] == "deny" for proof in proofs
        )
        for path, before in before_files.items():
            assert (path.read_bytes() if path.exists() else None) == before
        assert events == [
            ("stop", plan.predecessor["generation"]),
            ("start", plan.candidate["generation"]),
            ("stop", plan.candidate["generation"]),
            ("start", plan.predecessor["generation"]),
        ]
        if lifecycle is not None:
            assert len(lifecycle.pids) == 3 and len(set(lifecycle.pids)) == 3
            assert lifecycle.retired == lifecycle.pids[:2]
            assert all(_guard_daemon_pid_is_proven_dead(pid) for pid in lifecycle.retired)
            assert len(lifecycle.native_retired) >= 2
        runtime.retire(plan.operation_id)
    finally:
        if lifecycle is None:
            daemon.stop()
        else:
            lifecycle.cleanup()
        assert close_native_residents(context.guard_home, deadline_monotonic=time.monotonic() + 5)
    receipt_path = os.environ.get("HOL_GUARD_INVERSE_QUALIFICATION_RECEIPT")
    if receipt_path is not None and lifecycle is not None:
        assert all(_guard_daemon_pid_is_proven_dead(pid) for pid in lifecycle.pids)
        receipt = {
            "scope": "source-configured-native-inverse",
            "installed_qualification": False,
            "artifact_metadata_fixture": True,
            "production_daemon_driver_used": False,
            "test_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "native_sha256": identity.sha256,
            "native_path": str(identity.path),
            "daemon_pids": lifecycle.pids,
            "retired_daemon_pids": lifecycle.retired,
            "retired_native_pids": lifecycle.native_retired,
            "all_daemon_pids_proven_dead": True,
            "exact_password_grant": True,
            "phase": result.phase,
            "first_cause": result.first_cause,
            "bindings_restored": True,
            "managed_install_restored": True,
            "selection_restored": True,
            "native_hook_proofs": [
                {
                    "allow": proof.allow_receipt["decision"],
                    "deny": proof.deny_receipt["decision"],
                    "allow_authority": proof.allow_receipt["authority"],
                    "deny_authority": proof.deny_receipt["authority"],
                }
                for proof in proofs
            ],
        }
        selected = Path(receipt_path)
        with selected.open("x", encoding="utf-8") as output:
            json.dump(receipt, output, indent=2)
        selected.chmod(0o600)
