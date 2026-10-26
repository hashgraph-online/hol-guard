"""Candidate admission requires actual native enforcement, never a health bit."""

import time
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard import runtime_transition_admission as admission
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.native_runtime import native_runtime_status
from codex_plugin_scanner.guard.runtime_transition import TransitionError
from codex_plugin_scanner.guard.runtime_transition_admission import probe_native_protection
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.usefixtures("native_hook_force")
def test_real_native_candidate_admission_allows_benign_and_denies_canary(tmp_path):
    home, workspace = tmp_path / "home", tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard")
    worker = HookWorker(store=store, wait_for_native_policy=False)
    try:
        identity = native_runtime_status().identity
        assert identity is not None
        proof = probe_native_protection(
            worker=worker,
            operation_id="isolated-transition",
            artifact_generation="candidate-generation",
            expected_runtime=identity,
            home_dir=home,
            workspace=workspace,
            deadline_monotonic=time.monotonic() + 10,
        )
        assert proof.operation_id == "isolated-transition"
        assert proof.artifact_generation == "candidate-generation"
        assert proof.allow_receipt["decision"] == "allow"
        assert proof.allow_receipt["policy_action"] in {"allow", "warn"}
        assert proof.deny_receipt["decision"] == "deny"
        assert proof.allow_receipt["request_id"] != proof.deny_receipt["request_id"]
        assert proof.runtime_identity == identity
    finally:
        worker.close()
        assert close_native_residents(store.guard_home, deadline_monotonic=time.monotonic() + 3)


@pytest.mark.usefixtures("native_hook_force")
def test_candidate_admission_rejects_foreign_runtime_before_policy_publication(tmp_path):
    class Worker:
        def prepare_workspace_policy(self, *args, **kwargs):
            raise AssertionError("foreign runtime reached publication")

    identity = native_runtime_status().identity
    assert identity is not None
    with pytest.raises(TransitionError, match="admission_runtime_mismatch"):
        probe_native_protection(
            worker=Worker(),
            operation_id="transition",
            artifact_generation="candidate",
            expected_runtime=replace(identity, sha256="0" * 64),
            home_dir=tmp_path,
            workspace=tmp_path,
            deadline_monotonic=time.monotonic() + 1,
        )


def test_expired_admission_starts_no_native_probe(tmp_path, monkeypatch):
    def forbidden_status():
        raise AssertionError("expired admission started native discovery")

    monkeypatch.setattr(admission, "native_runtime_status", forbidden_status)
    with pytest.raises(TransitionError, match="admission_deadline_expired"):
        probe_native_protection(
            worker=None,
            operation_id="transition",
            artifact_generation="candidate",
            expected_runtime=None,
            home_dir=tmp_path,
            workspace=tmp_path,
            deadline_monotonic=time.monotonic() - 1,
        )


@pytest.mark.usefixtures("native_hook_force")
@pytest.mark.parametrize("fault", ["mode", "policy_digest", "runtime_identity", "generation"])
def test_unbound_policy_starts_no_admission_hook(tmp_path, monkeypatch, fault):
    identity = native_runtime_status().identity
    assert identity is not None

    class Worker:
        def prepare_workspace_policy(self, *args, **kwargs):
            snapshot = {
                "mode": "enforce",
                "policy_digest": "a" * 64,
                "runtime_identity": identity.sha256,
                "generation": 1,
            }
            snapshot[fault] = {
                "mode": "observe",
                "policy_digest": None,
                "runtime_identity": "0" * 64,
                "generation": True,
            }[fault]
            return snapshot

    def forbidden_edge(**kwargs):
        raise AssertionError("unbound policy reached native probe")

    monkeypatch.setattr(admission, "review_raw_hook_native", forbidden_edge)
    with pytest.raises(TransitionError, match="admission_policy_mismatch"):
        probe_native_protection(
            worker=Worker(),
            operation_id="transition",
            artifact_generation="candidate",
            expected_runtime=identity,
            home_dir=tmp_path,
            workspace=tmp_path,
            deadline_monotonic=time.monotonic() + 1,
        )
