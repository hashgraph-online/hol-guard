"""Native completion inputs belong to the exact approval, never launch override."""

import hashlib
import os
import time
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard import codex_hook_repair as repair
from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_hook_manifest import CODEX_AUTHORITY_REPAIR_ACTION
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity
from codex_plugin_scanner.guard.runtime_transition import TransitionError

from .test_codex_hook_recovery import installed  # noqa: F401 -- shared isolated fixture
from .test_codex_hook_repair_authorization import PASSWORD, _grant, prepared_repair  # noqa: F401 -- shared fixture
from .test_codex_publication_preparation import _tree


@pytest.fixture
def native_binding(prepared_repair, tmp_path):  # noqa: F811
    context, config, manifest, plan = prepared_repair
    # An inert comparison artifact: preparation must never execute it. Real
    # native receipts and their producer are a separate completion oracle.
    artifact = tmp_path / "comparison-native"
    content = b"#!/bin/sh\nexit 99\n"
    artifact.write_bytes(content)
    artifact.chmod(0o700)
    metadata = artifact.stat()
    identity = NativeRuntimeIdentity(
        artifact.resolve(), metadata.st_size, metadata.st_mtime_ns, hashlib.sha256(content).hexdigest()
    )
    workspace = tmp_path / "verification-workspace"
    workspace.mkdir()
    return context, config, manifest, plan, identity, workspace


def _prepare(plan, identity, workspace):
    return repair.prepare_codex_hook_repair_verification(
        plan,
        expected_runtime=identity,
        workspace=workspace.resolve(),
        deadline_monotonic=time.monotonic() + 5,
    )


def test_native_binding_is_read_only_and_changes_approved_subject(native_binding, tmp_path):
    _context, _config, manifest, plan, identity, workspace = native_binding
    before = _tree(tmp_path)
    prepared = _prepare(plan, identity, workspace)
    after = _tree(tmp_path)
    # A live resident refreshes its client-lease mtime; that liveness marker is
    # not a mutation of the protected native-binding inputs.
    after = {rel: entry for rel, entry in after.items() if "resident-client-leases.v1" not in rel}
    before = {rel: entry for rel, entry in before.items() if "resident-client-leases.v1" not in rel}
    assert after == before
    assert not manifest.exists()
    assert prepared.subject() != plan.subject()
    assert prepared.payload()["native_runtime"] == {
        "path": str(identity.path),
        "size": identity.size,
        "mtime_ns": identity.mtime_ns,
        "sha256": identity.sha256,
    }
    assert prepared.payload()["verification_workspace"] == str(workspace.resolve())
    assert sum(item.path == identity.path for item in prepared.files) == 1
    with pytest.raises(TransitionError, match="already_prepared"):
        _prepare(prepared, identity, workspace)


def test_old_grant_cannot_add_native_identity_after_approval(native_binding):
    context, config, manifest, plan, identity, workspace = native_binding
    with codex_install_transaction(context.guard_home, config, actor=CODEX_AUTHORITY_REPAIR_ACTION) as owner:
        grant = _grant(plan, owner)
        prepared = _prepare(plan, identity, workspace)
        with pytest.raises(ApprovalGateError):
            repair.authorize_codex_hook_repair(
                prepared, authority_home=context.guard_home, grant=grant, deadline_monotonic=time.monotonic() + 5
            )
    assert not manifest.exists()


@pytest.mark.parametrize("mutation", ["bytes", "mode", "symlink", "mtime"])
def test_changed_native_comparison_artifact_refuses_forward_publication(native_binding, mutation):
    context, config, manifest, plan, identity, workspace = native_binding
    prepared = _prepare(plan, identity, workspace)
    with codex_install_transaction(context.guard_home, config, actor=CODEX_AUTHORITY_REPAIR_ACTION) as owner:
        authorization = repair.authorize_codex_hook_repair(
            prepared,
            authority_home=context.guard_home,
            grant=_grant(prepared, owner),
            deadline_monotonic=time.monotonic() + 5,
        )
        if mutation == "bytes":
            identity.path.write_bytes(b"#!/bin/sh\nexit 98\n")
        elif mutation == "mode":
            identity.path.chmod(0o600)
        elif mutation == "symlink":
            other = identity.path.with_name("foreign-native")
            other.write_bytes(identity.path.read_bytes())
            identity.path.unlink()
            identity.path.symlink_to(other)
        else:
            os.utime(identity.path, ns=(identity.mtime_ns + 1, identity.mtime_ns + 1))
        with pytest.raises(TransitionError):
            repair.publish_codex_hook_repair(authorization)
    assert not manifest.exists()


def test_changed_workspace_cannot_reuse_exact_native_grant(native_binding):
    context, config, manifest, plan, identity, workspace = native_binding
    prepared = _prepare(plan, identity, workspace)
    other_workspace = workspace.with_name("other-workspace")
    other_workspace.mkdir()
    with codex_install_transaction(context.guard_home, config, actor=CODEX_AUTHORITY_REPAIR_ACTION) as owner:
        grant = _grant(prepared, owner)
        changed = replace(prepared, verification_workspace=other_workspace.resolve())
        with pytest.raises(ApprovalGateError):
            repair.authorize_codex_hook_repair(
                changed, authority_home=context.guard_home, grant=grant, deadline_monotonic=time.monotonic() + 5
            )
    assert not manifest.exists()


def test_unpinned_native_identity_is_not_a_valid_repair_plan(native_binding):
    _context, _config, _manifest, plan, identity, workspace = native_binding
    with pytest.raises(TransitionError, match="native_binding_invalid"):
        replace(plan, native_runtime=identity, verification_workspace=workspace.resolve()).payload()


@pytest.mark.usefixtures("native_hook_force")
@pytest.mark.parametrize(
    "boundary",
    [
        "commit",
        "commit-cleanup-crash",
        "wrong-native",
        "tampered-proof",
        "record-cap",
        "revoked-proof",
        "stale-proof",
    ],
)
def test_real_configured_hook_native_protection_commits_repair(
    prepared_repair,  # noqa: F811 -- shared isolated fixture
    tmp_path,
    monkeypatch,
    boundary,
):
    from codex_plugin_scanner.guard import codex_hook_recovery as recovery
    from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status
    from codex_plugin_scanner.guard.runtime_transition_admission import verified_admission_payload
    from codex_plugin_scanner.guard.store import GuardStore

    context, config, manifest, plan = prepared_repair
    identity = native_runtime_status().identity
    assert identity is not None
    if boundary == "wrong-native":
        comparison = tmp_path / "wrong-native-comparison"
        content = b"#!/bin/sh\nexit 99\n"
        comparison.write_bytes(content)
        comparison.chmod(0o700)
        metadata = comparison.stat()
        identity = NativeRuntimeIdentity(
            comparison.resolve(), metadata.st_size, metadata.st_mtime_ns, hashlib.sha256(content).hexdigest()
        )
    workspace = tmp_path / "native-repair-workspace"
    workspace.mkdir()
    prepared = _prepare(plan, identity, workspace)
    store = GuardStore(context.guard_home)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, home_dir=context.home_dir)
    daemon.start()
    try:
        with codex_install_transaction(context.guard_home, config, actor=CODEX_AUTHORITY_REPAIR_ACTION) as owner:
            authorization = repair.authorize_codex_hook_repair(
                prepared,
                authority_home=context.guard_home,
                grant=_grant(prepared, owner),
                deadline_monotonic=time.monotonic() + 45,
            )
            pending = repair.publish_codex_hook_repair(authorization)
            if boundary == "stale-proof":
                from codex_plugin_scanner.guard.runtime_transition_codex_observer import observe_configured_codex_hook

                old_proof = observe_configured_codex_hook(
                    operation_id=prepared.operation_id,
                    artifact_generation="codex-authority-repair-" + prepared.subject().rsplit(":", 1)[1],
                    expected_runtime=identity,
                    guard_home=context.guard_home,
                    config_path=config,
                    workspace=workspace.resolve(),
                    deadline_monotonic=authorization.deadline_monotonic,
                    receipt_store=store,
                )
                assert recovery.recover_hook_publication(context.guard_home)
                assert not manifest.exists()
                fresh_authorization = repair.authorize_codex_hook_repair(
                    prepared,
                    authority_home=context.guard_home,
                    grant=_grant(prepared, owner),
                    deadline_monotonic=authorization.deadline_monotonic,
                )
                pending = repair.publish_codex_hook_repair(fresh_authorization)
                with pytest.raises(CodexHookIntegrityError) as stale:
                    recovery._commit_verified_hook_repair_publication(
                        pending,
                        proof=old_proof,
                        started_monotonic=old_proof.observed_monotonic - 1,
                    )
                assert stale.value.reason == "codex_hook_recovery_repair_native_verification_invalid"
                assert recovery.hook_publication_pending(context.guard_home)
                assert recovery.recover_hook_publication(context.guard_home)
            if boundary == "record-cap":
                monkeypatch.setattr(recovery, "_MAX_RECORD", recovery._record_path(context.guard_home).stat().st_size)
            if boundary == "stale-proof":
                pass
            elif boundary == "commit-cleanup-crash":

                class CleanupCrash(BaseException):
                    pass

                def crash_cleanup(_home):
                    raise CleanupCrash

                with monkeypatch.context() as crash_patch:
                    crash_patch.setattr(recovery, "_remove_record", crash_cleanup)
                    with pytest.raises(CleanupCrash):
                        repair.verify_and_commit_codex_hook_repair(pending, receipt_store=store)
                assert recovery.hook_publication_pending(context.guard_home)
            elif boundary in {"wrong-native", "tampered-proof", "record-cap", "revoked-proof"}:
                tampered_proof_observed = False
                if boundary in {"tampered-proof", "revoked-proof"}:
                    from codex_plugin_scanner.guard import runtime_transition_codex_observer as observer

                    original_observe = observer.observe_configured_codex_hook

                    def tamper_proof(**kwargs):
                        nonlocal tampered_proof_observed
                        proof = original_observe(**kwargs)
                        if boundary == "tampered-proof":
                            assert proof.allow_receipt["decision"] == "allow"
                            proof.allow_receipt["decision"] = "deny"
                            tampered_proof_observed = True
                        else:
                            from codex_plugin_scanner.guard.approval_gate import (
                                ApprovalGateInput,
                                require_high_risk,
                                update_settings,
                            )

                            settings_grant = require_high_risk(
                                context.guard_home,
                                purpose="settings_write",
                                approval_gate_input=ApprovalGateInput(password=PASSWORD),
                                action="settings.write",
                                scope="local-protection",
                                subject="generated repair commit revocation",
                            )
                            update_settings(context.guard_home, {"enabled": False}, approval_gate_grant=settings_grant)
                        return proof

                    monkeypatch.setattr(observer, "observe_configured_codex_hook", tamper_proof)
                if boundary == "record-cap":
                    with pytest.raises(CodexHookIntegrityError) as capacity:
                        repair.verify_and_commit_codex_hook_repair(pending, receipt_store=store)
                    assert capacity.value.reason == "codex_hook_recovery_record_too_large"
                elif boundary == "revoked-proof":
                    with pytest.raises(ApprovalGateError):
                        repair.verify_and_commit_codex_hook_repair(pending, receipt_store=store)
                else:
                    with pytest.raises(TransitionError) as failure:
                        repair.verify_and_commit_codex_hook_repair(pending, receipt_store=store)
                    expected_reason = (
                        "admission_protection_failed" if boundary == "wrong-native" else "functional_proof_missing"
                    )
                    assert failure.value.reason == expected_reason
                    if boundary == "tampered-proof":
                        assert tampered_proof_observed
            else:
                proof = repair.verify_and_commit_codex_hook_repair(pending, receipt_store=store)
                observation = verified_admission_payload(proof)
                assert observation["allow_receipt"]["decision"] == "allow"
                assert observation["deny_receipt"]["decision"] == "deny"
                assert observation["runtime_identity"]["sha256"] == identity.sha256
                assert observation["installed_hook_evidence"]["harness"] == "codex"
        if boundary == "commit-cleanup-crash":
            with codex_install_transaction(context.guard_home, config, actor="isolated-commit-recovery"):
                assert recovery.recover_hook_publication(context.guard_home) is False
        if boundary in {"wrong-native", "tampered-proof", "record-cap", "revoked-proof", "stale-proof"}:
            assert not manifest.exists()
        else:
            assert manifest.read_bytes() == prepared.manifest_change.after
        assert not recovery.hook_publication_pending(context.guard_home)
    finally:
        daemon.stop()
        close_native_residents()


@pytest.mark.parametrize("proof", [True, {"verified": True}, object()])
def test_unsealed_completion_input_cannot_commit(native_binding, proof):
    from codex_plugin_scanner.guard import codex_hook_recovery as recovery

    context, config, manifest, plan, identity, workspace = native_binding
    prepared = _prepare(plan, identity, workspace)
    with codex_install_transaction(context.guard_home, config, actor=CODEX_AUTHORITY_REPAIR_ACTION) as owner:
        authorization = repair.authorize_codex_hook_repair(
            prepared,
            authority_home=context.guard_home,
            grant=_grant(prepared, owner),
            deadline_monotonic=time.monotonic() + 5,
        )
        pending = repair.publish_codex_hook_repair(authorization)
        with pytest.raises(TransitionError, match="functional_proof_missing"):
            recovery._commit_verified_hook_repair_publication(pending, proof=proof, started_monotonic=time.monotonic())
        assert recovery.hook_publication_pending(context.guard_home)
        assert recovery.recover_hook_publication(context.guard_home)
    assert not manifest.exists()
