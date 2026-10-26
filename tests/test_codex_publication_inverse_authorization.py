from __future__ import annotations

import hashlib
import time
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.adapters.codex import _hook_manifest_spec
from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    require_high_risk,
    update_settings,
)
from codex_plugin_scanner.guard.cli import commands_lifecycle_gate as lifecycle
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.codex_publication_inverse_authorization import authorize_codex_publication_inverse
from codex_plugin_scanner.guard.codex_publication_inverse_plan import (
    PUBLICATION_INVERSE_ACTION,
    bind_codex_publication_inverse_verification,
    prepare_authenticated_hook_publication_inverse,
)
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity
from codex_plugin_scanner.guard.runtime_transition import TransitionError

from .test_codex_hook_recovery import crash, installed  # noqa: F401 -- shared isolated fixture
from .test_codex_publication_inverse_plan import participant_digests

PASSWORD = "isolated-publication-inverse-password"


@pytest.fixture
def inverse(installed, tmp_path, monkeypatch):  # noqa: F811
    context, config, manifest = installed
    crash(context, "manifest")
    native = tmp_path / "comparison-native"
    native.write_bytes(b"comparison metadata fixture; never executed or admitted")
    native.chmod(0o700)
    metadata = native.stat()
    identity = NativeRuntimeIdentity(
        native, metadata.st_size, metadata.st_mtime_ns, hashlib.sha256(native.read_bytes()).hexdigest()
    )
    with codex_install_transaction(context.guard_home, config, actor="prepare-inverse-review"):
        plan = prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context))
        bound = bind_codex_publication_inverse_verification(
            plan,
            expected_runtime=identity,
            workspace=tmp_path,
            deadline_monotonic=time.monotonic() + 30,
        )
    monkeypatch.setattr(lifecycle, "canonical_lifecycle_home", lambda: context.guard_home)
    update_settings(context.guard_home, {"enabled": True, "new_password": PASSWORD, "confirm_password": PASSWORD})
    return context, config, manifest, plan, bound


def grant_for(plan, owner, *, action=None, subject=None, nonce=None):
    return require_high_risk(
        plan.guard_home,
        purpose="protection_lifecycle",
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        action=action or PUBLICATION_INVERSE_ACTION,
        scope="local-protection",
        subject=subject or plan.subject(),
        session_nonce=nonce or owner.operation_id,
    )


def test_exact_inverse_grant_is_read_only_and_owner_bound(inverse):
    context, config, manifest, _unbound, plan = inverse
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        grant = grant_for(plan, owner)
        authorization = authorize_codex_publication_inverse(
            plan,
            authority_home=context.guard_home,
            grant=grant,
            deadline_monotonic=time.monotonic() + 30,
        )
        authorization.compare_before()
    assert participant_digests(context, config, manifest) == before
    with pytest.raises(CodexHookIntegrityError):
        authorization.check()


@pytest.mark.parametrize("failure", ["action", "subject", "nonce", "missing"])
def test_foreign_grant_cannot_authorize_inverse(inverse, failure):
    context, config, manifest, _unbound, plan = inverse
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        grant = (
            None
            if failure == "missing"
            else grant_for(
                plan,
                owner,
                action="apps.repair.codex-authority" if failure == "action" else None,
                subject="different-inverse" if failure == "subject" else None,
                nonce="different-owner" if failure == "nonce" else None,
            )
        )
        with pytest.raises(ApprovalGateError):
            authorize_codex_publication_inverse(
                plan,
                authority_home=context.guard_home,
                grant=grant,
                deadline_monotonic=time.monotonic() + 30,
            )
    assert participant_digests(context, config, manifest) == before


def test_native_comparison_must_be_bound_before_approval(inverse):
    context, config, _manifest, unbound, _bound = inverse
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        grant = grant_for(unbound, owner)
        with pytest.raises(TransitionError) as failure:
            authorize_codex_publication_inverse(
                unbound,
                authority_home=context.guard_home,
                grant=grant,
                deadline_monotonic=time.monotonic() + 30,
            )
        assert failure.value.reason == "publication_inverse_native_binding_missing"


def test_failed_generation_check_consumes_grant_without_replay(inverse):
    context, config, _manifest, _unbound, plan = inverse
    original = config.read_bytes()
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        grant = grant_for(plan, owner)
        config.write_bytes(original + b"\n# intervening fixture generation\n")
        with pytest.raises(TransitionError):
            authorize_codex_publication_inverse(
                plan,
                authority_home=context.guard_home,
                grant=grant,
                deadline_monotonic=time.monotonic() + 30,
            )
        config.write_bytes(original)
        with pytest.raises(TransitionError) as failure:
            authorize_codex_publication_inverse(
                plan,
                authority_home=context.guard_home,
                grant=grant,
                deadline_monotonic=time.monotonic() + 30,
            )
        assert failure.value.reason == "publication_inverse_authorization_claimed"


def test_native_binding_change_invalidates_approved_subject(inverse):
    context, config, _manifest, _unbound, plan = inverse
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        grant = grant_for(plan, owner)
        changed = replace(plan, verification_workspace=plan.guard_home)
        with pytest.raises(ApprovalGateError):
            authorize_codex_publication_inverse(
                changed,
                authority_home=context.guard_home,
                grant=grant,
                deadline_monotonic=time.monotonic() + 30,
            )


def test_new_owner_cannot_borrow_previous_authorization(inverse):
    context, config, _manifest, _unbound, plan = inverse
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        authorization = authorize_codex_publication_inverse(
            plan,
            authority_home=context.guard_home,
            grant=grant_for(plan, owner),
            deadline_monotonic=time.monotonic() + 30,
        )
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION):
        with pytest.raises(TransitionError) as failure:
            authorization.check()
        assert failure.value.reason == "publication_inverse_owner_mismatch"


def test_inverse_authorization_preserves_parent_deadline(inverse, monkeypatch):
    from codex_plugin_scanner.guard import codex_publication_inverse_authorization as module

    context, config, _manifest, _unbound, plan = inverse
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        deadline = time.monotonic() + 30
        authorization = authorize_codex_publication_inverse(
            plan,
            authority_home=context.guard_home,
            grant=grant_for(plan, owner),
            deadline_monotonic=deadline,
        )
        assert authorization.deadline_monotonic <= deadline
        monkeypatch.setattr(module.time, "monotonic", lambda: deadline + 1)
        with pytest.raises(TransitionError) as failure:
            authorization.check()
        assert failure.value.reason == "deadline_exceeded"


def test_wrong_actor_cannot_claim_inverse_grant(inverse):
    context, config, _manifest, _unbound, plan = inverse
    with codex_install_transaction(context.guard_home, config, actor="apps.repair.codex-authority") as owner:
        with pytest.raises(TransitionError) as failure:
            authorize_codex_publication_inverse(
                plan,
                authority_home=context.guard_home,
                grant=grant_for(plan, owner),
                deadline_monotonic=time.monotonic() + 30,
            )
        assert failure.value.reason == "publication_inverse_owner_mismatch"


def test_revoked_grant_cannot_continue_inverse(inverse):
    context, config, manifest, _unbound, plan = inverse
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        authorization = authorize_codex_publication_inverse(
            plan,
            authority_home=context.guard_home,
            grant=grant_for(plan, owner),
            deadline_monotonic=time.monotonic() + 30,
        )
        settings_grant = require_high_risk(
            context.guard_home,
            purpose="settings_write",
            approval_gate_input=ApprovalGateInput(password=PASSWORD),
        )
        update_settings(context.guard_home, {"enabled": False}, approval_gate_grant=settings_grant)
        with pytest.raises(ApprovalGateError):
            authorization.compare_before()
    assert participant_digests(context, config, manifest) == before


def test_changed_native_comparison_cannot_continue_inverse(inverse):
    context, config, manifest, _unbound, plan = inverse
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        authorization = authorize_codex_publication_inverse(
            plan,
            authority_home=context.guard_home,
            grant=grant_for(plan, owner),
            deadline_monotonic=time.monotonic() + 30,
        )
        assert plan.native_runtime is not None
        plan.native_runtime.path.write_bytes(b"substituted native comparison")
        with pytest.raises(TransitionError):
            authorization.compare_before()
    assert participant_digests(context, config, manifest) == before


def test_foreign_authority_home_cannot_claim_inverse(inverse, tmp_path):
    context, config, manifest, _unbound, plan = inverse
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        with pytest.raises(TransitionError) as failure:
            authorize_codex_publication_inverse(
                plan,
                authority_home=tmp_path / "foreign-authority",
                grant=grant_for(plan, owner),
                deadline_monotonic=time.monotonic() + 30,
            )
        assert failure.value.reason == "approval_authority_mismatch"
    assert participant_digests(context, config, manifest) == before


def test_nonexecutable_native_comparison_cannot_continue_inverse(inverse):
    context, config, manifest, _unbound, plan = inverse
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        authorization = authorize_codex_publication_inverse(
            plan,
            authority_home=context.guard_home,
            grant=grant_for(plan, owner),
            deadline_monotonic=time.monotonic() + 30,
        )
        assert plan.native_runtime is not None
        plan.native_runtime.path.chmod(0o600)
        with pytest.raises(CodexHookIntegrityError):
            authorization.compare_before()
    assert participant_digests(context, config, manifest) == before
