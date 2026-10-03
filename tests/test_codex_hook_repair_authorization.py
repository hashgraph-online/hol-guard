"""Repair grants cannot be borrowed from activation, another owner or a retry."""

import os
import select
import signal
import time
import uuid
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard import codex_hook_manifest as manifests
from codex_plugin_scanner.guard import codex_hook_repair as repair
from codex_plugin_scanner.guard.adapters import codex as adapter
from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    require_high_risk,
    update_settings,
)
from codex_plugin_scanner.guard.cli import commands_lifecycle_gate as lifecycle
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.runtime_transition import TransitionError

from .test_codex_hook_recovery import installed  # noqa: F401 -- shared isolated fixture
from .test_codex_publication_preparation import _tree

PASSWORD = "isolated-repair-fixture-password"


@pytest.fixture
def prepared_repair(installed, monkeypatch):  # noqa: F811 -- shared pytest fixture
    context, config, manifest = installed
    manifest.unlink()
    prepared = manifests.prepare_authenticated_hook_manifest_repair(adapter._hook_manifest_spec(context))
    monkeypatch.setattr(lifecycle, "canonical_lifecycle_home", lambda: context.guard_home)
    update_settings(context.guard_home, {"enabled": True, "new_password": PASSWORD, "confirm_password": PASSWORD})
    return context, config, manifest, prepared


def _grant(plan, owner, *, action=None, subject=None, nonce=None):
    return require_high_risk(
        plan.guard_home,
        purpose="protection_lifecycle",
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        action=action or manifests.CODEX_AUTHORITY_REPAIR_ACTION,
        scope="local-protection",
        subject=subject or plan.subject(),
        session_nonce=nonce or owner.operation_id,
    )


def test_exact_repair_grant_is_owner_bound_and_read_only(prepared_repair, tmp_path):
    context, config, manifest, prepared = prepared_repair
    with codex_install_transaction(context.guard_home, config, actor=manifests.CODEX_AUTHORITY_REPAIR_ACTION) as owner:
        grant = _grant(prepared, owner)
        before = _tree(tmp_path)
        authorization = repair.authorize_codex_hook_repair(
            prepared,
            authority_home=context.guard_home,
            grant=grant,
            deadline_monotonic=time.monotonic() + 5,
        )
        authorization.compare_before()
        assert _tree(tmp_path) == before
        assert not manifest.exists()
    with pytest.raises(CodexHookIntegrityError):
        authorization.check()


@pytest.mark.parametrize("failure", ["activation", "subject", "nonce", "missing"])
def test_other_grant_cannot_authorize_repair(prepared_repair, failure):
    context, config, manifest, prepared = prepared_repair
    with codex_install_transaction(context.guard_home, config, actor=manifests.CODEX_AUTHORITY_REPAIR_ACTION) as owner:
        grant = (
            None
            if failure == "missing"
            else _grant(
                prepared,
                owner,
                action="runtime.transition" if failure == "activation" else None,
                subject="another-plan" if failure == "subject" else None,
                nonce="another-owner" if failure == "nonce" else None,
            )
        )
        with pytest.raises(ApprovalGateError):
            repair.authorize_codex_hook_repair(
                prepared, authority_home=context.guard_home, grant=grant, deadline_monotonic=time.monotonic() + 5
            )
    assert not manifest.exists()


def test_claimed_grant_cannot_reauthorize_after_failed_generation_check(prepared_repair):
    context, config, manifest, prepared = prepared_repair
    with codex_install_transaction(context.guard_home, config, actor=manifests.CODEX_AUTHORITY_REPAIR_ACTION) as owner:
        grant = _grant(prepared, owner)
        original = config.read_bytes()
        config.write_bytes(original + b"\n# intervening generation\n")
        with pytest.raises(TransitionError, match="generation_changed"):
            repair.authorize_codex_hook_repair(
                prepared, authority_home=context.guard_home, grant=grant, deadline_monotonic=time.monotonic() + 5
            )
        config.write_bytes(original)
        with pytest.raises(TransitionError, match="authorization_claimed"):
            repair.authorize_codex_hook_repair(
                prepared, authority_home=context.guard_home, grant=grant, deadline_monotonic=time.monotonic() + 5
            )
    assert not manifest.exists()


@pytest.mark.parametrize("pending", ["runtime-transition.json", "codex/pending-hook-publication.json"])
def test_pending_operation_excludes_repair_authorization(prepared_repair, pending):
    context, config, manifest, prepared = prepared_repair
    path = context.guard_home / "managed" / pending
    path.write_bytes(b"isolated pending operation")
    with (
        codex_install_transaction(context.guard_home, config, actor=manifests.CODEX_AUTHORITY_REPAIR_ACTION),
        pytest.raises(TransitionError, match="pending"),
    ):
        repair.authorize_codex_hook_repair(
            prepared, authority_home=context.guard_home, grant=None, deadline_monotonic=time.monotonic() + 5
        )
    assert path.read_bytes() == b"isolated pending operation"
    assert not manifest.exists()


def test_plan_change_invalidates_exact_repair_grant(prepared_repair):
    context, config, manifest, prepared = prepared_repair
    with codex_install_transaction(context.guard_home, config, actor=manifests.CODEX_AUTHORITY_REPAIR_ACTION) as owner:
        grant = _grant(prepared, owner)
        changed = replace(prepared, operation_id=str(uuid.uuid4()))
        with pytest.raises(ApprovalGateError):
            repair.authorize_codex_hook_repair(
                changed, authority_home=context.guard_home, grant=grant, deadline_monotonic=time.monotonic() + 5
            )
    assert not manifest.exists()


def test_short_parent_deadline_cannot_reset_a_claimed_proof(prepared_repair, monkeypatch):
    context, config, manifest, prepared = prepared_repair
    with codex_install_transaction(context.guard_home, config, actor=manifests.CODEX_AUTHORITY_REPAIR_ACTION) as owner:
        grant = _grant(prepared, owner)
        authorization = repair.authorize_codex_hook_repair(
            prepared,
            authority_home=context.guard_home,
            grant=grant,
            deadline_monotonic=time.monotonic() + 5,
        )
        expired = authorization.deadline_monotonic + 1
        with monkeypatch.context() as patch:
            patch.setattr(repair.time, "monotonic", lambda: expired)
            with pytest.raises(TransitionError, match="deadline_exceeded"):
                authorization.check()
            with pytest.raises(TransitionError, match="authorization_claimed"):
                repair.authorize_codex_hook_repair(
                    prepared, authority_home=context.guard_home, grant=grant, deadline_monotonic=expired + 5
                )
    assert not manifest.exists()


def test_ordinary_installer_owner_cannot_authorize_repair(prepared_repair):
    context, config, manifest, prepared = prepared_repair
    with (
        codex_install_transaction(context.guard_home, config, actor="install"),
        pytest.raises(TransitionError, match="owner_mismatch"),
    ):
        repair.authorize_codex_hook_repair(
            prepared, authority_home=context.guard_home, grant=None, deadline_monotonic=time.monotonic() + 5
        )
    assert not manifest.exists()


def test_proof_from_previous_owner_cannot_authorize_new_owner(prepared_repair):
    context, config, manifest, prepared = prepared_repair
    with codex_install_transaction(context.guard_home, config, actor=manifests.CODEX_AUTHORITY_REPAIR_ACTION) as owner:
        grant = _grant(prepared, owner)
    with (
        codex_install_transaction(context.guard_home, config, actor=manifests.CODEX_AUTHORITY_REPAIR_ACTION),
        pytest.raises(ApprovalGateError),
    ):
        repair.authorize_codex_hook_repair(
            prepared, authority_home=context.guard_home, grant=grant, deadline_monotonic=time.monotonic() + 5
        )
    assert not manifest.exists()


def test_gate_revocation_invalidates_existing_repair_authorization(prepared_repair):
    context, config, manifest, prepared = prepared_repair
    with codex_install_transaction(context.guard_home, config, actor=manifests.CODEX_AUTHORITY_REPAIR_ACTION) as owner:
        authorization = repair.authorize_codex_hook_repair(
            prepared,
            authority_home=context.guard_home,
            grant=_grant(prepared, owner),
            deadline_monotonic=time.monotonic() + 5,
        )
        settings_grant = require_high_risk(
            context.guard_home,
            purpose="settings_write",
            approval_gate_input=ApprovalGateInput(password=PASSWORD),
            action="settings.write",
            scope="local-protection",
            subject="generated gate revocation",
        )
        update_settings(context.guard_home, {"enabled": False}, approval_gate_grant=settings_grant)
        with pytest.raises(ApprovalGateError):
            authorization.check()
    assert not manifest.exists()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires actual process fork")
def test_fork_cannot_transfer_repair_authorization_or_owner_nonce(prepared_repair):
    context, config, manifest, prepared = prepared_repair
    with codex_install_transaction(context.guard_home, config, actor=manifests.CODEX_AUTHORITY_REPAIR_ACTION) as owner:
        grant = _grant(prepared, owner)
        authorization = repair.authorize_codex_hook_repair(
            prepared,
            authority_home=context.guard_home,
            grant=grant,
            deadline_monotonic=time.monotonic() + 5,
        )
    read_descriptor, write_descriptor = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_descriptor)
        outcome = b"failed"
        try:
            with codex_install_transaction(context.guard_home, config, actor=manifests.CODEX_AUTHORITY_REPAIR_ACTION):
                try:
                    authorization.check()
                except TransitionError:
                    pass
                else:
                    raise AssertionError("child accepted parent authorization")
                try:
                    repair.authorize_codex_hook_repair(
                        prepared,
                        authority_home=context.guard_home,
                        grant=grant,
                        deadline_monotonic=time.monotonic() + 5,
                    )
                except ApprovalGateError:
                    outcome = b"refused"
        except BaseException:
            pass
        os.write(write_descriptor, outcome)
        os.close(write_descriptor)
        os._exit(0 if outcome == b"refused" else 17)
    os.close(write_descriptor)
    reaped = False
    try:
        ready, _, _ = select.select([read_descriptor], [], [], 10)
        assert ready, "generated fork did not finish within its observation budget"
        assert os.read(read_descriptor, 16) == b"refused"
        _, status = os.waitpid(child, 0)
        reaped = True
        assert os.waitstatus_to_exitcode(status) == 0
    finally:
        os.close(read_descriptor)
        if not reaped:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
    assert not manifest.exists()
