from __future__ import annotations

import json
import multiprocessing
import os
import time

import pytest

from codex_plugin_scanner.guard import codex_publication_inverse as publication
from codex_plugin_scanner.guard.adapters.codex import _hook_manifest_spec, codex_native_hook_state
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_hook_recovery import commit_hook_publication, recover_hook_publication
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.codex_publication_inverse_authorization import authorize_codex_publication_inverse
from codex_plugin_scanner.guard.codex_publication_inverse_plan import (
    PUBLICATION_INVERSE_ACTION,
    bind_codex_publication_inverse_verification,
    prepare_authenticated_hook_publication_inverse,
)
from codex_plugin_scanner.guard.runtime_transition import TransitionError

from .test_codex_hook_recovery import installed  # noqa: F401 -- isolated fixture dependency
from .test_codex_publication_inverse_authorization import grant_for, inverse  # noqa: F401 -- isolated fixture
from .test_codex_publication_inverse_plan import participant_digests


def authorize(context, plan, owner):
    return authorize_codex_publication_inverse(
        plan,
        authority_home=context.guard_home,
        grant=grant_for(plan, owner),
        deadline_monotonic=time.monotonic() + 30,
    )


def test_publication_restores_authority_before_config_and_retains_journal(inverse, monkeypatch):  # noqa: F811
    context, config, manifest, _unbound, plan = inverse
    writes = []
    original = publication.atomic_write_bytes

    def record_write(path, value, **kwargs):
        if path in {change.path for change in plan.changes}:
            writes.append(path)
        return original(path, value, **kwargs)

    monkeypatch.setattr(publication, "atomic_write_bytes", record_write)
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        pending = publication.publish_codex_publication_inverse(authorize(context, plan, owner))
        pending.compare()
        for change in plan.changes:
            assert change.path.read_bytes() == change.after
        journal = context.guard_home / "managed/codex/pending-hook-publication.json"
        record = json.loads(journal.read_bytes())
        marker = record["publication_inverse"]
        assert marker["phase"] == "restored"
        assert marker["restored"] == [1, 2, 0]
        assert marker["subject"] == plan.subject()
        assert "grant_id" not in json.dumps(marker)
        assert "native_verification" not in marker
        assert writes == [
            change.path
            for change in (plan.changes[1], plan.changes[2], plan.changes[0])
            if change.before != change.after
        ]
    assert manifest.exists() and journal.exists()
    with pytest.raises(CodexHookIntegrityError):
        pending.compare()


@pytest.mark.parametrize("operation", [recover_hook_publication, commit_hook_publication])
def test_ordinary_recovery_and_commit_refuse_explicit_inverse(inverse, operation):  # noqa: F811
    context, config, manifest, _unbound, plan = inverse
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        publication.publish_codex_publication_inverse(authorize(context, plan, owner))
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor="ordinary-publication-recovery"):
        with pytest.raises(CodexHookIntegrityError) as failure:
            operation(context.guard_home)
        assert failure.value.reason == "codex_hook_recovery_explicit_inverse_pending"
        review = prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context))
        assert review.resumed_inverse_operation_id == plan.operation_id
        assert review.summary()["authorized"] is False
        assert review.subject() != plan.subject()
    assert participant_digests(context, config, manifest) == before
    print(f"H4 pass ordinary_recovery={failure.value.reason} bytes_unchanged=true")


def test_foreign_generation_before_publication_preserves_all_participants(inverse):  # noqa: F811
    context, config, manifest, _unbound, plan = inverse
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        authorization = authorize(context, plan, owner)
        config.write_bytes(config.read_bytes() + b"\n# competing generation\n")
        before = participant_digests(context, config, manifest)
        with pytest.raises(TransitionError):
            publication.publish_codex_publication_inverse(authorization)
    assert participant_digests(context, config, manifest) == before
    print("H3 pass stale_publication_preserves_winner=true")


def test_native_failure_retains_provisional_inverse(inverse, monkeypatch):  # noqa: F811
    from codex_plugin_scanner.guard import runtime_transition_codex_observer as observer

    context, config, manifest, _unbound, plan = inverse

    def fail_native(**kwargs):
        raise TransitionError("injected_configured_native_failure")

    monkeypatch.setattr(observer, "observe_configured_codex_hook", fail_native)
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        pending = publication.publish_codex_publication_inverse(authorize(context, plan, owner))
        before = participant_digests(context, config, manifest)
        with pytest.raises(TransitionError) as failure:
            publication.verify_and_retire_codex_publication_inverse(pending)
        assert failure.value.reason == "injected_configured_native_failure"
        pending.compare()
    assert participant_digests(context, config, manifest) == before


def test_serialized_native_assertion_cannot_retire_inverse(inverse, monkeypatch):  # noqa: F811
    from codex_plugin_scanner.guard import runtime_transition_codex_observer as observer

    context, config, manifest, _unbound, plan = inverse
    monkeypatch.setattr(observer, "observe_configured_codex_hook", lambda **kwargs: {"verified": True})
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        pending = publication.publish_codex_publication_inverse(authorize(context, plan, owner))
        before = participant_digests(context, config, manifest)
        with pytest.raises(TransitionError) as failure:
            publication.verify_and_retire_codex_publication_inverse(pending)
        assert failure.value.reason == "functional_proof_missing"
    assert participant_digests(context, config, manifest) == before


def test_same_byte_config_substitution_after_restore_preserves_journal(inverse):  # noqa: F811
    context, config, manifest, _unbound, plan = inverse
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        pending = publication.publish_codex_publication_inverse(authorize(context, plan, owner))
        replacement = config.with_name("same-byte-config")
        replacement.write_bytes(config.read_bytes())
        replacement.chmod(config.stat().st_mode & 0o777)
        replacement.replace(config)
        before = participant_digests(context, config, manifest)
        with pytest.raises(TransitionError) as failure:
            pending.compare()
        assert failure.value.reason == "publication_inverse_generation_changed"
    assert participant_digests(context, config, manifest) == before


@pytest.mark.parametrize("boundary", ["intent", "manifest", "config"])
def test_process_exit_preserves_explicit_inverse_for_fresh_recovery(inverse, boundary):  # noqa: F811
    context, config, manifest, _unbound, plan = inverse
    journal = context.guard_home / "managed/codex/pending-hook-publication.json"
    if boundary == "config":
        config.write_bytes(config.read_bytes() + b"\n# reviewed intervening config\n")
        with codex_install_transaction(context.guard_home, config, actor="prepare-config-inverse"):
            assert plan.native_runtime is not None and plan.verification_workspace is not None
            plan = bind_codex_publication_inverse_verification(
                prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context)),
                expected_runtime=plan.native_runtime,
                workspace=plan.verification_workspace,
                deadline_monotonic=time.monotonic() + 30,
            )

    def child():
        original = publication.atomic_write_bytes

        def exit_after_owned_write(path, value, **kwargs):
            original(path, value, **kwargs)
            target = {"intent": journal, "manifest": manifest, "config": config}[boundary]
            if path == target:
                os._exit(17)

        publication.atomic_write_bytes = exit_after_owned_write
        with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
            publication.publish_codex_publication_inverse(authorize(context, plan, owner))
        os._exit(18)

    process = multiprocessing.get_context("fork").Process(target=child)
    process.start()
    process.join(20)
    if process.is_alive():
        process.terminate()
        process.join(5)
        pytest.fail("owned inverse child exceeded its bounded test deadline")
    assert process.exitcode == 17
    marker = json.loads(journal.read_bytes())["publication_inverse"]
    assert marker["phase"] == "restoring"
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor="restart-after-explicit-inverse"):
        with pytest.raises(CodexHookIntegrityError) as failure:
            recover_hook_publication(context.guard_home)
        assert failure.value.reason == "codex_hook_recovery_explicit_inverse_pending"
    assert participant_digests(context, config, manifest) == before
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        assert plan.native_runtime is not None and plan.verification_workspace is not None
        reviewed = bind_codex_publication_inverse_verification(
            prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context)),
            expected_runtime=plan.native_runtime,
            workspace=plan.verification_workspace,
            deadline_monotonic=time.monotonic() + 30,
        )
        assert reviewed.resumed_inverse_operation_id == plan.operation_id
        pending = publication.publish_codex_publication_inverse(authorize(context, reviewed, owner))
        pending.compare()
        for change in reviewed.changes:
            assert change.path.read_bytes() == change.after


def test_same_byte_substitution_inside_publication_cannot_be_claimed(inverse, monkeypatch):  # noqa: F811
    context, config, manifest, _unbound, plan = inverse
    original = publication.atomic_write_bytes
    observed = {}

    def substitute_after_owned_write(path, value, **kwargs):
        original(path, value, **kwargs)
        if path == manifest:
            replacement = manifest.with_name("foreign-manifest")
            replacement.write_bytes(manifest.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(manifest)
            observed.update(participant_digests(context, config, manifest))

    monkeypatch.setattr(publication, "atomic_write_bytes", substitute_after_owned_write)
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        with pytest.raises(TransitionError) as failure:
            publication.publish_codex_publication_inverse(authorize(context, plan, owner))
        assert failure.value.reason == "publication_inverse_generation_changed"
    assert observed
    assert participant_digests(context, config, manifest) == observed


def test_competing_config_during_file_preparation_prevents_publication(inverse, monkeypatch):  # noqa: F811
    context, config, manifest, _unbound, plan = inverse
    original = publication.atomic_write_bytes
    observed = {}

    def prepare_then_intervene(path, value, **kwargs):
        if path == manifest:
            compare = kwargs["before_publish"]

            def intervene():
                config.write_bytes(config.read_bytes() + b"\n# competing writer during preparation\n")
                observed.update(participant_digests(context, config, manifest))
                compare()

            kwargs["before_publish"] = intervene
        return original(path, value, **kwargs)

    monkeypatch.setattr(publication, "atomic_write_bytes", prepare_then_intervene)
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        with pytest.raises(TransitionError) as failure:
            publication.publish_codex_publication_inverse(authorize(context, plan, owner))
        assert failure.value.reason == "publication_inverse_generation_changed"
    assert observed
    assert participant_digests(context, config, manifest) == observed


@pytest.mark.skipif(os.name == "nt", reason="POSIX private mode normalization")
def test_matching_config_bytes_are_published_with_reviewed_private_mode(inverse):  # noqa: F811
    context, config, _manifest, _unbound, prior_plan = inverse
    config.chmod(0o644)
    assert prior_plan.native_runtime is not None and prior_plan.verification_workspace is not None
    with codex_install_transaction(context.guard_home, config, actor="prepare-reviewed-config-mode"):
        plan = bind_codex_publication_inverse_verification(
            prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context)),
            expected_runtime=prior_plan.native_runtime,
            workspace=prior_plan.verification_workspace,
            deadline_monotonic=time.monotonic() + 30,
        )
    assert plan.changes[0].before == plan.changes[0].after
    assert plan.changes[0].before_mode == 0o644
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        pending = publication.publish_codex_publication_inverse(authorize(context, plan, owner))
        pending.compare()
        assert config.stat().st_mode & 0o777 == 0o600
        assert pending._identities[0] != plan.change_identities[0]


def test_resumption_requires_fresh_plan_and_owner_grant(inverse):  # noqa: F811
    from codex_plugin_scanner.guard.approval_gate import ApprovalGateError

    context, config, manifest, _unbound, plan = inverse
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        old_authorization = authorize(context, plan, owner)
        old_pending = publication.publish_codex_publication_inverse(old_authorization)
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        assert plan.native_runtime is not None and plan.verification_workspace is not None
        fresh = bind_codex_publication_inverse_verification(
            prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context)),
            expected_runtime=plan.native_runtime,
            workspace=plan.verification_workspace,
            deadline_monotonic=time.monotonic() + 30,
        )
        assert fresh.resumed_inverse_operation_id == plan.operation_id
        assert fresh.operation_id != plan.operation_id
        assert fresh.subject() != plan.subject()
        with pytest.raises(ApprovalGateError):
            authorize_codex_publication_inverse(
                fresh,
                authority_home=context.guard_home,
                grant=old_authorization.grant,
                deadline_monotonic=time.monotonic() + 30,
            )
        assert participant_digests(context, config, manifest) == before
        pending = publication.publish_codex_publication_inverse(authorize(context, fresh, owner))
        pending.compare()
        with pytest.raises(TransitionError) as failure:
            old_pending.compare()
        assert failure.value.reason == "publication_inverse_owner_mismatch"
        record = json.loads((context.guard_home / "managed/codex/pending-hook-publication.json").read_bytes())
        assert record["publication_inverse"]["plan"]["operation_id"] == fresh.operation_id
        assert "native_verification" not in record["publication_inverse"]


@pytest.mark.parametrize("mutation", ["schema", "restore-order", "target", "predecessor"])
def test_signed_but_invalid_prior_inverse_never_authorizes_resumption(inverse, mutation):  # noqa: F811
    import hashlib

    from codex_plugin_scanner.guard.codex_hook_integrity import canonical_manifest_bytes, load_hook_secret
    from codex_plugin_scanner.guard.codex_hook_recovery import _PURPOSE
    from codex_plugin_scanner.guard.local_authority_integrity import sign_local_authority_payload

    context, config, manifest, _unbound, plan = inverse
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
        publication.publish_codex_publication_inverse(authorize(context, plan, owner))
    journal = context.guard_home / "managed/codex/pending-hook-publication.json"
    record = json.loads(journal.read_bytes())
    record.pop("authentication")
    marker = record["publication_inverse"]
    prior = marker["plan"]
    if mutation == "schema":
        marker["schema"] = "unsupported-inverse-schema"
    elif mutation == "restore-order":
        marker["restored"] = [0, 1, 2]
    elif mutation == "target":
        prior["files"][0]["path"] = str(config.with_name("foreign-config.toml"))
    else:
        prior["files"][0]["after"] = prior["files"][1]["after"]
    marker["subject"] = (
        "codex-publication-inverse:"
        + prior["operation_id"]
        + ":"
        + hashlib.sha256(canonical_manifest_bytes(prior)).hexdigest()
    )
    # Use the normal authority signer in this isolated fixture. A valid MAC
    # alone must not make an unsupported/foreign inverse actionable.
    secret = load_hook_secret(context.guard_home)
    record["authentication"] = sign_local_authority_payload(
        record,
        key=secret.key,
        key_id=secret.key_id,
        purpose=_PURPOSE,
        signed_at=marker["owner_operation_id"],
    )
    journal.write_bytes(canonical_manifest_bytes(record) + b"\n")
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor="review-prior-inverse"):
        with pytest.raises(TransitionError) as failure:
            prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context))
        assert failure.value.reason == "publication_inverse_prior_record_invalid"
    assert participant_digests(context, config, manifest) == before


@pytest.mark.usefixtures("native_hook_force")
@pytest.mark.parametrize(
    "boundary",
    [
        "retire",
        "tampered-proof",
        "stale-proof",
        "retirement-interrupted",
        "inactive-enrollment",
    ],
)
def test_real_configured_native_protection_before_inverse_retirement(
    inverse,
    monkeypatch,
    tmp_path,
    boundary,  # noqa: F811
):
    from codex_plugin_scanner.guard import runtime_transition_codex_observer as observer
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status
    from codex_plugin_scanner.guard.runtime_transition_admission import verified_admission_payload
    from codex_plugin_scanner.guard.store import GuardStore

    from .test_runtime_transition_configured_inverse import OwnedDaemonLifecycle

    context, config, manifest, unbound, _fixture_bound = inverse
    identity = native_runtime_status().identity
    assert identity is not None
    workspace = tmp_path / "native-inverse-workspace"
    workspace.mkdir()
    with codex_install_transaction(context.guard_home, config, actor="prepare-native-inverse"):
        plan = bind_codex_publication_inverse_verification(
            unbound,
            expected_runtime=identity,
            workspace=workspace.resolve(),
            deadline_monotonic=time.monotonic() + 30,
        )
    assert plan.verification_workspace is not None
    store = GuardStore(context.guard_home)
    daemon = OwnedDaemonLifecycle(context.home_dir, context.guard_home, identity.path)
    original_remove = publication._remove_record
    try:
        with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
            pending = publication.publish_codex_publication_inverse(authorize(context, plan, owner))
            store.set_managed_install(
                "codex",
                boundary != "inactive-enrollment",
                None,
                codex_native_hook_state(context),
                "isolated-publication-inverse",
            )
            daemon.start(pending.authorization.deadline_monotonic)
            journal = context.guard_home / "managed/codex/pending-hook-publication.json"
            before = participant_digests(context, config, manifest)
            if boundary == "stale-proof":
                old_proof = observer.observe_configured_codex_hook(
                    operation_id=plan.operation_id,
                    artifact_generation="codex-publication-inverse-" + plan.subject().rsplit(":", 1)[1],
                    expected_runtime=identity,
                    guard_home=context.guard_home,
                    config_path=config,
                    workspace=plan.verification_workspace,
                    deadline_monotonic=pending.authorization.deadline_monotonic,
                    receipt_store=store,
                )
                monkeypatch.setattr(observer, "observe_configured_codex_hook", lambda **kwargs: old_proof)
            elif boundary == "tampered-proof":
                original = observer.observe_configured_codex_hook

                def tamper(**kwargs):
                    proof = original(**kwargs)
                    proof.allow_receipt["decision"] = "deny"
                    return proof

                monkeypatch.setattr(observer, "observe_configured_codex_hook", tamper)
            elif boundary == "retirement-interrupted":

                def interrupt(_home):
                    raise OSError("injected retirement interruption")

                monkeypatch.setattr(publication, "_remove_record", interrupt)
            if boundary == "retire":
                proof = publication.verify_and_retire_codex_publication_inverse(pending, receipt_store=store)
                evidence = verified_admission_payload(proof)
                allow, deny, installed_evidence = (
                    evidence["allow_receipt"],
                    evidence["deny_receipt"],
                    evidence["installed_hook_evidence"],
                )
                assert isinstance(allow, dict) and allow["decision"] == "allow"
                assert isinstance(deny, dict) and deny["decision"] == "deny"
                assert isinstance(installed_evidence, dict) and installed_evidence["harness"] == "codex"
                assert not journal.exists()
            elif boundary == "retirement-interrupted":
                with pytest.raises(OSError, match="injected retirement interruption"):
                    publication.verify_and_retire_codex_publication_inverse(pending, receipt_store=store)
                marker = json.loads(journal.read_bytes())["publication_inverse"]
                assert marker["phase"] == "verified"
                assert marker["native_verification"]["installed_hook_evidence"]["harness"] == "codex"
                pending.compare()
            else:
                with pytest.raises(TransitionError) as failure:
                    publication.verify_and_retire_codex_publication_inverse(pending, receipt_store=store)
                expected_reason = {
                    "tampered-proof": "functional_proof_missing",
                    "stale-proof": "publication_inverse_native_verification_invalid",
                    "inactive-enrollment": "admission_protection_failed",
                }[boundary]
                assert failure.value.reason == expected_reason
                assert participant_digests(context, config, manifest) == before
            if boundary == "inactive-enrollment":
                daemon.cleanup()
            else:
                daemon.stop(pending.authorization.deadline_monotonic)
        if boundary != "retire":
            retained = participant_digests(context, config, manifest)
            with (
                codex_install_transaction(context.guard_home, config, actor="restart-after-native-inverse"),
                pytest.raises(CodexHookIntegrityError) as failure,
            ):
                recover_hook_publication(context.guard_home)
            assert failure.value.reason == "codex_hook_recovery_explicit_inverse_pending"
            assert participant_digests(context, config, manifest) == retained
        if boundary == "retirement-interrupted":
            monkeypatch.setattr(publication, "_remove_record", original_remove)
            with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION) as owner:
                recovery_deadline = time.monotonic() + 30
                resumed = bind_codex_publication_inverse_verification(
                    prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context)),
                    expected_runtime=identity,
                    workspace=workspace.resolve(),
                    deadline_monotonic=recovery_deadline,
                )
                assert resumed.resumed_inverse_operation_id == plan.operation_id
                authorization = authorize_codex_publication_inverse(
                    resumed,
                    authority_home=context.guard_home,
                    grant=grant_for(resumed, owner),
                    deadline_monotonic=recovery_deadline,
                )
                assert authorization.deadline_monotonic <= recovery_deadline
                resumed_pending = publication.publish_codex_publication_inverse(authorization)
                daemon.start(authorization.deadline_monotonic)
                proof = publication.verify_and_retire_codex_publication_inverse(resumed_pending, receipt_store=store)
                assert verified_admission_payload(proof)["operation_id"] == resumed.operation_id
                assert not journal.exists()
                daemon.stop(authorization.deadline_monotonic)
            assert len(daemon.pids) == 2 and daemon.retired == daemon.pids
    finally:
        daemon.cleanup()
