"""Actual hook decisions consume signed exact-byte policies without widening scope."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.cli.hook_exact_policy import authenticated_exact_policy_allow
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.exact_command import exact_command_sha256
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import policy_bundle_keyring_payload
from codex_plugin_scanner.guard.runtime.canonical_policy_decisions import build_canonical_policy_bundle_decisions
from tests.test_guard_approval_precedence_generic_stdio import _run_generic_hook
from tests.test_guard_review_policy_memory_command import _bundle, _resign_bundle, _store
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key

_HARNESS = "generic-test"
_COMMAND = "/usr/bin/printf 'Synthetic  exact'"
# A missing local script requires review independently of PATH interpreter trust.
_REAPPROVAL_COMMAND = "bash synthetic-policy-review.sh"


@pytest.fixture(autouse=True)
def _isolate_exact_policy_approval_ui(monkeypatch):
    """Keep signed-policy tests local; daemon lifecycle has separate contracts."""
    from codex_plugin_scanner.guard.cli import commands_hook_generic, commands_hook_runtime_review
    from codex_plugin_scanner.guard.daemon.manager import guard_daemon_url_for_home

    def predicted_origin(guard_home, *, home_dir=None):
        del home_dir
        return guard_daemon_url_for_home(guard_home)

    def unavailable_client(*args, **kwargs):
        del args, kwargs
        raise RuntimeError("Approval UI transport is isolated for policy tests.")

    monkeypatch.setattr(commands_hook_generic, "schedule_guard_daemon_ensure", predicted_origin)
    monkeypatch.setattr(commands_hook_runtime_review, "schedule_guard_daemon_ensure", predicted_origin)
    monkeypatch.setattr(commands_hook_runtime_review, "load_guard_surface_daemon_client", unavailable_client)


def _payload(command=_COMMAND):
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": command},
        "source_scope": "project",
    }


def _run(capsys, store, workspace, payload=None, action="review", harness=_HARNESS, **kwargs):
    return _run_generic_hook(
        capsys=capsys,
        store=store,
        workspace=workspace,
        payload=payload or _payload(),
        harness=harness,
        config=GuardConfig(
            guard_home=store.guard_home, workspace=workspace, default_action=action, harness_actions={harness: action}
        ),
        **kwargs,
    )


def _publish(store, artifact, source, command=_COMMAND, harness=_HARNESS):
    now = datetime.now(timezone.utc).isoformat()
    selector = {"contractVersion": "guard.exact-command.v1", "sha256": exact_command_sha256(command)}
    if source == "memory":
        bundle = _bundle(store)
        rule = bundle["memoryRules"][0]
        rule.update(artifactId=artifact, harnessId=harness, exactCommand=selector)
        rule.pop("artifactHash")
        rule.pop("projectIdentity")
        assert store.apply_review_policy_memory_state(_resign_bundle(bundle), now=now)["status"] == "accepted"
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private_key, workspace_id="workspace-1")
    payload = {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "synthetic-policy", "name": "Synthetic", "revision": 8},
        "spec": {
            "defaults": {"mode": "enforce", "defaultAction": "warn"},
            "rules": [
                {
                    "id": "synthetic-rule",
                    "enabled": True,
                    "effect": "allow",
                    "match": {"harnesses": [harness], "artifacts": [artifact], "exactCommand": selector},
                    "lifetime": {"mode": "permanent", "expiresAt": None},
                    "provenance": {"source": "cloud", "createdAt": "2026-09-17T00:00:00Z"},
                }
            ],
        },
    }
    bundle = _signed_bundle(private_key, key, payload_base=payload, rollout_state="enforcing")
    # The signing helper's fixed workspace must match this authentic test installation.
    import base64

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    from codex_plugin_scanner.guard.policy_bundle_v2 import (
        canonical_policy_bundle_v2_payload,
        computed_policy_bundle_v2_hash,
    )

    bundle["workspaceId"] = "workspace-1"
    bundle["bundleHash"] = computed_policy_bundle_v2_hash(bundle)
    bundle["verifier"]["signature"] = base64.b64encode(
        private_key.sign(
            canonical_policy_bundle_v2_payload(bundle),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    ).decode()
    device = store.get_device_metadata()
    result = store.apply_policy_bundle_authority(
        build_canonical_policy_bundle_decisions(
            bundle, device_id=device["installation_id"], device_name=device["device_label"]
        ),
        now,
        policy_bundle=bundle,
        policy_bundle_keyring=policy_bundle_keyring_payload((key,), workspace_id="workspace-1"),
        cloud_exceptions=[],
        policy_bundle_ack={"bundleHash": bundle["bundleHash"], "bundleVersion": 8, "status": "validated"},
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        remote_write_authorized=True,
    )
    assert result is not None


def _prepared(tmp_path, capsys, source):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = _store(tmp_path)
    first_rc, first = _run(capsys, store, workspace)
    assert first_rc == 1 and first["policy_action"] == "review"
    artifact = store.list_receipts(limit=1)[0]["artifact_id"]
    _publish(store, artifact, source)
    return store, workspace, artifact


@pytest.mark.parametrize("source", ["memory", "canonical"])
def test_actual_generic_hook_consumes_exact_policy_and_rechecks_after_claim(tmp_path, capsys, source):
    store, workspace, artifact = _prepared(tmp_path, capsys, source)
    rc, output = _run(capsys, store, workspace)
    assert rc == 0 and output["policy_action"] == "allow"
    assert output["policy_composition"]["current_composed_action"] == "review"
    assert output["approval_reuse"]["reason_code"] == "approval_reuse_accepted"
    assert store.list_receipts(limit=1)[0]["artifact_id"] == artifact


@pytest.mark.parametrize(
    "command", [_COMMAND + " ", _COMMAND.replace("  ", " "), _COMMAND.replace("Synthetic", "synthetic")]
)
def test_raw_byte_change_cannot_reuse_signed_exact_allow(tmp_path, capsys, command):
    store, workspace, _ = _prepared(tmp_path, capsys, "memory")
    rc, output = _run(capsys, store, workspace, _payload(command))
    assert rc == 1 and output["policy_action"] == "review"


@pytest.mark.parametrize("change", ["aliases", "artifact", "tool", "harness"])
def test_original_identity_and_unambiguous_source_remain_required(tmp_path, capsys, change):
    store, workspace, _ = _prepared(tmp_path, capsys, "memory")
    payload = _payload()
    if change == "aliases":
        payload["tool_input"]["cmd"] = _COMMAND
    elif change == "artifact":
        payload["artifact_id"] = "synthetic:other"
    elif change == "tool":
        payload["tool_name"] = "not-shell"
    rc, output = _run(capsys, store, workspace, payload, harness="unrelated" if change == "harness" else _HARNESS)
    assert rc == 1 and output["policy_action"] == "review"


@pytest.mark.parametrize("action", ["require-reapproval", "sandbox-required", "block"])
def test_signed_exact_allow_preserves_current_stronger_actions(tmp_path, capsys, action):
    store, workspace, _ = _prepared(tmp_path, capsys, "memory")
    rc, output = _run(capsys, store, workspace, action=action)
    assert rc == 1 and output["policy_action"] == action


@pytest.mark.parametrize("mutation", ["clear", "signature", "digest"])
def test_post_claim_signed_authority_change_cannot_launch(tmp_path, capsys, monkeypatch, mutation):
    store, workspace, _ = _prepared(tmp_path, capsys, "memory")
    original = store.claim_approval_reuse_decision

    def racing_claim(decision, **kwargs):
        assert original(decision, **kwargs)
        if mutation == "clear":
            store.clear_review_policy_memory_state()
        else:
            registry = store.get_sync_payload("guard_review_memory_registry")
            bundle = next(iter(registry["bundles"].values()))
            if mutation == "signature":
                bundle["signature"] = "invalid"
            else:
                bundle["memoryRules"][0]["exactCommand"]["sha256"] = "a" * 64
            store.set_sync_payload("guard_review_memory_registry", registry, datetime.now(timezone.utc).isoformat())
        return True

    monkeypatch.setattr(store, "claim_approval_reuse_decision", racing_claim)
    rc, output = _run(capsys, store, workspace)
    assert rc == 1 and output["policy_action"] != "allow"
    assert output["approval_reuse"]["reason_code"] == "approval_reuse_integrity_failure"


def test_source_label_and_digest_alone_never_prove_policy_authority(tmp_path):
    store = _store(tmp_path)
    digest = exact_command_sha256(_COMMAND)
    for source in ("cloud-signed-memory", "policy-bundle-canonical", "manual", "approval-gate"):
        assert not authenticated_exact_policy_allow(
            store,
            {
                "action": "allow",
                "scope": "artifact",
                "artifact_id": "synthetic",
                "artifact_hash": None,
                "exact_command_sha256": digest,
                "source": source,
            },
            digest,
        )


def _runtime(store, workspace, command, **kwargs):
    import argparse

    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.cli.commands_hook_runtime_eval import _evaluate_runtime_artifact_hook
    from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact

    payload = _payload(command)
    artifact = _hook_runtime_artifact(
        harness=_HARNESS,
        payload=payload,
        action_envelope=None,
        home_dir=workspace.parent,
        guard_home=store.guard_home,
        workspace=workspace,
    )
    assert artifact is not None
    state = _evaluate_runtime_artifact_hook(
        argparse.Namespace(harness=_HARNESS, policy_action=None, json=True),
        action_envelope=None,
        config=GuardConfig(
            guard_home=store.guard_home,
            workspace=workspace,
            default_action="review",
            harness_actions={_HARNESS: "review"},
        ),
        context=HarnessContext(home_dir=workspace.parent, workspace_dir=workspace, guard_home=store.guard_home),
        data_flow_signals=(),
        guard_home=store.guard_home,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace,
        store=store,
        **kwargs,
    )
    assert not isinstance(state, int)
    return artifact, state


@pytest.mark.parametrize("source", ["memory", "canonical"])
def test_actual_runtime_artifact_producer_consumes_exact_policy(tmp_path, source):
    command = "ssh synthetic@example.invalid true"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = _store(tmp_path)
    artifact, before = _runtime(store, workspace, command)
    assert before.policy_action == "review"
    _publish(store, artifact.artifact_id, source, command)
    _, after = _runtime(store, workspace, command)
    assert after.policy_action == "allow"
    assert after.response_payload["approval_reuse"]["reason_code"] == "approval_reuse_accepted"
    changed_artifact, changed = _runtime(store, workspace, command + " ")
    assert changed_artifact.artifact_id == artifact.artifact_id
    assert changed.policy_action == "review"


def test_runtime_exact_policy_cannot_relax_intrinsic_reapproval(tmp_path):
    command = _REAPPROVAL_COMMAND
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = _store(tmp_path)
    artifact, before = _runtime(store, workspace, command)
    assert before.policy_action == "require-reapproval"
    _publish(store, artifact.artifact_id, "memory", command)
    _, after = _runtime(store, workspace, command)
    assert after.policy_action == "require-reapproval"


def test_runtime_post_claim_refresh_retains_authenticated_identity(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.cli.hook_exact_policy import ExactCommandPolicyClaim

    command = "ssh synthetic@example.invalid true"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = _store(tmp_path)
    artifact, before = _runtime(store, workspace, command)
    assert before.policy_action == "review"
    _publish(store, artifact.artifact_id, "memory", command)
    observed = []

    def refresh(claim, trusted, request, package):
        assert isinstance(claim, ExactCommandPolicyClaim)
        observed.append(claim)
        store.clear_review_policy_memory_state()
        return _runtime(store, workspace, command, _claimed_saved_allow_hash=claim, _claim_saved_approval=False)[1]

    _, result = _runtime(store, workspace, command, post_claim_revalidator=refresh)
    assert len(observed) == 1
    assert result.policy_action != "allow"
    assert result.response_payload["approval_reuse"]["reason_code"] == "approval_reuse_integrity_failure"


def test_generic_external_refresh_retains_authenticated_identity(tmp_path, capsys):
    import argparse

    from codex_plugin_scanner.guard.cli.commands_hook_generic import _run_hook_generic_payload
    from codex_plugin_scanner.guard.cli.hook_exact_policy import ExactCommandPolicyClaim

    store, workspace, _ = _prepared(tmp_path, capsys, "memory")
    observed = []

    def refresh(claim):
        assert isinstance(claim, ExactCommandPolicyClaim)
        observed.append(claim)
        store.clear_review_policy_memory_state()
        return _run_hook_generic_payload(
            argparse.Namespace(artifact_id=None, artifact_name=None, harness=_HARNESS, json=True, policy_action=None),
            action_envelope=None,
            config=GuardConfig(
                guard_home=store.guard_home,
                workspace=workspace,
                default_action="review",
                harness_actions={_HARNESS: "review"},
            ),
            home_dir=workspace.parent,
            payload=_payload(),
            runtime_workspace=workspace,
            store=store,
            _claimed_saved_allow_hash=claim,
            _claim_saved_approval=False,
        )

    rc, output = _run(capsys, store, workspace, post_claim_revalidator=refresh)
    assert len(observed) == 1
    assert rc == 1 and output["policy_action"] != "allow"
    assert output["approval_reuse"]["reason_code"] == "approval_reuse_integrity_failure"


def _outer(capsys, store, workspace, command, *, extra_payload=None, harness=_HARNESS, redaction="full"):
    import argparse
    import json

    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.cli.commands_hook import _run_guard_hook_command

    (store.guard_home / "config.toml").write_text(
        'default_action = "review"\napproval_wait_timeout_seconds = 0\n'
        f'receipt_redaction_level = "{redaction}"\n[harnesses.{harness}]\ndefault_action = "review"\n'
    )
    config = GuardConfig(
        guard_home=store.guard_home,
        workspace=workspace,
        default_action="review",
        harness_actions={harness: "review"},
        approval_wait_timeout_seconds=0,
        receipt_redaction_level=redaction,
    )
    payload = {**_payload(command), **(extra_payload or {})}
    rc = _run_guard_hook_command(
        argparse.Namespace(harness=harness, artifact_id=None, artifact_name=None, json=True, policy_action=None),
        guard_home=store.guard_home,
        workspace=workspace,
        context=HarnessContext(home_dir=workspace.parent, workspace_dir=workspace, guard_home=store.guard_home),
        store=store,
        config=config,
        input_text=json.dumps(payload),
    )
    output = json.loads(capsys.readouterr().out)
    return rc, output


@pytest.mark.parametrize("harness", [_HARNESS, "codex"])
def test_outer_hook_preserves_raw_selector_before_alias_normalization(tmp_path, capsys, harness):
    command = _COMMAND
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = _store(tmp_path)
    before_rc, before = _outer(capsys, store, workspace, command, harness=harness)
    assert before_rc == 1 and before["policy_action"] == "review"
    artifact = store.list_receipts(limit=1)[0]["artifact_id"]
    _publish(store, artifact, "memory", command, harness=harness)
    after_rc, after = _outer(capsys, store, workspace, command, harness=harness)
    assert after_rc == 0 and after["policy_action"] == "allow", (
        after.get("approval_reuse"),
        after.get("policy_composition"),
    )
    assert after["approval_reuse"]["reason_code"] == "approval_reuse_accepted"
    changed_rc, changed = _outer(capsys, store, workspace, command + " ", harness=harness)
    assert changed_rc == 1 and changed["policy_action"] == "review"
    ambiguous_rc, ambiguous = _outer(
        capsys, store, workspace, command, harness=harness, extra_payload={"arguments": {"command": command}}
    )
    assert ambiguous_rc == 1 and ambiguous["policy_action"] == "review"


@pytest.mark.parametrize(
    "command,expected",
    [("ssh synthetic@example.invalid true", "block"), (_REAPPROVAL_COMMAND, "require-reapproval")],
)
def test_outer_runtime_envelope_retains_intrinsic_floors(tmp_path, capsys, command, expected):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = _store(tmp_path)
    before_rc, before = _outer(capsys, store, workspace, command, harness="codex")
    assert before_rc == 1 and before["policy_action"] == expected
    artifact = store.list_receipts(limit=1)[0]["artifact_id"]
    _publish(store, artifact, "memory", command, harness="codex")
    after_rc, after = _outer(capsys, store, workspace, command, harness="codex")
    assert after_rc == 1 and after["policy_action"] == expected


@pytest.mark.parametrize("command", ["\tprintf 'Synthetic  source'\r\n", _REAPPROVAL_COMMAND])
@pytest.mark.parametrize("consent,ambiguous", [(True, False), (False, False), (True, True)])
def test_outer_hook_local_queue_discloses_only_original_consented_source(
    tmp_path, capsys, monkeypatch, command, consent, ambiguous
):
    from codex_plugin_scanner.guard.cli import commands_hook_runtime_review as runtime_review
    from codex_plugin_scanner.guard.policy_memory_source import verified_request_policy_memory_source
    from tests.test_policy_memory_source_disclosure import _connected_store, _grant

    def unavailable_daemon(*_args, **_kwargs):
        raise RuntimeError("Synthetic daemon unavailability")

    # Exercise the actual local fallback. A detached production daemon must not
    # inherit this process's injected signing keyring or bypass source MAC checks.
    monkeypatch.setattr(runtime_review, "load_guard_surface_daemon_client", unavailable_daemon)
    monkeypatch.setattr(runtime_review, "schedule_guard_daemon_ensure", lambda *_args, **_kwargs: "http://localhost:1")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = _connected_store(tmp_path)
    if consent:
        _grant(store)
    extra = {"arguments": {"command": command}} if ambiguous else None
    rc, output = _outer(capsys, store, workspace, command, harness="codex", extra_payload=extra, redaction="none")
    assert rc == 1 and output["policy_action"] in {"review", "require-reapproval"}
    requests = store.list_approval_requests()
    assert len(requests) == 1
    source = verified_request_policy_memory_source(store, requests[0])
    if consent and not ambiguous:
        assert source is not None and source["commandText"] == command
        assert source["localRequestId"] == requests[0]["request_id"]
        assert source["artifactId"] == requests[0]["artifact_id"]
    else:
        assert source is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX detached-worker ownership probe")
def test_exact_policy_fixture_does_not_launch_detached_approval_workers(tmp_path, capsys, monkeypatch):
    from tests.guard_exact_policy_process_probe import capture_detached_approval_launches

    with capture_detached_approval_launches(monkeypatch, tmp_path / "guard-home") as probe:
        store, workspace, _ = _prepared(tmp_path, capsys, "memory")
        rc, output = _run(capsys, store, workspace)
        assert rc == 0 and output["policy_action"] == "allow"
    assert probe.children_reaped is True
    assert probe.requests == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX detached-worker ownership probe")
def test_detached_approval_probe_observes_real_scheduler(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.daemon import manager
    from tests.guard_exact_policy_process_probe import capture_detached_approval_launches

    guard_home = tmp_path / "probe-positive"
    with capture_detached_approval_launches(monkeypatch, guard_home) as probe:
        predicted = manager.schedule_guard_daemon_ensure(guard_home, home_dir=tmp_path)
        assert predicted == manager.guard_daemon_url_for_home(guard_home)
        assert probe.requests == 1
        assert probe.live_child_observed is True
    assert probe.children_reaped is True
