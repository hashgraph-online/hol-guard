"""Completed subprocess outcomes retain their captured signed publication."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.local_supply_chain import build_package_protect_payload
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import policy_bundle_keyring_payload
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    canonical_policy_bundle_v2_payload,
    computed_policy_bundle_v2_hash,
)
from codex_plugin_scanner.guard.runtime.canonical_policy_decisions import build_canonical_policy_bundle_decisions
from codex_plugin_scanner.guard.runtime.runner import _cloud_sync_receipt_payload, _receipt_sync_rows_for_upload
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_canonical_policy_row_authority import _NOW
from tests.test_guard_local_supply_chain_phase15 import _bundle_response, _package
from tests.test_guard_protect_harness_attribution import _install_fake_package_manager
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key


def _package_payload(*, package_manager, store, workspace_dir, now, dry_run=True):
    result = build_package_protect_payload(
        command=[package_manager, "install", "synthetic-known@1.0.0"],
        store=store,
        workspace_dir=workspace_dir,
        now=now,
        dry_run=dry_run,
        config=GuardConfig(
            guard_home=store.guard_home,
            workspace=workspace_dir,
            security_level="custom",
            risk_actions={"package_script": "review"},
        ),
        unsafe_raw_output=False,
        timeout_seconds=10,
    )
    assert result is not None
    return result


def _execution_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, exit_code: int = 0, workspace_id: str = "workspace-alpha"
):
    _install_fake_package_manager(monkeypatch, tmp_path, "npm")
    executable = tmp_path / "package-bin" / ("npm.cmd" if os.name == "nt" else "npm")
    executable.write_text(
        f"@echo off\r\nexit /b {exit_code}\r\n" if os.name == "nt" else f"#!/bin/sh\nexit {exit_code}\n"
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    key_pair = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="synthetic-refresh",
        dpop_private_key_pem=key_pair.private_key_pem,
        dpop_public_jwk=key_pair.public_jwk,
        dpop_public_jwk_thumbprint=key_pair.public_jwk_thumbprint,
        device_id=key_pair.public_jwk_thumbprint,
        grant_id="synthetic-grant",
        machine_id=store.get_or_create_installation_id(),
        workspace_id=workspace_id,
        supply_chain_plan_id="free",
        supply_chain_firewall=False,
        now=_NOW,
        access_token="synthetic-access",
        access_token_expires_at="2099-01-01T00:00:00Z",
    )

    def unavailable_cloud(*args, **kwargs):
        raise TimeoutError("synthetic cloud unavailability")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.supply_chain_package_eval._urlopen_json_with_timeout_retry",
        unavailable_cloud,
    )
    store.set_sync_payload("supply_chain_bundle_entitlement", {"tier": "free"}, _NOW)
    package = {
        **_package(name="synthetic-known", version="1.0.0", default_action="allow", normalized_severity="low"),
        "knownExploited": False,
        "malwareState": "none",
        "exploitLevel": "none",
        "riskScore": 0,
        "relatedAdvisoryIds": [],
        "recommendedFixVersion": None,
    }
    store.cache_supply_chain_bundle(workspace_id, _bundle_response(packages=[package]), _NOW)
    baseline, baseline_rc = _package_payload(package_manager="npm", store=store, workspace_dir=workspace, now=_NOW)
    assert baseline_rc == 2, baseline
    receipt = baseline["receipt"]
    device = store.get_device_metadata()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private_key, workspace_id=workspace_id)
    document = {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "synthetic.execution", "name": "Synthetic execution", "revision": 8},
        "spec": {
            "defaults": {"mode": "enforce", "defaultAction": "warn"},
            "rules": [
                {
                    "id": "synthetic.allow",
                    "enabled": True,
                    "effect": "allow",
                    "match": {
                        "harnesses": ["guard-cli"],
                        "artifacts": [receipt["artifact_id"]],
                        "devices": [device["installation_id"]],
                    },
                    "x-hol-local": {"scope": "artifact", "artifactHash": receipt["artifact_hash"]},
                    "lifetime": {"mode": "permanent", "expiresAt": None},
                    "provenance": {"source": "cloud", "createdAt": _NOW},
                }
            ],
        },
    }
    bundle = _signed_bundle(private_key, key, payload_base=document, rollout_state="enforcing", bundle_version=42)
    bundle["workspaceId"] = workspace_id
    bundle["bundleHash"] = computed_policy_bundle_v2_hash(bundle)
    bundle["verifier"]["signature"] = base64.b64encode(
        private_key.sign(
            canonical_policy_bundle_v2_payload(bundle),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    ).decode("ascii")
    decisions = build_canonical_policy_bundle_decisions(
        bundle, device_id=device["installation_id"], device_name=device["device_label"]
    )
    store.apply_policy_bundle_authority(
        decisions,
        _NOW,
        policy_bundle=bundle,
        policy_bundle_keyring=policy_bundle_keyring_payload((key,), workspace_id=workspace_id),
        cloud_exceptions=[],
        policy_bundle_ack={},
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        remote_write_authorized=True,
    )
    return store, workspace, bundle


@pytest.mark.parametrize(
    "exit_code,workspace_id",
    [(0, "workspace-alpha"), (7, "workspace-alpha"), (0, "11111111-1111-4111-8111-111111111111")],
)
def test_actual_subprocess_completion_survives_receipt_redaction_and_transport(
    tmp_path, monkeypatch, exit_code, workspace_id
):
    store, workspace, bundle = _execution_store(tmp_path, monkeypatch, exit_code=exit_code, workspace_id=workspace_id)
    payload, status = _package_payload(
        package_manager="npm", store=store, workspace_dir=workspace, now=_NOW, dry_run=False
    )
    assert status == exit_code, json.dumps(payload.get("supply_chain_evaluation"), indent=2)
    assert payload["executed"] is True
    receipt = store.list_receipts(limit=1)[0]
    witness = receipt["envelope_redacted_json"].get("policyExecutionOutcome")
    assert witness is not None, receipt
    assert witness == {
        "schemaVersion": "guard.policy-execution-outcome.v1",
        "receiptId": receipt["receipt_id"],
        "completedAt": witness["completedAt"],
        "outcome": "succeeded" if exit_code == 0 else "failed",
        "source": "guard_subprocess",
        "trust": "self_attested",
        "policyId": "synthetic.execution",
        "ruleId": "synthetic.allow",
        "policyVersion": "8",
        "bundleVersion": 42,
        "bundleHash": bundle["bundleHash"],
        "installationId": store.get_device_metadata()["installation_id"],
    }
    transported = _cloud_sync_receipt_payload(
        receipt, device_id=witness["installationId"], device_name="Synthetic device"
    )
    assert transported["envelopeRedacted"]["policyExecutionOutcome"] == witness
    assert str(tmp_path) not in json.dumps(witness)


def test_dry_run_has_no_execution_outcome(tmp_path, monkeypatch):
    store, workspace, _bundle = _execution_store(tmp_path, monkeypatch)
    payload, status = _package_payload(
        package_manager="npm", store=store, workspace_dir=workspace, now=_NOW, dry_run=True
    )
    assert status == 0 and payload["executed"] is False
    assert all(
        "policyExecutionOutcome" not in (r.get("envelope_redacted_json") or {}) for r in store.list_receipts(limit=10)
    )


def test_source_removed_after_real_child_completion_does_not_relabel_the_receipt(tmp_path, monkeypatch):
    import subprocess

    store, workspace, bundle = _execution_store(tmp_path, monkeypatch)
    actual_run = subprocess.run
    completed = []

    def execute_then_clear_source(*args, **kwargs):
        result = actual_run(*args, **kwargs)
        if args and isinstance(args[0], (list, tuple)) and tuple(args[0][-2:]) == ("install", "synthetic-known@1.0.0"):
            completed.append(result.returncode)
            store.clear_policy_bundle_authority(_NOW, policy_bundle_last_error={})
        return result

    monkeypatch.setattr("codex_plugin_scanner.guard.local_supply_chain.subprocess.run", execute_then_clear_source)
    payload, status = _package_payload(
        package_manager="npm", store=store, workspace_dir=workspace, now=_NOW, dry_run=False
    )
    assert status == 0 and payload["executed"] is True and completed == [0]
    assert store.get_sync_payload("policy_bundle") is None
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["envelope_redacted_json"]["policyExecutionOutcome"]["bundleHash"] == bundle["bundleHash"]


def test_completed_receipt_is_sync_visible_with_witness_at_first_insert_commit(tmp_path, monkeypatch):
    store, workspace, bundle = _execution_store(tmp_path, monkeypatch)
    cursor = store.latest_receipt_rowid() or 0
    actual_add_receipt = store.add_receipt
    uploaded = []

    def insert_then_sync(receipt, **kwargs):
        nonlocal cursor
        actual_add_receipt(receipt, **kwargs)
        # A real cursor reader at the former receipt/envelope transaction seam.
        rows = _receipt_sync_rows_for_upload(store, cursor_rowid=cursor)
        for row in rows:
            uploaded.append(
                _cloud_sync_receipt_payload(row, device_id="synthetic-device", device_name="Synthetic device")
            )
            cursor = max(cursor, row["receipt_rowid"])

    monkeypatch.setattr(store, "add_receipt", insert_then_sync)
    payload, status = _package_payload(
        package_manager="npm", store=store, workspace_dir=workspace, now=_NOW, dry_run=False
    )
    assert status == 0 and payload["executed"] is True
    assert len(uploaded) == 1
    assert uploaded[0]["envelopeRedacted"]["policyExecutionOutcome"]["bundleHash"] == bundle["bundleHash"]
    assert _receipt_sync_rows_for_upload(store, cursor_rowid=cursor) == []


def test_completed_receipt_envelope_and_event_roll_back_together(tmp_path, monkeypatch):
    store, workspace, _bundle = _execution_store(tmp_path, monkeypatch)
    cursor = store.latest_receipt_rowid() or 0
    inserted = []

    def fail_before_commit(connection, event):
        rows = connection.execute("select receipt_id from runtime_receipts where rowid > ?", (cursor,)).fetchall()
        inserted.extend(row["receipt_id"] for row in rows)
        assert len(inserted) == 1
        row = connection.execute(
            "select envelope_redacted_json from runtime_receipt_envelopes where receipt_id = ?", (inserted[0],)
        ).fetchone()
        assert json.loads(row["envelope_redacted_json"])["policyExecutionOutcome"]["outcome"] == "succeeded"
        raise RuntimeError("synthetic transaction failure")

    monkeypatch.setattr(store, "_add_guard_event_v1", fail_before_commit)
    with pytest.raises(RuntimeError, match="synthetic transaction failure"):
        _package_payload(package_manager="npm", store=store, workspace_dir=workspace, now=_NOW, dry_run=False)
    assert _receipt_sync_rows_for_upload(store, cursor_rowid=cursor) == []
    with store._connect() as connection:
        assert (
            connection.execute(
                "select 1 from runtime_receipt_envelopes where receipt_id = ?", (inserted[0],)
            ).fetchone()
            is None
        )
        assert (
            connection.execute(
                "select 1 from guard_cloud_events where idempotency_key = ?", (f"receipt.created:{inserted[0]}",)
            ).fetchone()
            is None
        )


def test_failed_spawn_does_not_claim_completed_execution(tmp_path, monkeypatch):
    store, workspace, _bundle = _execution_store(tmp_path, monkeypatch)

    def unavailable_process(*args, **kwargs):
        raise OSError("synthetic launch failure")

    monkeypatch.setattr("codex_plugin_scanner.guard.local_supply_chain.subprocess.run", unavailable_process)
    _payload, status = _package_payload(
        package_manager="npm", store=store, workspace_dir=workspace, now=_NOW, dry_run=False
    )
    assert status == 1
    assert all(
        "policyExecutionOutcome" not in (r.get("envelope_redacted_json") or {}) for r in store.list_receipts(limit=10)
    )


def _witness():
    return {
        "schemaVersion": "guard.policy-execution-outcome.v1",
        "receiptId": "guard-receipt-synthetic",
        "completedAt": "2026-09-17T00:00:00Z",
        "outcome": "succeeded",
        "source": "guard_subprocess",
        "trust": "self_attested",
        "policyId": "synthetic.policy",
        "ruleId": "synthetic.rule",
        "policyVersion": "8",
        "bundleVersion": 42,
        "bundleHash": "sha256:" + "a" * 64,
        "installationId": "synthetic-installation",
    }


@pytest.mark.parametrize(
    "change",
    [
        {"rawOutput": "private output"},
        {"policyId": "invalid\nidentifier"},
        {"ruleId": None},
        {"policyVersion": 8},
        {"policyVersion": "08"},
        {"bundleVersion": True},
        {"bundleVersion": 42.0},
        {"bundleVersion": 0},
        {"bundleHash": "unbound"},
        {"installationId": "../private"},
        {"receiptId": ""},
        {"completedAt": "2026-09-17T00:00:00"},
        {"completedAt": "not-a-time"},
        {"outcome": {}},
        {"outcome": "allowed"},
        {"trust": "verified"},
        {"source": "allow_decision"},
    ],
)
def test_redaction_drops_malformed_completion_witness_as_a_unit(change):
    from codex_plugin_scanner.guard.receipts.manager import _redacted_envelope_dict
    from codex_plugin_scanner.guard.receipts.policy_execution_outcome import safe_policy_execution_outcome

    value = {**_witness(), **change}
    assert safe_policy_execution_outcome(value) is None
    assert "policyExecutionOutcome" not in _redacted_envelope_dict(
        {"policy_action": "allow", "policyExecutionOutcome": value}
    )


def test_complete_witness_survives_typed_and_legacy_redaction_but_not_identity_cache():
    from codex_plugin_scanner.guard.policy_rule_identity import PolicyRuleIdentity
    from codex_plugin_scanner.guard.receipts.manager import _redacted_envelope_dict
    from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope

    witness = _witness()
    legacy = {"policy_action": "allow", "policyExecutionOutcome": witness}
    typed = GuardActionEnvelope(
        schema_version=1,
        action_id="synthetic-action",
        harness="codex",
        event_name="PreToolUse",
        action_type="command",
        workspace=None,
        workspace_hash=None,
        tool_name="Bash",
        command="printf synthetic",
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
    ).to_dict()
    for envelope in (legacy, {**typed, "policyExecutionOutcome": witness}):
        assert _redacted_envelope_dict(envelope)["policyExecutionOutcome"] == witness
    identity = PolicyRuleIdentity.from_selected_row(
        {
            **witness,
            "_policyPublication": {key: witness[key] for key in ("bundleVersion", "bundleHash", "installationId")},
        }
    )
    assert identity is not None and identity.publication is not None
    assert PolicyRuleIdentity.from_mapping(identity.to_dict()).publication is None
