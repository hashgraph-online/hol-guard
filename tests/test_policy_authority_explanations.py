"""Actual resolver outcomes cited by the cross-lane authority explanation."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlSurface,
    ControlTargetKind,
)
from codex_plugin_scanner.guard.runtime.extension_control_resolver import resolve_extension_controls
from tests.test_guard_extension_control_resolver import _catalog_subjects, _control, _layer
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key
from tests.test_policy_bundle_v2_runtime_admission import (
    _generic_v2_payload,
    _seed_v2_admission_store,
    _sync_signed_v2_bundle,
)


@pytest.mark.parametrize("local_newer", [True, False])
def test_generic_row_recency_is_not_a_cloud_priority_rule(tmp_path: Path, monkeypatch, local_newer):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private, workspace_id="workspace-alpha")
    store = _seed_v2_admission_store(tmp_path, key)
    artifact = "skill:authority-example"
    signed = _signed_bundle(private, key, payload_base=_generic_v2_payload(rule_id="cloud-block", artifact_id=artifact))
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    store.upsert_policy(
        PolicyDecision(harness="codex", scope="artifact", artifact_id=artifact, action="allow", source="local"),
        "2026-09-17T12:01:00Z" if local_newer else "2026-09-17T11:59:00Z",
    )
    _sync_signed_v2_bundle(store, monkeypatch, signed, synced_at="2026-09-17T12:00:00Z")
    rows = store.list_policy_decisions()
    assert {row["source"] for row in rows} == {"local", "policy-bundle-canonical"}
    result = store.resolve_policy_decision_lookup("codex", artifact, now="2026-09-17T12:02:00Z")["decision"]
    assert result is not None
    assert result["action"] == ("allow" if local_newer else "block")
    assert result["source"] == ("local" if local_newer else "policy-bundle-canonical")


def test_managed_permission_disable_retains_its_reason_against_local_enable():
    extension, permission = _catalog_subjects()
    layers = (
        _layer(ControlLayerKind.LOCAL_ADMIN, _control(ControlTargetKind.PERMISSION, permission, ControlState.ENABLED)),
        _layer(
            ControlLayerKind.SIGNED_CLOUD, _control(ControlTargetKind.PERMISSION, permission, ControlState.DISABLED)
        ),
    )
    result = resolve_extension_controls(
        layers,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(extension,),
        permission_ids=(permission,),
        surface=ControlSurface.COMMAND_EVALUATION,
    )
    assert result.blocked is True
    assert any(factor.reason_code == "control.disabled-permission" for factor in result.factors)


@pytest.mark.parametrize("cloud_effect", ["allow", "block"])
def test_generic_one_shot_consumption_depends_on_selected_persisted_action(
    tmp_path: Path, monkeypatch, cloud_effect: str
):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private, workspace_id="workspace-alpha")
    store = _seed_v2_admission_store(tmp_path, key)
    artifact = "codex:project:tool-action:one-shot-precedence"
    payload = _generic_v2_payload(rule_id="cloud-rule", artifact_id=artifact)
    payload["spec"]["rules"][0]["effect"] = cloud_effect
    signed = _signed_bundle(private, key, payload_base=payload)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    _sync_signed_v2_bundle(store, monkeypatch, signed, synced_at="2026-09-17T12:00:00Z")
    approval_id = store.record_local_once_approval(
        request_id="one-shot-precedence",
        harness="codex",
        artifact_id=artifact,
        artifact_hash="sha256:one-shot-precedence",
        workspace=None,
        publisher=None,
        action="allow",
        created_at="2026-09-17T12:01:00Z",
        expires_at="2026-09-17T13:00:00Z",
    )
    result = store.resolve_policy_decision_lookup(
        "codex", artifact, artifact_hash="sha256:one-shot-precedence", now="2026-09-17T12:02:00Z"
    )["decision"]
    assert result is not None and result["action"] == cloud_effect
    with store._connect() as connection:
        claimed_at = connection.execute(
            "select claimed_at from guard_local_once_approvals where approval_id = ?", (approval_id,)
        ).fetchone()[0]
    if cloud_effect == "block":
        assert result["source"] == "policy-bundle-canonical"
        assert claimed_at is None
    else:
        assert result["source"] == "approval-gate-once"
        assert datetime.fromisoformat(claimed_at) == datetime.fromisoformat("2026-09-17T12:02:00Z")
