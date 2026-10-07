"""Post-claim freshness regressions for native runtime hook consumers."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_tool_calls import (
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
)
from codex_plugin_scanner.guard.models import GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_bundle_signing_helpers import (
    TEST_POLICY_BUNDLE_WORKSPACE_ID,
    policy_bundle_test_keyring,
    sign_policy_bundle,
)

_SIGNED_POLICY_REFRESHED_AT = "2026-07-17T00:01:00+00:00"


def _provision_test_policy_bundle_anchor(store: GuardStore) -> None:
    store.set_sync_payload(
        "oauth_local_credentials",
        {"workspace_id": TEST_POLICY_BUNDLE_WORKSPACE_ID},
        _SIGNED_POLICY_REFRESHED_AT,
    )
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID),
        _SIGNED_POLICY_REFRESHED_AT,
    )


def _activate_signed_block_policy(store: GuardStore) -> None:
    policy_bundle = sign_policy_bundle(
        {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": "policy-2026-07-17.post-claim",
            "issuedAt": _SIGNED_POLICY_REFRESHED_AT,
            "expiresAt": None,
            "verifier": {},
            "rolloutState": "enforcing",
            "policyDefaults": {
                "mode": "enforce",
                "defaultAction": "block",
                "unknownPublisherAction": "review",
                "changedHashAction": "require-reapproval",
                "newNetworkDomainAction": "block",
                "subprocessAction": "block",
                "telemetryEnabled": False,
                "syncEnabled": True,
            },
            "rules": [],
            "acknowledgements": [],
        },
        workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )
    store.set_sync_payload("policy_bundle", policy_bundle, _SIGNED_POLICY_REFRESHED_AT)


def _record_once_allow(
    store: GuardStore,
    *,
    artifact: GuardArtifact,
    artifact_hash: str,
    workspace: Path,
    request_id: str,
) -> None:
    approval_id = store.record_local_once_approval(
        request_id=request_id,
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        workspace=str(workspace),
        publisher=artifact.publisher,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None


def _hook_args(harness: str, *, json_output: bool) -> argparse.Namespace:
    return argparse.Namespace(
        artifact_id=None,
        artifact_name=None,
        event_file=None,
        harness=harness,
        json=json_output,
        policy_action=None,
        runtime_harness=None,
    )


def _record_once_from_receipt(
    store: GuardStore,
    receipt: dict[str, object],
    *,
    request_id: str,
    workspace: Path,
) -> None:
    approval_id = store.record_local_once_approval(
        request_id=request_id,
        harness=cast(str, receipt["harness"]),
        artifact_id=cast(str, receipt["artifact_id"]),
        artifact_hash=cast(str, receipt["artifact_hash"]),
        workspace=str(workspace),
        publisher=None,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None


def _approval_reuse_reason(receipt: dict[str, object]) -> str | None:
    evidence = receipt.get("scanner_evidence")
    if not isinstance(evidence, list):
        return None
    for item in evidence:
        if isinstance(item, dict) and item.get("source") == "approval_reuse":
            reason = item.get("reason_code")
            return reason if isinstance(reason, str) else None
    return None


def _insert_tampered_broader_block(
    store: GuardStore,
    *,
    harness: str,
) -> None:
    store.upsert_policy(
        PolicyDecision(
            harness=harness,
            scope="global",
            action="block",
            reason="tampered broader authority must not be ignored",
            source="manual",
        ),
        "2026-07-17T00:01:00+00:00",
    )
    broader_block = next(
        item for item in store.list_policy_decisions(harness) if item["scope"] == "global" and item["action"] == "block"
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update policy_decisions set payload_mac = ? where decision_id = ?",
            ("00", broader_block["decision_id"]),
        )


def test_mcp_current_allow_and_exact_allow_do_not_hide_tampered_broader_authority(
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        default_action="allow",
    )
    artifact = build_tool_call_artifact(
        harness="copilot",
        server_name="status-lab",
        tool_name="read_status",
        source_scope="project",
        config_path=str(workspace / ".vscode" / "mcp.json"),
        transport="stdio",
    )
    arguments = {"status": "ok"}
    artifact_hash = build_tool_call_hash(
        artifact,
        arguments,
        workspace=workspace,
        config=config,
    )
    approval_id = store.record_local_once_approval(
        request_id="mcp-current-allow-integrity-collision",
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        workspace=str(workspace),
        publisher=artifact.publisher,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None
    _insert_tampered_broader_block(store, harness="copilot")

    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=artifact_hash,
        arguments=arguments,
    )
    with sqlite3.connect(store.path) as connection:
        claimed_at = connection.execute(
            "select claimed_at from guard_local_once_approvals where approval_id = ?",
            (approval_id,),
        ).fetchone()[0]

    assert decision.current_action == "allow"
    assert decision.saved_action == "allow"
    assert decision.action == "require-reapproval"
    assert decision.approval_reuse_status == "rejected"
    assert decision.approval_reuse_reason_code == "approval_reuse_integrity_failure"
    assert claimed_at is None
