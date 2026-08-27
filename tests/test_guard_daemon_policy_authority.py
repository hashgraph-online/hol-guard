"""Regression coverage for daemon-owned native policy authority."""

from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.local_supply_chain import _resolve_stored_package_policy_override
from codex_plugin_scanner.guard.models import GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.runtime.approval_context import build_approval_context_token
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
    PackageRequestEvaluation,
    SupplyChainUserCopy,
)
from codex_plugin_scanner.guard.store import GuardStore


class _MemorySecretStore:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def set_secret(self, secret_id: str, value: str) -> None:
        self.values[secret_id] = value

    def get_secret(self, secret_id: str) -> str | None:
        return self.values.get(secret_id)

    def delete_secret(self, secret_id: str) -> None:
        self.values.pop(secret_id, None)


class _OneShotStore:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home

    def resolve_policy_decision_lookup(self, *_args, **_kwargs) -> dict[str, object]:
        return {
            "decision": None,
            "ignored_local_integrity": {"integrity_status": "unknown_key"},
            "trust_status": {"remembered_rules": "disabled_degraded"},
            "authority_revision": 0,
        }

    def approval_reuse_claim_disposition(self, _decision: dict[str, object]) -> str:
        return "retained"


def _review_evaluation() -> PackageRequestEvaluation:
    return PackageRequestEvaluation(
        decision="review",
        policy_action="require-reapproval",
        enforcement="policy",
        entitlement_state="offline",
        cache_status="miss",
        package_intent_hash="intent-hash",
        policy_version="policy-v1",
        bundle_version=None,
        workspace_fingerprint=None,
        reasons=({"code": "package_review", "message": "Review package"},),
        packages=(),
        risk_summary="Review package",
        user_copy=SupplyChainUserCopy(
            title="Review package",
            summary="Review package",
            next_step=None,
            dashboard_url=None,
            harness_message="Review package",
        ),
    )


def test_package_reuses_native_signed_policy_through_running_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact_hash = build_approval_context_token(
        identity={"command": "npx", "package": "@modelcontextprotocol/server-memory"},
        content={"specifier": "latest"},
        capabilities={"install": True},
        policy={"action": "allow"},
        sandbox={"workspace": str(workspace)},
    )
    artifact = GuardArtifact(
        artifact_id="guard-cli:project:package-request:test",
        name="npx execute server-memory",
        harness="guard-cli",
        artifact_type="package_request",
        source_scope="project",
        config_path=str(workspace / "hol-guard.toml"),
        command="npx -y @modelcontextprotocol/server-memory",
    )

    daemon_store = GuardStore(guard_home, prime_policy_integrity=False)
    daemon_store._policy_integrity_secret_store = _MemorySecretStore()
    daemon_store.ensure_policy_integrity_ready_for_write(now="2026-08-27T00:00:00Z")
    daemon_store.upsert_policy(
        PolicyDecision(
            harness="guard-cli",
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=artifact_hash,
            workspace=str(workspace),
            publisher=None,
            reason="Always allow exact action",
            source="approval-gate",
        ),
        "2026-08-27T00:00:00Z",
    )
    one_shot_store = _OneShotStore(guard_home)

    monkeypatch.setattr(HookProcessRunner, "notify_queued_work", lambda _self: None, raising=False)
    daemon = GuardDaemonServer(daemon_store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        resolution = _resolve_stored_package_policy_override(
            _review_evaluation(),
            store=one_shot_store,
            artifact=artifact,
            artifact_hash=artifact_hash,
            workspace_dir=workspace,
            now="2026-08-27T00:01:00Z",
        )
    finally:
        daemon.stop()

    assert resolution.evaluation.policy_action == "allow"
    assert resolution.evaluation.reasons[0]["code"] == "saved_package_approval"
    assert resolution.claim_disposition == "retained"


def test_package_stays_blocked_when_native_authority_daemon_is_unavailable(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = GuardArtifact(
        artifact_id="guard-cli:project:package-request:test",
        name="npx execute server-memory",
        harness="guard-cli",
        artifact_type="package_request",
        source_scope="project",
        config_path=str(workspace / "hol-guard.toml"),
    )
    store = _OneShotStore(guard_home)

    resolution = _resolve_stored_package_policy_override(
        _review_evaluation(),
        store=store,
        artifact=artifact,
        artifact_hash="a" * 64,
        workspace_dir=workspace,
        now="2026-08-27T00:01:00Z",
    )

    assert resolution.evaluation.policy_action == "require-reapproval"


def test_policy_authority_route_rejects_unauthenticated_clients(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    monkeypatch.setattr(HookProcessRunner, "notify_queued_work", lambda _self: None, raising=False)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/policy/resolve",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
    finally:
        daemon.stop()

    assert error.value.code == 401
