"""Phase 14 package-hook regressions across managed harnesses."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.store import GuardStore


def _seed_guard_cloud(store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).

    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


pytest_plugins = ["tests.bundle_first_cloud"]
pytestmark = pytest.mark.usefixtures("bundle_first_cloud")

WORKSPACE_ID = "workspace-alpha"


def _generate_key_pair() -> tuple[bytes, bytes]:
    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _fingerprint(public_key_pem: bytes) -> str:
    return hashlib.sha256(public_key_pem.decode("utf-8").strip().encode("utf-8")).hexdigest()


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _bundle_response(*, action: str, policy_rules: list[dict[str, object]] | None = None) -> dict[str, object]:
    generated_at = datetime(2026, 5, 19, tzinfo=timezone.utc)
    expires_at = generated_at + timedelta(hours=12)
    bundle = {
        "advisories": [
            {
                "advisoryId": "GHSA-vh95-rmgr-6w4m",
                "aliases": ["CVE-2020-7598"],
                "confidence": 990,
                "exploitLevel": "active",
                "knownExploited": True,
                "malwareState": "known",
                "normalizedSeverity": "critical",
                "recommendedFixVersion": "1.2.9",
                "sourceKey": "ghsa",
                "summary": "Prototype pollution in minimist",
                "title": "Prototype pollution in minimist",
            }
        ],
        "bundleVersion": "1747612800000-deadbeef",
        "expiresAt": _iso(expires_at),
        "feedSnapshotHash": "feed-snapshot-1",
        "generatedAt": _iso(generated_at),
        "keyId": "guard-bundle-key-2026-05",
        "packages": [
            {
                "confidence": 990,
                "defaultAction": action,
                "ecosystem": "npm",
                "exploitLevel": "active",
                "knownExploited": True,
                "malwareState": "known",
                "name": "minimist",
                "namespace": None,
                "normalizedSeverity": "critical",
                "packageAgeState": "watch",
                "purl": "pkg:npm/minimist@1.2.8",
                "reachability": "reachable",
                "recommendedFixVersion": "1.2.9",
                "relatedAdvisoryIds": ["GHSA-vh95-rmgr-6w4m"],
                "riskScore": 980,
                "sourceIntegrityState": "high-risk",
                "version": "1.2.8",
            }
        ],
        "policyHash": "policy-hash-1",
        "policyRules": policy_rules or [],
        "scoringVersion": "scf-v1",
        "sourceHashes": [{"payloadHash": "ghsa-feed-hash", "sourceKey": "ghsa", "staleStatus": "fresh"}],
        "tier": "premium",
        "workspaceId": WORKSPACE_ID,
    }
    private_key_pem, public_key_pem = _generate_key_pair()
    loaded_key = serialization.load_pem_private_key(private_key_pem, password=None)
    assert isinstance(loaded_key, RSAPrivateKey)
    canonical_payload = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_hash = hashlib.sha256(canonical_payload).hexdigest()
    signature = loaded_key.sign(
        canonical_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return {
        "bundle": bundle,
        "payloadHash": payload_hash,
        "signature": base64.b64encode(signature).decode("utf-8"),
        "signatureAlgorithm": "rsa-pss-sha256",
        "verificationKeys": [
            {
                "fingerprintSha256": _fingerprint(public_key_pem),
                "keyId": "guard-bundle-key-2026-05",
                "publicKeyPem": public_key_pem.decode("utf-8").strip(),
                "state": "active",
                "validUntil": None,
            }
        ],
    }


def _event_for_harness(harness: str, command: str, workspace_dir: Path) -> dict[str, object]:
    if harness == "codex":
        return {
            "session_id": "session-1",
            "turn_id": "turn-1",
            "cwd": str(workspace_dir),
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.4",
            "permission_mode": "bypassPermissions",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "call-1",
        }
    if harness == "copilot":
        return {
            "hookName": "preToolUse",
            "toolName": "bash",
            "toolArgs": {"command": command},
            "sourceScope": "project",
            "cwd": str(workspace_dir),
        }
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "source_scope": "project",
        "cwd": str(workspace_dir),
    }


def _run_guard_hook(
    *,
    home_dir: Path,
    workspace_dir: Path,
    harness: str,
    event: dict[str, object],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[int, dict[str, object]]:
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    rc = main(
        [
            "guard",
            "hook",
            "--json",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            harness,
        ]
    )
    return rc, json.loads(capsys.readouterr().out)


def _seed_review_bundle(home_dir: Path, *, harness_selector: str = "*") -> GuardStore:
    store = GuardStore(home_dir)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(
            action="block",
            policy_rules=[
                {
                    "action": "review",
                    "ruleId": "policy-review-1",
                    "ecosystemSelector": "npm",
                    "enabled": True,
                    "expiresAt": "2099-01-01T00:00:00Z",
                    "harnessSelector": harness_selector,
                    "packageSelector": "minimist",
                    "priority": 1,
                    "severityThreshold": "low",
                    "versionRangeSelector": "1.2.8",
                }
            ],
        ),
        "2026-05-19T00:00:00Z",
    )
    return store


def _seed_block_bundle(home_dir: Path) -> GuardStore:
    store = GuardStore(home_dir)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(action="block"),
        "2026-05-19T00:00:00Z",
    )
    return store


@pytest.mark.parametrize(
    "harness",
    ["codex", "claude-code", "opencode", "copilot", "gemini", "hermes", "openclaw"],
)
def test_phase14_guard_hook_enriches_package_contract_for_managed_harnesses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    harness: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    store = _seed_review_bundle(home_dir)
    (home_dir / "config.toml").write_text("approval_wait_timeout_seconds = 0\n", encoding="utf-8")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(
        guard_commands_module,
        "load_guard_surface_daemon_client",
        lambda _home: (_ for _ in ()).throw(RuntimeError("no daemon client")),
    )

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness=harness,
        event=_event_for_harness(harness, "npm install minimist@1.2.8", workspace_dir),
        capsys=capsys,
        monkeypatch=monkeypatch,
    )

    pending = store.list_approval_requests(limit=5)

    assert rc == 1
    assert output["artifact_type"] == "package_request"
    assert pending
    assert pending[0]["artifact_type"] == "package_request"
    assert pending[0]["action_envelope_json"]["package_manager"] == "npm"
    assert pending[0]["action_envelope_json"]["package_name"] == "minimist"
    assert pending[0]["action_envelope_json"]["package_intent_kind"] == "install"
    assert pending[0]["action_envelope_json"]["package_targets"] == ["minimist@1.2.8"]
    assert pending[0]["action_envelope_json"]["pre_execution_result"] == output["policy_action"]


def test_phase14_package_hook_retry_after_block_reuses_saved_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    store = _seed_review_bundle(home_dir, harness_selector="codex")
    (home_dir / "config.toml").write_text("approval_wait_timeout_seconds = 0\n", encoding="utf-8")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(
        guard_commands_module,
        "load_guard_surface_daemon_client",
        lambda _home: (_ for _ in ()).throw(RuntimeError("no daemon client")),
    )
    event = _event_for_harness("codex", "npm install minimist@1.2.8", workspace_dir)

    first_rc, first_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    request_id = str(store.list_approval_requests(limit=5)[0]["request_id"])
    apply_approval_resolution(
        store=store,
        request_id=request_id,
        action="block",
        scope="artifact",
        workspace=None,
        reason="blocked in phase14 test",
    )

    second_rc, second_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )

    assert first_rc == 1
    assert first_output["policy_action"] == "require-reapproval"
    assert second_rc == 1
    assert second_output["policy_action"] == "block"
    assert second_output.get("approval_requests") in (None, [])
    assert store.count_approval_requests(status="pending") == 0


def test_phase14_package_hook_evidence_includes_source_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    store = _seed_review_bundle(home_dir)
    (home_dir / "config.toml").write_text("approval_wait_timeout_seconds = 0\n", encoding="utf-8")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(
        guard_commands_module,
        "load_guard_surface_daemon_client",
        lambda _home: (_ for _ in ()).throw(RuntimeError("no daemon client")),
    )

    rc, _output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=_event_for_harness("codex", "npm install minimist@1.2.8", workspace_dir),
        capsys=capsys,
        monkeypatch=monkeypatch,
    )

    evidence = store.list_evidence()
    details = evidence[0]["details"]

    assert rc == 1
    assert details["harness"] == "codex"
    assert details["agent_app"] == "codex"
    assert details["workspace_fingerprint"]
    assert details["command_shape"] == "npm install minimist@1.2.8"


@pytest.mark.parametrize(
    "harness",
    ["codex", "claude-code", "opencode", "copilot", "gemini", "hermes", "openclaw"],
)
def test_phase14_package_hook_block_copy_stays_consistent_across_harnesses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    harness: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _seed_block_bundle(home_dir)
    (home_dir / "config.toml").write_text("approval_wait_timeout_seconds = 0\n", encoding="utf-8")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(
        guard_commands_module,
        "load_guard_surface_daemon_client",
        lambda _home: (_ for _ in ()).throw(RuntimeError("no daemon client")),
    )

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness=harness,
        event=_event_for_harness(harness, "npm install minimist@1.2.8", workspace_dir),
        capsys=capsys,
        monkeypatch=monkeypatch,
    )

    decision = output["decision_v2_json"]

    assert rc == 1
    assert decision["user_title"] == "Critical install blocked"
    assert decision["harness_message"].startswith("HOL Guard blocked")
    assert "Reason:" in decision["harness_message"]
    assert "Fix: install `npm install minimist@1.2.9` or choose a team exception." in decision["harness_message"]
    assert (
        "Open HOL Guard to approve or keep this blocked: http://127.0.0.1:5474/requests/" in decision["harness_message"]
    )
    assert "guard/inbox" not in decision["harness_message"]


def test_phase14_claude_daemon_hook_bridge_queues_package_install_without_node(tmp_path: Path) -> None:
    """Claude hooks must not depend on a Node binary for supply-chain enforcement."""
    from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=guard_home,
    )
    _seed_review_bundle(guard_home, harness_selector="claude-code")
    (guard_home / "config.toml").write_text("approval_wait_timeout_seconds = 0\n", encoding="utf-8")
    (guard_home / "daemon-state.json").write_text('{"port":59998}', encoding="utf-8")

    adapter = ClaudeCodeHarnessAdapter()
    command = adapter._daemon_hook_command(context)
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "npm install minimist@1.2.8"},
        "cwd": str(workspace_dir),
    }
    result = subprocess.run(
        ["/bin/sh", "-c", command],
        input=json.dumps(event),
        text=True,
        capture_output=True,
        timeout=40,
        check=False,
    )
    payload = json.loads(result.stdout)

    assert result.returncode == 0
    assert result.stderr == ""
    assert "minimist@1.2.8" in result.stdout
    assert payload["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "minimist@1.2.8" in payload["hookSpecificOutput"]["permissionDecisionReason"]
