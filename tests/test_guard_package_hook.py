"""Package-request hook integration tests for HOL Guard."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.runtime.signals import RiskSignalV2
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


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


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


def _write_codex_pre_tool_payload(path: Path, workspace_dir: Path, command: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
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
        ),
        encoding="utf-8",
    )


class _CiscoSignalStub:
    plain_language_summary = "Cisco scanner found a critical package exfiltration path."

    def to_dict(self) -> dict[str, object]:
        return {
            "signal_id": "cisco:package-exfiltration",
            "category": "network",
            "severity": "critical",
            "confidence": "strong",
            "detector": "cisco",
            "title": "Cisco scanner found a critical package exfiltration path.",
            "plain_language_summary": self.plain_language_summary,
        }


def _scanner_signal_v2() -> RiskSignalV2:
    return RiskSignalV2(
        signal_id="cisco:package-exfiltration",
        category="network",
        severity="critical",
        confidence="strong",
        detector="cisco",
        title="Cisco scanner found a critical package exfiltration path.",
        plain_reason="Cisco scanner found a critical package exfiltration path.",
        technical_detail=None,
        evidence_ref="artifact",
        redaction_level="summary",
        false_positive_hint=None,
        advisory_id=None,
    )


def _data_flow_signal_v2() -> RiskSignalV2:
    return RiskSignalV2(
        signal_id="data-flow:secret-pipe-http",
        category="network",
        severity="critical",
        confidence="strong",
        detector="data_flow.exfiltration",
        title="Shell pipeline sends a local secret to a network host",
        plain_reason="This command sends local secret to network host.",
        technical_detail="source and sink were detected without retaining secret contents",
        evidence_ref="command",
        redaction_level="summary",
        false_positive_hint="Allow only when the command intentionally moves non-sensitive data.",
        advisory_id=None,
    )


def test_guard_hook_terminal_package_block_is_not_queued_for_browser_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    payload_path = workspace_dir / "hook-event.json"
    _write_codex_pre_tool_payload(payload_path, workspace_dir, "npm install minimist@1.2.8")
    store = GuardStore(home_dir)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(action="block"), "2026-05-19T00:00:00Z")
    (home_dir / "config.toml").write_text("approval_wait_timeout_seconds = 0\n", encoding="utf-8")
    monkeypatch.setenv("CODEX_MANAGED_BY_BUN", "1")

    def unexpected_browser_approval(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("terminal package block must not queue or wait for browser approval")

    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", unexpected_browser_approval)
    monkeypatch.setattr(guard_commands_module, "queue_blocked_approvals", unexpected_browser_approval)
    monkeypatch.setattr(guard_commands_module, "wait_for_approval_requests", unexpected_browser_approval)

    def fail_subprocess(*args: object, **kwargs: object) -> object:
        raise AssertionError("blocked package request must not launch a subprocess")

    monkeypatch.setattr(guard_commands_module.subprocess, "run", fail_subprocess)

    rc = main(
        [
            "guard",
            "hook",
            "--harness",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--event-file",
            str(payload_path),
        ]
    )
    captured = capsys.readouterr()

    payload = json.loads(captured.out)
    assert rc == 0
    assert captured.err == ""
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    reason = str(payload["hookSpecificOutput"]["permissionDecisionReason"])
    assert "blocked" in reason.lower()
    assert "terminal policy decision" in reason
    assert "Browser approval cannot override it" in reason
    assert "/requests/" not in reason
    evidence = store.list_evidence()
    assert evidence
    assert evidence[0]["category"] == "supply-chain"
    queued_events = store.list_guard_events_v1(uploaded=False)
    assert queued_events
    assert any(event["event_type"] == "receipt.created" for event in queued_events)
    assert store.list_approval_requests(limit=5) == []


def test_guard_hook_ask_queues_package_approval_with_advisory_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    payload_path = workspace_dir / "hook-event.json"
    _write_codex_pre_tool_payload(payload_path, workspace_dir, "npm install minimist@1.2.8")
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
                    "harnessSelector": "codex",
                    "packageSelector": "minimist",
                    "priority": 1,
                    "severityThreshold": "low",
                    "versionRangeSelector": "1.2.8",
                }
            ],
        ),
        "2026-05-19T00:00:00Z",
    )
    (home_dir / "config.toml").write_text("approval_wait_timeout_seconds = 0\n", encoding="utf-8")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")

    def fail_daemon(_home: Path) -> object:
        raise RuntimeError("no daemon client")

    monkeypatch.setattr(guard_commands_module, "load_guard_surface_daemon_client", fail_daemon)

    rc = main(
        [
            "guard",
            "hook",
            "--harness",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--event-file",
            str(payload_path),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert output["policy_action"] == "require-reapproval"
    assert output["approval_requests"]
    pending = store.list_approval_requests(limit=5)
    assert pending[0]["risk_summary"]
    assert "minimist" in pending[0]["risk_summary"].lower()


def test_guard_hook_ask_package_live_wait_surfaces_approval_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    payload_path = workspace_dir / "hook-event.json"
    _write_codex_pre_tool_payload(payload_path, workspace_dir, "npm install minimist@1.2.8")
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
                    "harnessSelector": "codex",
                    "packageSelector": "minimist",
                    "priority": 1,
                    "severityThreshold": "low",
                    "versionRangeSelector": "1.2.8",
                }
            ],
        ),
        "2026-05-19T00:00:00Z",
    )
    (home_dir / "config.toml").write_text("approval_wait_timeout_seconds = 10\n", encoding="utf-8")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")

    def fail_daemon(_home: Path) -> object:
        raise RuntimeError("no daemon")

    monkeypatch.setattr(guard_commands_module, "load_guard_surface_daemon_client", fail_daemon)
    opened_urls: list[str] = []
    resolved_request_ids: list[str] = []
    monkeypatch.setattr(guard_commands_module.webbrowser, "open", opened_urls.append)

    def resolve_actual_exact_request(**kwargs: object) -> dict[str, object]:
        request_ids = kwargs.get("request_ids")
        assert isinstance(request_ids, list)
        assert request_ids
        resolved_items: list[dict[str, object]] = []
        for request_id_value in request_ids:
            assert isinstance(request_id_value, str)
            queued_request = store.get_approval_request(request_id_value)
            assert queued_request is not None
            assert str(queued_request["artifact_hash"]).startswith("guard-approval-context:v1:")
            apply_approval_resolution(
                store=store,
                request_id=request_id_value,
                action="allow",
                scope="artifact",
                workspace=None,
                reason="approved exact package request",
            )
            resolved_request = store.get_approval_request(request_id_value)
            assert resolved_request is not None
            resolved_items.append(resolved_request)
            resolved_request_ids.append(request_id_value)
        return {
            "resolved": True,
            "pending_request_ids": [],
            "items": resolved_items,
        }

    monkeypatch.setattr(
        guard_commands_module,
        "wait_for_approval_requests",
        resolve_actual_exact_request,
    )

    rc = main(
        [
            "guard",
            "hook",
            "--harness",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--event-file",
            str(payload_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 0
    assert captured.out == ""
    assert len(resolved_request_ids) == 1
    assert opened_urls
    assert "/requests/" in opened_urls[0]
    assert opened_urls[0] in captured.err


def test_guard_hook_ask_package_live_wait_caps_browser_approval_wait(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    payload_path = workspace_dir / "hook-event.json"
    _write_codex_pre_tool_payload(payload_path, workspace_dir, "npm install minimist@1.2.8")
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
                    "harnessSelector": "codex",
                    "packageSelector": "minimist",
                    "priority": 1,
                    "severityThreshold": "low",
                    "versionRangeSelector": "1.2.8",
                }
            ],
        ),
        "2026-05-19T00:00:00Z",
    )
    (home_dir / "config.toml").write_text("approval_wait_timeout_seconds = 120\n", encoding="utf-8")
    observed_timeouts: list[int] = []
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")

    def fail_daemon(_home: Path) -> object:
        raise RuntimeError("no daemon")

    monkeypatch.setattr(guard_commands_module, "load_guard_surface_daemon_client", fail_daemon)
    monkeypatch.setattr(guard_commands_module.webbrowser, "open", lambda _url: None)

    def unresolved_wait(**kwargs: object) -> dict[str, object]:
        timeout_seconds = kwargs.get("timeout_seconds")
        assert isinstance(timeout_seconds, int)
        observed_timeouts.append(timeout_seconds)
        return {"resolved": False, "status": "timeout", "items": []}

    monkeypatch.setattr(guard_commands_module, "wait_for_approval_requests", unresolved_wait)

    rc = main(
        [
            "guard",
            "hook",
            "--harness",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--event-file",
            str(payload_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 0
    assert observed_timeouts == [8]
    assert "/requests/" in captured.out or "/requests/" in captured.err


def test_guard_hook_warns_for_package_request_without_blocking(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    payload_path = workspace_dir / "hook-event.json"
    _write_codex_pre_tool_payload(payload_path, workspace_dir, "npm install minimist@1.2.8")
    store = GuardStore(home_dir)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(action="warn"), "2026-05-19T00:00:00Z")

    rc = main(
        [
            "guard",
            "hook",
            "--harness",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--event-file",
            str(payload_path),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["policy_action"] == "warn"
    assert output["risk_summary"]
    assert "minimist@1.2.8" in output["supply_chain_evaluation"]["risk_summary"]
    assert output["supply_chain_evaluation"]["packages"]
    assert "approval_requests" not in output


def test_guard_hook_keeps_block_copy_when_scanner_escalates_package_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    payload_path = workspace_dir / "hook-event.json"
    _write_codex_pre_tool_payload(payload_path, workspace_dir, "npm install minimist@1.2.8")
    store = GuardStore(home_dir)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(action="warn"), "2026-05-19T00:00:00Z")
    (home_dir / "config.toml").write_text("approval_wait_timeout_seconds = 0\n", encoding="utf-8")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")

    def fail_daemon(_home: Path) -> object:
        raise RuntimeError("no daemon client")

    monkeypatch.setattr(guard_commands_module, "load_guard_surface_daemon_client", fail_daemon)
    monkeypatch.setattr(
        guard_commands_module,
        "scan_action_for_cisco_evidence",
        lambda *_args, **_kwargs: (_CiscoSignalStub(),),
    )
    monkeypatch.setattr(
        guard_commands_module,
        "policy_action_for_cisco_signals",
        lambda *_args, **_kwargs: "block",
    )
    monkeypatch.setattr(
        guard_commands_module,
        "cisco_risk_signal_v3_to_v2",
        lambda _signal: _scanner_signal_v2(),
    )

    rc = main(
        [
            "guard",
            "hook",
            "--harness",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--event-file",
            str(payload_path),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert output["policy_action"] == "block"
    assert output["decision_v2_json"]["user_title"] == "Blocked by policy"
    assert output["decision_v2_json"]["user_title"] != output["supply_chain_evaluation"]["user_copy"]["title"]
    assert (
        output["decision_v2_json"]["dashboard_primary_detail"]
        == "Cisco scanner found a critical package exfiltration path."
    )


def test_guard_hook_keeps_data_flow_summary_when_package_warning_is_weaker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    payload_path = workspace_dir / "hook-event.json"
    _write_codex_pre_tool_payload(payload_path, workspace_dir, "npm install minimist@1.2.8")
    store = GuardStore(home_dir)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(action="warn"), "2026-05-19T00:00:00Z")
    (home_dir / "config.toml").write_text("approval_wait_timeout_seconds = 0\n", encoding="utf-8")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")

    def fail_daemon(_home: Path) -> object:
        raise RuntimeError("no daemon client")

    monkeypatch.setattr(guard_commands_module, "load_guard_surface_daemon_client", fail_daemon)
    monkeypatch.setattr(
        guard_commands_module,
        "_runtime_action_data_flow_signals",
        lambda *_args, **_kwargs: (_data_flow_signal_v2(),),
    )
    monkeypatch.setattr(
        guard_commands_module,
        "resolve_risk_action",
        lambda _config, risk_class, harness=None: "block" if risk_class == "data_flow_exfiltration" else "allow",
    )
    monkeypatch.setattr(
        guard_commands_module,
        "scan_action_for_cisco_evidence",
        lambda *_args, **_kwargs: (),
    )

    rc = main(
        [
            "guard",
            "hook",
            "--harness",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--event-file",
            str(payload_path),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert output["policy_action"] == "block"
    assert "network host" in output["risk_summary"]
    assert output["decision_v2_json"]["user_title"] == "Blocked by policy"
    assert (
        output["decision_v2_json"]["dashboard_primary_detail"] == "Source-to-sink route: local secret -> network host. "
        "This command sends local secret to network host without exposing the raw secret in Guard evidence."
    )
    assert output["decision_v2_json"]["dashboard_primary_detail"] != output["supply_chain_evaluation"]["risk_summary"]
    evidence = store.list_evidence()
    assert evidence
    assert evidence[0]["category"] == "supply-chain"
