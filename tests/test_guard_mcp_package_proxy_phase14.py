"""Phase 14 MCP package-routing regressions."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approval_scope_support import package_request_runtime_workspace_scope
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer.service import artifact_hash
from codex_plugin_scanner.guard.local_supply_chain import package_request_policy_hash
from codex_plugin_scanner.guard.mcp_tool_calls import ToolCallDecision
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.package_execution_context import build_package_execution_context
from codex_plugin_scanner.guard.proxy import runtime_mcp as runtime_mcp_module
from codex_plugin_scanner.guard.proxy.runtime_mcp import CodexMcpGuardProxy, RuntimeMcpGuardProxy
from codex_plugin_scanner.guard.runtime.package_intent import (
    build_package_request_artifact,
    extract_package_intent_request,
)
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
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


def _bundle_response(*, action: str) -> dict[str, object]:
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
        "policyRules": [],
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


def _child_command(marker_path: Path) -> list[str]:
    return [
        sys.executable,
        "-u",
        "-c",
        "\n".join(
            [
                "import json",
                "import sys",
                "from pathlib import Path",
                f"marker_path = Path({str(marker_path)!r})",
                "for line in sys.stdin:",
                "    message = json.loads(line)",
                "    message_id = message.get('id')",
                "    method = message.get('method')",
                "    if method == 'initialize':",
                (
                    "        result = {'protocolVersion': '2025-06-18', "
                    "'capabilities': {'tools': {}}, "
                    "'serverInfo': {'name': 'fixture', 'version': '1.0.0'}}"
                ),
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': result}))",
                "        sys.stdout.flush()",
                "        continue",
                "    if method == 'tools/list':",
                "        tool = {",
                "            'name': 'run_terminal_command',",
                "            'description': 'Run a terminal command in the workspace.',",
                "            'inputSchema': {'type': 'object', 'properties': {'command': {'type': 'string'}}},",
                "        }",
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': {'tools': [tool]}}))",
                "        sys.stdout.flush()",
                "        continue",
                "    if method == 'tools/call':",
                "        marker_path.write_text(json.dumps(message.get('params', {})), encoding='utf-8')",
                (
                    "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, "
                    "'result': {'content': [{'type': 'text', 'text': 'forwarded'}]}}))"
                ),
                "        sys.stdout.flush()",
                "        continue",
                "    print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': {}}))",
                "    sys.stdout.flush()",
            ]
        ),
    ]


def _context(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir(parents=True, exist_ok=True)
    workspace_dir.mkdir(parents=True, exist_ok=True)
    guard_home.mkdir(parents=True, exist_ok=True)
    return HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)


def _context_without_workspace(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir(parents=True, exist_ok=True)
    guard_home.mkdir(parents=True, exist_ok=True)
    return HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)


def _package_policy_key(
    *,
    context: HarnessContext,
    store: GuardStore,
    artifact: GuardArtifact,
    config: GuardConfig | None = None,
) -> tuple[str, str]:
    assert context.workspace_dir is not None
    effective_config = config or GuardConfig(
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
    )
    evaluation = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=context.workspace_dir,
    )
    execution_context = build_package_execution_context(
        workspace_dir=context.workspace_dir,
        artifact=artifact,
    )
    digest = package_request_policy_hash(
        artifact=artifact,
        store=store,
        workspace_dir=context.workspace_dir,
        evaluation=evaluation,
        execution_context=execution_context,
        config=effective_config,
    )
    workspace = package_request_runtime_workspace_scope(
        artifact_id=artifact.artifact_id,
        artifact_hash=digest,
        artifact_type=artifact.artifact_type,
        execution_context=execution_context,
    )
    assert workspace is not None
    return digest, workspace


def _allow_mcp_tool_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runtime_mcp_module,
        "evaluate_tool_call",
        lambda **_kwargs: ToolCallDecision(
            action="allow",
            source="heuristic",
            signals=(),
            summary="tool call allowed",
        ),
    )


def _runtime_package_artifact(context: HarnessContext) -> GuardArtifact:
    intent = extract_package_intent_request(
        "run_terminal_command",
        {"command": "npm install minimist@1.2.8"},
        action_envelope_command="npm install minimist@1.2.8",
        workspace=context.workspace_dir,
    )
    assert intent is not None
    assert context.workspace_dir is not None
    return build_package_request_artifact(
        harness="cursor",
        intent=intent,
        config_path=str(context.workspace_dir / ".cursor" / "mcp.json"),
        source_scope="project",
    )


def _runtime_package_policy_config(
    *,
    context: HarnessContext,
    package_action: GuardAction = "review",
    harness_action: GuardAction | None = None,
    artifact_id: str | None = None,
    artifact_action: GuardAction | None = None,
) -> GuardConfig:
    return GuardConfig(
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        security_level="custom",
        risk_actions={"package_script": package_action},
        harness_actions={"cursor": harness_action} if harness_action is not None else None,
        artifact_actions={artifact_id: artifact_action}
        if artifact_id is not None and artifact_action is not None
        else None,
    )


def _seed_runtime_package_review_allow(
    *,
    context: HarnessContext,
    store: GuardStore,
    artifact: GuardArtifact,
    config: GuardConfig,
) -> None:
    package_digest, policy_workspace = _package_policy_key(
        context=context,
        store=store,
        artifact=artifact,
        config=config,
    )
    store.ensure_policy_integrity_ready_for_write(now="2026-05-19T00:00:00Z")
    store.upsert_policy(
        PolicyDecision(
            harness="cursor",
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=package_digest,
            workspace=policy_workspace,
            publisher=artifact.publisher,
            source="approval-gate",
            reason="reviewed exact package request",
        ),
        "2026-05-19T00:00:00Z",
    )


def _run_runtime_package_call(
    *,
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
    marker_path: Path,
) -> dict[str, object]:
    proxy = RuntimeMcpGuardProxy(
        harness="cursor",
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        current_config_provider=lambda: config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".cursor" / "mcp.json"),
    )
    return proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "run_terminal_command",
                    "arguments": {"command": "npm install minimist@1.2.8"},
                },
            },
        ]
    )


@pytest.mark.parametrize("harness", ["cursor", "opencode", "hermes", "openclaw"])
def test_phase14_runtime_mcp_proxy_terminally_blocks_package_request_not_generic_tool_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness: str,
) -> None:
    _allow_mcp_tool_calls(monkeypatch)
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(action="block"), "2026-05-19T00:00:00Z")
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / f"{harness}-mcp-forwarded.json"
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    proxy = RuntimeMcpGuardProxy(
        harness=harness,
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        current_config_provider=lambda: config,
        source_scope="project",
        config_path=str(context.workspace_dir / f"{harness}.json"),
    )

    result = proxy.run_session(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"capabilities": {}},
            },
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "run_terminal_command",
                    "arguments": {"command": "npm install minimist@1.2.8"},
                },
            },
        ]
    )

    assert marker_path.exists() is False
    response = result["responses"][2]
    assert response["error"]["code"] == -32001
    assert response["error"]["data"]["guardPolicyAction"] == "block"
    assert response["error"]["data"]["approvalRequests"] == []
    assert store.list_approval_requests(limit=5) == []
    receipts = store.list_receipts(limit=10)
    assert len(receipts) == 1
    assert receipts[0]["artifact_id"].startswith(f"{harness}:project:package-request:")
    assert receipts[0]["policy_decision"] == "block"


def test_phase14_runtime_mcp_proxy_forwards_allowed_package_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_mcp_tool_calls(monkeypatch)
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(action="allow"), "2026-05-19T00:00:00Z")
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "cursor-mcp-forwarded.json"
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    proxy = RuntimeMcpGuardProxy(
        harness="cursor",
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".cursor" / "mcp.json"),
    )

    result = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "run_terminal_command",
                    "arguments": {"command": "npm install minimist@1.2.8"},
                },
            },
        ]
    )

    assert marker_path.exists() is True
    assert "error" not in result["responses"][2]
    assert store.list_approval_requests(limit=5) == []
    receipts = store.list_receipts(limit=10)
    assert len(receipts) == 1
    assert receipts[0]["artifact_id"].startswith("cursor:project:package-request:")
    assert receipts[0]["policy_decision"] == "warn"


def test_runtime_mcp_reuses_unchanged_exact_package_review_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_mcp_tool_calls(monkeypatch)
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(action="allow"), "2026-05-19T00:00:00Z")
    artifact = _runtime_package_artifact(context)
    config = _runtime_package_policy_config(context=context)
    _seed_runtime_package_review_allow(context=context, store=store, artifact=artifact, config=config)
    marker_path = tmp_path / "cursor-mcp-unchanged-review.json"
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")

    result = _run_runtime_package_call(
        context=context,
        store=store,
        config=config,
        marker_path=marker_path,
    )

    assert marker_path.exists() is True
    assert "error" not in result["responses"][2]
    assert store.list_approval_requests(limit=5) == []
    package_events = [event for event in result["events"] if str(event.get("decision", "")).startswith("package-")]
    assert package_events
    assert package_events[-1]["decision"] == "package-allow"
    receipts = store.list_receipts(limit=10)
    assert len(receipts) == 1
    assert receipts[0]["artifact_id"] == artifact.artifact_id
    assert receipts[0]["policy_decision"] == "allow"


@pytest.mark.parametrize("blocking_policy", ["package_script", "harness", "package_artifact"])
def test_runtime_mcp_old_package_review_approval_cannot_lower_current_config_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    blocking_policy: str,
) -> None:
    _allow_mcp_tool_calls(monkeypatch)
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(action="allow"), "2026-05-19T00:00:00Z")
    artifact = _runtime_package_artifact(context)
    base_config = _runtime_package_policy_config(context=context)
    _seed_runtime_package_review_allow(context=context, store=store, artifact=artifact, config=base_config)
    changed_config = _runtime_package_policy_config(
        context=context,
        package_action="block" if blocking_policy == "package_script" else "review",
        harness_action="block" if blocking_policy == "harness" else None,
        artifact_id=artifact.artifact_id if blocking_policy == "package_artifact" else None,
        artifact_action="block" if blocking_policy == "package_artifact" else None,
    )
    marker_path = tmp_path / f"cursor-mcp-current-{blocking_policy}-block.json"
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")

    result = _run_runtime_package_call(
        context=context,
        store=store,
        config=changed_config,
        marker_path=marker_path,
    )

    assert marker_path.exists() is False
    response = result["responses"][2]
    assert response["error"]["code"] == -32001
    assert "block" in json.dumps(response).lower()
    assert response["error"]["data"]["guardPolicyAction"] == "block"
    assert response["error"]["data"]["approvalRequests"] == []
    assert store.list_approval_requests(limit=1) == []
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "block"
    assert (
        receipt["artifact_hash"]
        != _package_policy_key(
            context=context,
            store=store,
            artifact=artifact,
            config=base_config,
        )[0]
    )


def test_phase14_runtime_mcp_proxy_rejects_stored_allow_when_current_package_blocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_mcp_tool_calls(monkeypatch)
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(action="block"), "2026-05-19T00:00:00Z")
    intent = extract_package_intent_request(
        "run_terminal_command",
        {"command": "npm install minimist@1.2.8"},
        action_envelope_command="npm install minimist@1.2.8",
        workspace=context.workspace_dir,
    )
    assert intent is not None
    package_artifact = build_package_request_artifact(
        harness="cursor",
        intent=intent,
        config_path=str(context.workspace_dir / ".cursor" / "mcp.json"),
        source_scope="project",
    )
    package_digest, policy_workspace = _package_policy_key(
        context=context,
        store=store,
        artifact=package_artifact,
    )
    store.upsert_policy(
        PolicyDecision(
            harness="cursor",
            scope="artifact",
            action="allow",
            artifact_id=package_artifact.artifact_id,
            artifact_hash=package_digest,
            workspace=policy_workspace,
            publisher=None,
            reason="verified false positive",
        ),
        "2026-05-19T00:00:00Z",
    )
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "cursor-mcp-override.json"
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    proxy = RuntimeMcpGuardProxy(
        harness="cursor",
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".cursor" / "mcp.json"),
    )

    result = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "run_terminal_command",
                    "arguments": {"command": "npm install minimist@1.2.8"},
                },
            },
        ]
    )

    assert marker_path.exists() is False
    assert result["responses"][2]["error"]["code"] == -32001
    assert result["responses"][2]["error"]["data"]["guardPolicyAction"] == "block"
    assert store.list_approval_requests(limit=5) == []


def test_phase14_runtime_mcp_proxy_rejects_stored_allow_without_workspace_when_current_package_blocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context_without_workspace(tmp_path)
    store = GuardStore(context.guard_home)
    tool_claims: list[object] = []
    monkeypatch.setattr(
        runtime_mcp_module,
        "evaluate_tool_call",
        lambda **_kwargs: ToolCallDecision(
            action="allow",
            source="policy",
            signals=("tool review",),
            summary="provisionally accepted saved tool approval",
            approval_reuse_status="accepted",
            approval_reuse_reason_code="approval_reuse_accepted",
            current_action="review",
            saved_action="allow",
            pending_approval_reuse_decision={"action": "allow", "decision_id": 999},
        ),
    )
    monkeypatch.setattr(
        store,
        "claim_approval_reuse_decisions",
        lambda decisions, **_kwargs: tool_claims.extend(decisions) is None,
    )
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(action="block"), "2026-05-19T00:00:00Z")
    intent = extract_package_intent_request(
        "run_terminal_command",
        {"command": "npm install minimist@1.2.8"},
        action_envelope_command="npm install minimist@1.2.8",
        workspace=None,
    )
    assert intent is not None
    package_artifact = build_package_request_artifact(
        harness="cursor",
        intent=intent,
        config_path=str(context.home_dir / ".cursor" / "mcp.json"),
        source_scope="project",
    )
    store.upsert_policy(
        PolicyDecision(
            harness="cursor",
            scope="artifact",
            action="allow",
            artifact_id=package_artifact.artifact_id,
            artifact_hash=artifact_hash(package_artifact),
            workspace=None,
            publisher=None,
            reason="verified false positive",
        ),
        "2026-05-19T00:00:00Z",
    )
    config = GuardConfig(guard_home=context.guard_home, workspace=None)
    marker_path = tmp_path / "cursor-mcp-no-workspace.json"
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    proxy = RuntimeMcpGuardProxy(
        harness="cursor",
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.home_dir / ".cursor" / "mcp.json"),
    )

    result = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "run_terminal_command",
                    "arguments": {"command": "npm install minimist@1.2.8"},
                },
            },
        ]
    )

    assert marker_path.exists() is False
    assert result["responses"][2]["error"]["code"] == -32001
    assert result["responses"][2]["error"]["data"]["guardPolicyAction"] == "block"
    assert store.list_approval_requests(limit=5) == []
    assert tool_claims == []


def test_phase14_runtime_mcp_proxy_skips_requeue_for_stored_package_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_mcp_tool_calls(monkeypatch)
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(action="block"), "2026-05-19T00:00:00Z")
    intent = extract_package_intent_request(
        "run_terminal_command",
        {"command": "npm install minimist@1.2.8"},
        action_envelope_command="npm install minimist@1.2.8",
        workspace=context.workspace_dir,
    )
    assert intent is not None
    package_artifact = build_package_request_artifact(
        harness="cursor",
        intent=intent,
        config_path=str(context.workspace_dir / ".cursor" / "mcp.json"),
        source_scope="project",
    )
    package_digest, policy_workspace = _package_policy_key(
        context=context,
        store=store,
        artifact=package_artifact,
    )
    store.upsert_policy(
        PolicyDecision(
            harness="cursor",
            scope="artifact",
            action="block",
            artifact_id=package_artifact.artifact_id,
            artifact_hash=package_digest,
            workspace=policy_workspace,
            publisher=None,
            reason="known blocked package",
        ),
        "2026-05-19T00:00:00Z",
    )
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "cursor-mcp-stored-block.json"
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    proxy = RuntimeMcpGuardProxy(
        harness="cursor",
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".cursor" / "mcp.json"),
    )

    result = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "run_terminal_command",
                    "arguments": {"command": "npm install minimist@1.2.8"},
                },
            },
        ]
    )

    assert marker_path.exists() is False
    assert result["responses"][2]["error"]["code"] == -32001
    assert "already blocked by stored policy" in json.dumps(result["responses"][2])
    assert store.list_approval_requests(limit=5) == []


def test_phase14_runtime_mcp_proxy_preserves_tool_policy_for_package_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "cursor-mcp-tool-policy.json"
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(
        runtime_mcp_module,
        "evaluate_tool_call",
        lambda **_kwargs: ToolCallDecision(
            action="block",
            source="policy",
            signals=("command_execution",),
            summary="blocked by explicit tool policy",
            risk_categories=("command_execution",),
        ),
    )
    proxy = RuntimeMcpGuardProxy(
        harness="cursor",
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".cursor" / "mcp.json"),
    )

    result = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "run_terminal_command",
                    "arguments": {"command": "npm install minimist@1.2.8"},
                },
            },
        ]
    )

    assert marker_path.exists() is False
    response = result["responses"][2]
    assert response["error"]["code"] == -32001
    assert response["error"]["data"]["guardPolicyAction"] == "block"
    assert response["error"]["data"]["approvalRequests"] == []
    assert store.list_approval_requests(limit=5) == []
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "block"
    assert ":runtime:" in receipt["artifact_id"]


def test_phase14_runtime_mcp_proxy_enforces_tool_policy_review_before_package_routing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "cursor-mcp-tool-review.json"
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(
        runtime_mcp_module,
        "evaluate_tool_call",
        lambda **_kwargs: ToolCallDecision(
            action="review",
            source="policy",
            signals=("command_execution",),
            summary="review before execution",
            risk_categories=("command_execution",),
        ),
    )
    proxy = RuntimeMcpGuardProxy(
        harness="cursor",
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".cursor" / "mcp.json"),
    )

    result = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "run_terminal_command",
                    "arguments": {"command": "npm install minimist@1.2.8"},
                },
            },
        ]
    )

    request = store.list_approval_requests(limit=5)[0]

    assert marker_path.exists() is False
    assert result["responses"][2]["error"]["code"] == -32001
    assert request["artifact_type"] == "tool_call"


def test_phase14_runtime_mcp_proxy_enforces_non_policy_review_before_package_routing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "cursor-mcp-risk-review.json"
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(
        runtime_mcp_module,
        "evaluate_tool_call",
        lambda **_kwargs: ToolCallDecision(
            action="review",
            source="risk-policy",
            signals=("command_execution",),
            summary="review before execution",
            risk_categories=("command_execution",),
        ),
    )
    proxy = RuntimeMcpGuardProxy(
        harness="cursor",
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".cursor" / "mcp.json"),
    )

    result = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "run_terminal_command",
                    "arguments": {"command": "npm install minimist@1.2.8"},
                },
            },
        ]
    )

    request = store.list_approval_requests(limit=5)[0]

    assert marker_path.exists() is False
    assert result["responses"][2]["error"]["code"] == -32001
    assert request["artifact_type"] == "tool_call"


def test_phase14_codex_package_inline_approval_is_remembered(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(action="allow"), "2026-05-19T00:00:00Z")
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "codex-inline-package.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        current_config_provider=lambda: config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    approvals: list[dict[str, object]] = []
    intent = extract_package_intent_request(
        "run_terminal_command",
        {"command": "npm install minimist@1.2.8"},
        action_envelope_command="npm install minimist@1.2.8",
        workspace=context.workspace_dir,
    )
    assert intent is not None
    package_artifact = build_package_request_artifact(
        harness="codex",
        intent=intent,
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
        source_scope="project",
    )
    package_digest, policy_workspace = _package_policy_key(
        context=context,
        store=store,
        artifact=package_artifact,
    )

    def inline_approval(request: dict[str, object]) -> dict[str, object]:
        approvals.append(request)
        return {"action": "accept", "content": {"decision": "approve"}}

    first_result = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {"elicitation": {}}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "run_terminal_command",
                    "arguments": {"command": "npm install minimist@1.2.8"},
                },
            },
        ],
        inline_approval_callback=inline_approval,
    )
    second_result = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 11, "method": "initialize", "params": {"capabilities": {"elicitation": {}}}},
            {"jsonrpc": "2.0", "id": 12, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": {
                    "name": "run_terminal_command",
                    "arguments": {"command": "npm install minimist@1.2.8"},
                },
            },
        ],
        inline_approval_callback=inline_approval,
    )

    assert marker_path.exists() is True
    assert "error" not in first_result["responses"][2]
    assert "error" not in second_result["responses"][2]
    assert len(approvals) == 1
    assert (
        store.resolve_policy(
            package_artifact.harness,
            package_artifact.artifact_id,
            artifact_hash=package_digest,
            workspace=policy_workspace,
        )
        == "allow"
    )
    receipts = store.list_receipts(limit=10)
    assert len(receipts) == 2
    assert {receipt["artifact_id"] for receipt in receipts} == {package_artifact.artifact_id}
    assert {receipt["policy_decision"] for receipt in receipts} == {"warn"}


def test_phase14_runtime_mcp_proxy_normalizes_stored_review_for_package_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_mcp_tool_calls(monkeypatch)
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(action="allow"), "2026-05-19T00:00:00Z")
    intent = extract_package_intent_request(
        "run_terminal_command",
        {"command": "npm install minimist@1.2.8"},
        action_envelope_command="npm install minimist@1.2.8",
        workspace=context.workspace_dir,
    )
    assert intent is not None
    package_artifact = build_package_request_artifact(
        harness="cursor",
        intent=intent,
        config_path=str(context.workspace_dir / ".cursor" / "mcp.json"),
        source_scope="project",
    )
    package_digest, policy_workspace = _package_policy_key(
        context=context,
        store=store,
        artifact=package_artifact,
    )
    store.upsert_policy(
        PolicyDecision(
            harness="cursor",
            scope="artifact",
            action="review",
            artifact_id=package_artifact.artifact_id,
            artifact_hash=package_digest,
            workspace=policy_workspace,
            publisher=None,
            reason="review exact package request",
        ),
        "2026-05-19T00:00:00Z",
    )
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "cursor-mcp-stored-review.json"
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    proxy = RuntimeMcpGuardProxy(
        harness="cursor",
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".cursor" / "mcp.json"),
    )

    result = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "run_terminal_command",
                    "arguments": {"command": "npm install minimist@1.2.8"},
                },
            },
        ]
    )

    assert marker_path.exists() is False
    assert result["responses"][2]["error"]["code"] == -32001
    assert "approve request" in json.dumps(result["responses"][2]).lower()
    assert len(store.list_approval_requests(limit=5)) == 1
