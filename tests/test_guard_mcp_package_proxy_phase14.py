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
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer.service import artifact_hash
from codex_plugin_scanner.guard.mcp_tool_calls import ToolCallDecision
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.proxy import runtime_mcp as runtime_mcp_module
from codex_plugin_scanner.guard.proxy.runtime_mcp import RuntimeMcpGuardProxy
from codex_plugin_scanner.guard.runtime.package_intent import (
    build_package_request_artifact,
    extract_package_intent_request,
)
from codex_plugin_scanner.guard.store import GuardStore

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


@pytest.mark.parametrize("harness", ["cursor", "opencode", "hermes", "openclaw"])
def test_phase14_runtime_mcp_proxy_queues_package_request_not_generic_tool_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness: str,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "demo-token",
        "2026-05-19T00:00:00Z",
        workspace_id=WORKSPACE_ID,
    )
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

    request = store.list_approval_requests(limit=5)[0]

    assert marker_path.exists() is False
    assert result["responses"][2]["error"]["code"] == -32001
    assert request["artifact_type"] == "package_request"
    assert request["decision_v2_json"]["signals"]
    assert "minimist" in str(request["risk_summary"]).lower()


def test_phase14_runtime_mcp_proxy_forwards_allowed_package_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "demo-token",
        "2026-05-19T00:00:00Z",
        workspace_id=WORKSPACE_ID,
    )
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


def test_phase14_runtime_mcp_proxy_honors_stored_allow_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "demo-token",
        "2026-05-19T00:00:00Z",
        workspace_id=WORKSPACE_ID,
    )
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

    assert marker_path.exists() is True
    assert "error" not in result["responses"][2]
    assert store.list_approval_requests(limit=5) == []


def test_phase14_runtime_mcp_proxy_honors_stored_allow_override_without_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context_without_workspace(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "demo-token",
        "2026-05-19T00:00:00Z",
        workspace_id=WORKSPACE_ID,
    )
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

    assert marker_path.exists() is True
    assert "error" not in result["responses"][2]
    assert store.list_approval_requests(limit=5) == []


def test_phase14_runtime_mcp_proxy_skips_requeue_for_stored_package_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "demo-token",
        "2026-05-19T00:00:00Z",
        workspace_id=WORKSPACE_ID,
    )
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
    store.upsert_policy(
        PolicyDecision(
            harness="cursor",
            scope="artifact",
            action="block",
            artifact_id=package_artifact.artifact_id,
            artifact_hash=artifact_hash(package_artifact),
            workspace=None,
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

    request = store.list_approval_requests(limit=5)[0]

    assert marker_path.exists() is False
    assert result["responses"][2]["error"]["code"] == -32001
    assert request["artifact_type"] == "tool_call"


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
