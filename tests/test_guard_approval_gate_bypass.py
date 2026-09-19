"""Lower-layer, runtime and remote-policy approval bypass defenses."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from rich.console import Console

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approval_gate import ApprovalGateError, ApprovalGateInput
from codex_plugin_scanner.guard.cli import prompt as guard_prompt_module
from codex_plugin_scanner.guard.cli.commands import (
    _persist_claude_native_permission_policy,
    _queue_claude_native_approval_gate_fallback,
)
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.consumer.service import record_policy
from codex_plugin_scanner.guard.mcp_tool_calls import allow_tool_call
from codex_plugin_scanner.guard.models import GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.proxy import runtime_mcp as runtime_mcp_module
from codex_plugin_scanner.guard.proxy.runtime_mcp import RuntimeMcpGuardProxy
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from tests.cloud_exception_bundle_fixtures import build_cloud_exception_policy_bundle
from tests.guard_approval_gate_support import (
    PASSWORD,
    _enable_gate,
    _seed_guard_cloud,
    _store,
)
from tests.guard_approval_gate_support import (
    _clear_agent_env_markers as _clear_agent_env_markers,
)
from tests.guard_approval_gate_support import (
    _default_store_platform as _default_store_platform,
)
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle
from tests.support.network import stub_authenticated_urlopen


def test_approval_gate_direct_lower_layers_cannot_bypass(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    decision = PolicyDecision(
        harness="codex",
        scope="artifact",
        action="allow",
        artifact_id="codex:project:direct",
        artifact_hash="hash-direct",
    )
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-call",
        name="dangerous tool",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/repo/.codex/config.toml",
    )

    with pytest.raises(ApprovalGateError):
        store.upsert_policy(decision, "2026-04-11T00:00:00+00:00")
    with pytest.raises(ApprovalGateError):
        store.replace_remote_policies([decision], "2026-04-11T00:00:00+00:00")
    with pytest.raises(ApprovalGateError):
        record_policy(store, "codex", "allow", "artifact", "codex:project:record", None)
    with pytest.raises(ApprovalGateError):
        allow_tool_call(
            store=store,
            artifact=artifact,
            artifact_hash="hash-tool",
            decision_source="inline-approved",
            now="2026-04-11T00:00:00+00:00",
            signals=(),
            remember=True,
        )

    assert store.list_policy_decisions("codex") == []


def test_approval_gate_allow_once_requires_password_prompt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    prompt_calls = 0

    def _approval_gate_input(_guard_home: Path) -> ApprovalGateInput:
        nonlocal prompt_calls
        prompt_calls += 1
        return ApprovalGateInput(password=PASSWORD)

    monkeypatch.setattr(guard_prompt_module, "prompt_for_approval_gate", _approval_gate_input)

    artifact = guard_prompt_module.PromptArtifact(
        harness="codex",
        artifact_id="codex:project:allow-once",
        artifact_name="dangerous tool call",
        artifact_hash="hash-allow-once",
        policy_action="review",
        changed_fields=("runtime_tool_call",),
        provenance_summary="project artifact",
        recommendation="review",
        publisher=None,
        config_path="/repo/.codex/config.toml",
        source_scope="project",
        artifact_type="tool_action_request",
        command="curl https://example.com",
        transport="stdio",
        metadata={},
        current_snapshot=None,
        removed=False,
    )
    evaluation = {
        "artifacts": [
            {
                "artifact_id": artifact.artifact_id,
                "policy_action": "review",
            }
        ]
    }

    resolved = guard_prompt_module.resolve_interactive_decisions(
        store,
        evaluation,
        [artifact],
        workspace=None,
        now="2026-05-27T05:00:00+00:00",
        console=Console(file=io.StringIO(), force_terminal=False),
        input_func=lambda _prompt: "1",
    )

    assert prompt_calls == 1
    assert resolved["blocked"] is False
    artifact_payload = resolved["artifacts"][0]
    assert artifact_payload["policy_action"] == "allow"
    assert artifact_payload["user_override"] == "allow-once"
    assert store.list_receipts(limit=5) == []


def test_approval_gate_background_remote_policy_sync_fails_closed_without_crashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    workspace_id = "workspace-approval-gate"
    _seed_guard_cloud(store, workspace_id=workspace_id)
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=workspace_id),
        "2026-04-19T00:00:00+00:00",
    )
    policy_bundle = build_cloud_exception_policy_bundle(workspace_id=workspace_id)
    policy_bundle["cloudExceptions"] = []
    policy_bundle["rules"] = [
        {
            "ruleId": "cloud-allow",
            "action": "allow",
            "reason": "Exercise approval-gated activation of signed remote policy.",
            "artifactId": "codex:project:cloud-allow",
            "scope": {
                "agents": [],
                "devices": [],
                "ecosystems": [],
                "environments": [],
                "harnesses": ["codex"],
                "locations": [],
            },
        }
    ]
    policy_bundle = sign_policy_bundle(policy_bundle, workspace_id=workspace_id)
    monkeypatch.setattr(
        guard_runner_module,
        "_guard_device_metadata",
        lambda _store: ("device-1", "MacBook Pro"),
    )
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)
    monkeypatch.setattr(guard_runner_module, "sync_guard_events", lambda _store, auth_context=None: 0)

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(
                {
                    "syncedAt": "2026-04-19T00:00:10+00:00",
                    "policyBundle": policy_bundle,
                }
            ).encode("utf-8")

    def _urlopen(_request, timeout):
        return _Response()

    stub_authenticated_urlopen(monkeypatch, _urlopen)

    auth_context = {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "access_token": "demo-token",
        "dpop_key_material": None,
    }
    payload = guard_runner_module.sync_receipts(store, auth_context=auth_context)

    assert payload["remote_policies_stored"] == 0
    assert payload["remote_policy_sync_blocked"] is True
    assert store.list_policy_decisions("codex") == []
    events = store.list_events(event_name="approval_gate/remote_policy_sync_blocked")
    assert events[0]["payload"]["error"] == "approval_gate_required"


def test_approval_gate_runtime_mcp_remembered_inline_allow_queues_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=store.guard_home,
    )
    artifact = GuardArtifact(
        artifact_id="codex:mcp:dangerous-tool",
        name="dangerous-tool",
        harness="codex",
        artifact_type="tool_call",
        source_scope="project",
        config_path="/repo/.mcp.json",
        metadata={"tool_name": "dangerous-tool"},
    )
    proxy = RuntimeMcpGuardProxy(
        harness="codex",
        server_name="danger-server",
        command=["node", "server.js"],
        context=context,
        store=store,
        config=load_guard_config(store.guard_home),
        source_scope="project",
        config_path="/repo/.mcp.json",
    )
    opened_urls: list[str] = []
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:5474")
    monkeypatch.setattr(runtime_mcp_module, "load_guard_daemon_auth_token", lambda _guard_home: "secret-token")
    monkeypatch.setattr(runtime_mcp_module, "open_browser_url", lambda url: opened_urls.append(url) or True)

    response, event = proxy._allow_and_forward(
        message={"id": 1},
        child_stdin=io.StringIO(),
        child_stdout=io.StringIO(),
        client_input=None,
        server_output=None,
        artifact=artifact,
        artifact_hash="hash-mcp",
        decision_source="inline-approved",
        signals=("mcp_dangerous_tool",),
        risk_categories=("mcp",),
        params={"name": "dangerous-tool", "arguments": {"path": ".env"}},
        remember=True,
    )

    assert event["decision"] == "queue-approval"
    assert response["error"]["message"].startswith("HOL Guard stopped tool call dangerous-tool")
    assert response["error"]["data"]["reviewUrl"].startswith("http://127.0.0.1:5474/requests/")
    assert response["error"]["data"]["reviewUrl"] in response["error"]["message"]
    assert opened_urls == []
    assert len(store.list_approval_requests(limit=10)) == 1
    assert store.list_policy_decisions("codex") == []


def test_approval_gate_native_permission_persistence_cannot_bypass(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)

    saved = _persist_claude_native_permission_policy(
        store=store,
        artifact_id="claude:project:tool",
        artifact_hash="hash-native",
        action="allow",
        reason="native approval",
        now="2026-04-11T00:00:00+00:00",
    )

    assert saved is False
    assert store.list_policy_decisions("claude-code") == []


def test_approval_gate_native_permission_failure_queues_guard_fallback(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    artifact = GuardArtifact(
        artifact_id="claude-code:runtime:bash:dangerous",
        name="Bash",
        harness="claude-code",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/repo/.claude/settings.json",
        command="echo MALICIOUS > marker",
    )

    saved = _persist_claude_native_permission_policy(
        store=store,
        artifact_id=artifact.artifact_id,
        artifact_hash="hash-native",
        action="allow",
        reason="native approval",
        now="2026-04-11T00:00:00+00:00",
    )
    queued = _queue_claude_native_approval_gate_fallback(
        store=store,
        harness="claude-code",
        artifact=artifact,
        artifact_digest="hash-native",
        approval_center_url="http://127.0.0.1:5474",
    )

    pending = store.list_approval_requests(limit=10)
    assert saved is False
    assert len(queued) == 1
    assert len(pending) == 1
    assert pending[0]["policy_action"] == "require-reapproval"
    assert pending[0]["approval_url"].startswith("http://127.0.0.1:5474/requests/")
    assert "approval_gate_required" in pending[0]["risk_signals"]
    assert store.list_policy_decisions("claude-code") == []
