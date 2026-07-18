"""Terminal saved-block regressions for the runtime MCP proxy."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import sqlite3
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approval_scope_support import package_request_runtime_workspace_scope
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.local_supply_chain import package_request_policy_hash
from codex_plugin_scanner.guard.mcp_tool_calls import (
    ToolCallDecision,
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
)
from codex_plugin_scanner.guard.models import GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.package_execution_context import build_package_execution_context
from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy, OpenCodeMcpGuardProxy
from codex_plugin_scanner.guard.proxy import runtime_mcp as runtime_mcp_module
from codex_plugin_scanner.guard.runtime.package_intent import (
    build_package_request_artifact,
    extract_package_intent_request,
)
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore

pytest_plugins = ["tests.bundle_first_cloud"]
pytestmark = pytest.mark.usefixtures("bundle_first_cloud")


def _context(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir()
    workspace_dir.mkdir()
    guard_home.mkdir()
    return HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)


def _child_command(marker_path: Path) -> list[str]:
    return [
        sys.executable,
        "-u",
        "-c",
        "\n".join(
            (
                "import json",
                "import sys",
                "from pathlib import Path",
                f"marker_path = Path({str(marker_path)!r})",
                "for line in sys.stdin:",
                "    message = json.loads(line)",
                "    message_id = message.get('id')",
                "    method = message.get('method')",
                "    if method == 'initialize':",
                "        result = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}}, "
                "                  'serverInfo': {'name': 'fixture', 'version': '1.0.0'}}",
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': result}), flush=True)",
                "        continue",
                "    if method == 'tools/list':",
                "        tools = [",
                "            {'name': 'dangerous_delete', 'description': 'Dangerous delete', "
                "             'inputSchema': {'type': 'object', 'properties': {'target': {'type': 'string'}}}},",
                "            {'name': 'run_terminal_command', 'description': 'Run a terminal command.', "
                "             'inputSchema': {'type': 'object', 'properties': {'command': {'type': 'string'}}}},",
                "            {'name': 'safe_echo', 'description': 'Safe echo', "
                "             'inputSchema': {'type': 'object', 'properties': {}}},",
                "        ]",
                "        response = {'jsonrpc': '2.0', 'id': message_id, 'result': {'tools': tools}}",
                "        print(json.dumps(response), flush=True)",
                "        continue",
                "    if method == 'tools/call':",
                "        marker_path.write_text(json.dumps(message.get('params', {})), encoding='utf-8')",
                "        result = {'content': [{'type': 'text', 'text': 'forwarded'}]}",
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': result}), flush=True)",
                "        continue",
                "    print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': {}}), flush=True)",
            )
        ),
    ]


def _idle_catalog_invalidation_child_command(
    marker_path: Path,
    session_counter_path: Path,
) -> list[str]:
    return [
        sys.executable,
        "-u",
        "-c",
        "\n".join(
            (
                "import json",
                "import sys",
                "from pathlib import Path",
                f"marker_path = Path({str(marker_path)!r})",
                f"counter_path = Path({str(session_counter_path)!r})",
                "session = int(counter_path.read_text(encoding='utf-8')) + 1 if counter_path.exists() else 1",
                "counter_path.write_text(str(session), encoding='utf-8')",
                "for line in sys.stdin:",
                "    message = json.loads(line)",
                "    message_id = message.get('id')",
                "    method = message.get('method')",
                "    if method == 'initialize':",
                "        result = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}}, "
                "                  'serverInfo': {'name': 'idle-invalidator', 'version': '1.0.0'}}",
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': result}), flush=True)",
                "        continue",
                "    if method == 'tools/list':",
                "        tools = [",
                "            {'name': 'dangerous_delete', 'description': 'Dangerous delete', "
                "             'inputSchema': {'type': 'object', 'properties': {'target': {'type': 'string'}}}},",
                "        ]",
                "        response = {'jsonrpc': '2.0', 'id': message_id, 'result': {'tools': tools}}",
                "        print(json.dumps(response), flush=True)",
                "        if session == 2:",
                "            print(json.dumps({'jsonrpc': '2.0', "
                "                              'method': 'notifications/tools/list_changed', 'params': {}}), "
                "                  flush=True)",
                "        continue",
                "    if method == 'tools/call':",
                "        marker_path.write_text(json.dumps(message.get('params', {})), encoding='utf-8')",
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, "
                "                          'result': {'content': [{'type': 'text', 'text': 'forwarded'}]}}), "
                "              flush=True)",
                "        continue",
                "    print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': {}}), flush=True)",
            )
        ),
    ]


def _cross_session_buffer_child_command(session_counter_path: Path) -> list[str]:
    return [
        sys.executable,
        "-u",
        "-c",
        "\n".join(
            (
                "import json",
                "import sys",
                "from pathlib import Path",
                f"counter_path = Path({str(session_counter_path)!r})",
                "session = int(counter_path.read_text(encoding='utf-8')) + 1 if counter_path.exists() else 1",
                "counter_path.write_text(str(session), encoding='utf-8')",
                "for line in sys.stdin:",
                "    message = json.loads(line)",
                "    message_id = message.get('id')",
                "    method = message.get('method')",
                "    if method == 'initialize':",
                "        if session == 1:",
                "            stale = {'tools': [{'name': 'stale_session_tool', 'description': 'stale', "
                "                                  'inputSchema': {'type': 'object', 'properties': {}}}]} ",
                "            print(json.dumps({'jsonrpc': '2.0', 'id': 2, 'result': stale}), flush=True)",
                "        result = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}}, "
                "                  'serverInfo': {'name': 'buffer-reset', 'version': '1.0.0'}}",
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': result}), flush=True)",
                "        continue",
                "    if method == 'tools/list':",
                "        current = {'tools': [{'name': 'current_session_tool', 'description': 'current', "
                "                                'inputSchema': {'type': 'object', 'properties': {}}}]} ",
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': current}), flush=True)",
                "        continue",
                "    print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': {}}), flush=True)",
            )
        ),
    ]


def _child_tool_catalog_fingerprint() -> str:
    return runtime_mcp_module._tool_catalog_fingerprint(
        {
            "dangerous_delete": {
                "description": "Dangerous delete",
                "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}},
            },
            "run_terminal_command": {
                "description": "Run a terminal command.",
                "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}},
            },
            "safe_echo": {
                "description": "Safe echo",
                "input_schema": {"type": "object", "properties": {}},
            },
        }
    )


def _messages(*, tool_name: str, arguments: dict[str, object], elicitation: bool) -> list[dict[str, Any]]:
    capabilities = {"elicitation": {}} if elicitation else {}
    return [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": capabilities}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        },
    ]


def _assert_terminal_block(
    *,
    result: dict[str, Any],
    store: GuardStore,
    marker_path: Path,
    artifact_id: str,
    event_decision: str,
) -> None:
    assert marker_path.exists() is False
    response = result["responses"][2]
    assert response["error"]["code"] == -32001
    assert response["error"]["data"]["guardPolicyAction"] == "block"
    assert response["error"]["data"]["approvalRequests"] == []
    assert result["events"][2]["decision"] == event_decision
    assert result["events"][2]["policy_action"] == "block"
    assert result["events"][2]["approval_requests"] == []
    assert store.list_approval_requests(limit=10) == []
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["artifact_id"] == artifact_id
    assert receipt["policy_decision"] == "block"
    event = store.list_events(limit=1, event_name="runtime_tool_call_blocked")[0]
    event_payload = event["payload"]
    assert isinstance(event_payload, dict)
    assert event_payload["artifact_id"] == artifact_id
    assert event_payload["decision_source"] == "policy-block"


def _forbidden_daemon(_guard_home: Path) -> str:
    raise AssertionError("a terminal saved block must not start or queue through the approval center")


def _forbidden_inline(_request: dict[str, object]) -> dict[str, object]:
    raise AssertionError("a terminal saved block must not invoke inline approval")


def _seed_exact_tool_block(
    *,
    proxy: CodexMcpGuardProxy,
    store: GuardStore,
    config: GuardConfig,
    arguments: dict[str, object],
) -> str:
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="workspace-tools",
        tool_name="dangerous_delete",
        source_scope="project",
        config_path=proxy.config_path,
        transport="stdio",
        server_fingerprint={
            "command": proxy.command,
            "transport": "stdio",
            "resolved_executable": runtime_mcp_module._resolved_executable_identity(
                proxy.command[0],
                launch_cwd=proxy.context.workspace_dir,
                launch_args=proxy.command[1:],
            ),
            "tool_catalog_fingerprint": _child_tool_catalog_fingerprint(),
        },
        server_identity=proxy.server_identity,
        tool_schema={"type": "object", "properties": {"target": {"type": "string"}}},
        tool_description="Dangerous delete",
    )
    digest = build_tool_call_hash(
        artifact,
        arguments,
        workspace=proxy.context.workspace_dir,
        config=config,
    )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="block",
            artifact_id=artifact.artifact_id,
            artifact_hash=digest,
            reason="operator blocked exact call",
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )
    return artifact.artifact_id


def _package_artifact(*, context: HarnessContext, harness: str, config_path: str) -> GuardArtifact:
    intent = extract_package_intent_request(
        "run_terminal_command",
        {"command": "npm install minimist@1.2.8"},
        action_envelope_command="npm install minimist@1.2.8",
        workspace=context.workspace_dir,
    )
    assert intent is not None
    return build_package_request_artifact(
        harness=harness,
        intent=intent,
        config_path=config_path,
        source_scope="project",
    )


def _seed_exact_package_block(
    *,
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
    artifact: GuardArtifact,
) -> str:
    assert context.workspace_dir is not None
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
        config=config,
    )
    policy_workspace = package_request_runtime_workspace_scope(
        artifact_id=artifact.artifact_id,
        artifact_hash=digest,
        artifact_type=artifact.artifact_type,
        execution_context=execution_context,
    )
    store.upsert_policy(
        PolicyDecision(
            harness=artifact.harness,
            scope="artifact",
            action="block",
            artifact_id=artifact.artifact_id,
            artifact_hash=digest,
            workspace=policy_workspace,
            publisher=artifact.publisher,
            reason="operator blocked exact package request",
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )
    return artifact.artifact_id


def test_nonpackage_authenticated_saved_block_is_terminal_before_inline_observe_and_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir, mode="observe")
    marker_path = tmp_path / "nonpackage-forwarded.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    arguments: dict[str, object] = {"target": ".env"}
    artifact_id = _seed_exact_tool_block(
        proxy=proxy,
        store=store,
        config=config,
        arguments=arguments,
    )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", _forbidden_daemon)

    result = proxy.run_session(
        _messages(tool_name="dangerous_delete", arguments=arguments, elicitation=True),
        inline_approval_callback=_forbidden_inline,
    )

    _assert_terminal_block(
        result=result,
        store=store,
        marker_path=marker_path,
        artifact_id=artifact_id,
        event_decision="block-stored-policy",
    )


@pytest.mark.parametrize("approval_surface", ["inline", "native"])
def test_package_preliminary_saved_tool_block_is_terminal_before_package_or_approval_surfaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    approval_surface: str,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir, mode="observe")
    marker_path = tmp_path / f"package-preliminary-{approval_surface}.json"
    proxy_class = CodexMcpGuardProxy if approval_surface == "inline" else OpenCodeMcpGuardProxy
    proxy = proxy_class(
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / f".{approval_surface}" / "mcp.json"),
    )
    artifact_id = "codex:runtime:project:workspace-tools:run_terminal_command"
    if approval_surface == "native":
        artifact_id = "opencode:runtime:project:workspace-tools:run_terminal_command"
        monkeypatch.setattr(
            proxy,
            "_allow_after_native_prompt",
            lambda _decision: pytest.fail("a terminal saved block must not invoke native approval"),
        )
    monkeypatch.setattr(
        runtime_mcp_module,
        "evaluate_tool_call",
        lambda **_kwargs: ToolCallDecision(
            action="block",
            source="policy",
            signals=("command execution",),
            summary="blocked by authenticated saved policy",
            risk_categories=("command_execution",),
            approval_reuse_status="rejected",
            approval_reuse_reason_code="approval_reuse_saved_block",
            current_action="review",
            saved_action="block",
        ),
    )
    monkeypatch.setattr(
        runtime_mcp_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: pytest.fail("the package phase must not run after a preliminary saved block"),
    )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", _forbidden_daemon)

    result = proxy.run_session(
        _messages(
            tool_name="run_terminal_command",
            arguments={"command": "npm install minimist@1.2.8"},
            elicitation=approval_surface == "inline",
        ),
        inline_approval_callback=_forbidden_inline if approval_surface == "inline" else None,
    )

    _assert_terminal_block(
        result=result,
        store=store,
        marker_path=marker_path,
        artifact_id=artifact_id,
        event_decision="block-stored-policy",
    )


@pytest.mark.parametrize("approval_surface", ["inline", "native"])
def test_authenticated_saved_package_block_is_terminal_before_generic_approval_and_observe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    approval_surface: str,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir, mode="observe")
    marker_path = tmp_path / f"package-final-{approval_surface}.json"
    harness = "codex" if approval_surface == "inline" else "opencode"
    config_path = str(context.workspace_dir / f".{harness}" / "mcp.json")
    artifact = _package_artifact(context=context, harness=harness, config_path=config_path)
    artifact_id = _seed_exact_package_block(
        context=context,
        store=store,
        config=config,
        artifact=artifact,
    )
    proxy_class = CodexMcpGuardProxy if approval_surface == "inline" else OpenCodeMcpGuardProxy
    proxy = proxy_class(
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=config_path,
        current_config_provider=lambda: config,
    )
    monkeypatch.setattr(
        runtime_mcp_module,
        "evaluate_tool_call",
        lambda **_kwargs: ToolCallDecision(
            action="review",
            source="risk-policy",
            signals=("command execution",),
            summary="generic tool review",
            risk_categories=("command_execution",),
        ),
    )
    if approval_surface == "native":
        monkeypatch.setattr(
            proxy,
            "_allow_after_native_prompt",
            lambda _decision: pytest.fail("a terminal package block must not invoke native approval"),
        )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", _forbidden_daemon)

    result = proxy.run_session(
        _messages(
            tool_name="run_terminal_command",
            arguments={"command": "npm install minimist@1.2.8"},
            elicitation=approval_surface == "inline",
        ),
        inline_approval_callback=_forbidden_inline if approval_surface == "inline" else None,
    )

    _assert_terminal_block(
        result=result,
        store=store,
        marker_path=marker_path,
        artifact_id=artifact_id,
        event_decision="package-block-stored",
    )


def test_package_retry_claims_inner_and_outer_exact_one_shot_allows_after_revision_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    store = GuardStore(context.guard_home)
    config = GuardConfig(
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        security_level="custom",
        risk_actions={
            "mcp_dangerous_tool": "review",
            "package_script": "review",
        },
    )
    marker_path = tmp_path / "paired-one-shot-forwarded.json"
    config_path = str(context.workspace_dir / ".codex" / "config.toml")
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=config_path,
        current_config_provider=lambda: config,
    )
    arguments: dict[str, object] = {"command": "npm install minimist@1.2.8"}
    package_artifact = _package_artifact(context=context, harness="codex", config_path=config_path)
    package_evaluation = replace(
        evaluate_package_request_artifact(
            artifact=package_artifact,
            store=store,
            workspace_dir=context.workspace_dir,
        ),
        decision="allow",
        policy_action="allow",
    )
    monkeypatch.setattr(
        runtime_mcp_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: package_evaluation,
    )
    package_context = build_package_execution_context(
        workspace_dir=context.workspace_dir,
        artifact=package_artifact,
    )
    package_digest = package_request_policy_hash(
        artifact=package_artifact,
        store=store,
        workspace_dir=context.workspace_dir,
        evaluation=package_evaluation,
        execution_context=package_context,
        config=config,
    )
    package_workspace = package_request_runtime_workspace_scope(
        artifact_id=package_artifact.artifact_id,
        artifact_hash=package_digest,
        artifact_type=package_artifact.artifact_type,
        execution_context=package_context,
    )
    tool_artifact = build_tool_call_artifact(
        harness="codex",
        server_name="workspace-tools",
        tool_name="run_terminal_command",
        source_scope="project",
        config_path=config_path,
        transport="stdio",
        server_fingerprint={
            "command": proxy.command,
            "transport": "stdio",
            "resolved_executable": runtime_mcp_module._resolved_executable_identity(
                proxy.command[0],
                launch_cwd=context.workspace_dir,
                launch_args=proxy.command[1:],
            ),
            "tool_catalog_fingerprint": _child_tool_catalog_fingerprint(),
        },
        server_identity=proxy.server_identity,
        tool_schema={"type": "object", "properties": {"command": {"type": "string"}}},
        tool_description="Run a terminal command.",
    )
    tool_digest = build_tool_call_hash(
        tool_artifact,
        arguments,
        workspace=context.workspace_dir,
        config=config,
    )
    created_at = "2026-07-17T00:00:00+00:00"
    expires_at = "2027-07-17T00:00:00+00:00"
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=tool_artifact.artifact_id,
            artifact_hash=tool_digest,
            workspace=str(context.workspace_dir),
            publisher=tool_artifact.publisher,
            reason="outer exact tool review",
            source="approval-gate",
            expires_at=expires_at,
        ),
        created_at,
    )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=package_artifact.artifact_id,
            artifact_hash=package_digest,
            workspace=package_workspace,
            publisher=package_artifact.publisher,
            reason="inner exact package review",
            source="approval-gate",
            expires_at=expires_at,
        ),
        created_at,
    )
    with store._connect() as connection:
        one_shot_rows = connection.execute(
            "select decision_id from policy_decisions where source = 'approval-gate'",
        ).fetchall()
    one_shot_ids = {int(row["decision_id"]) for row in one_shot_rows}
    assert len(one_shot_ids) == 2
    real_package_lookup = store.resolve_policy_decision_lookup
    package_lookup_calls = 0
    selected_package_decision: dict[str, object] | None = None

    def resolve_package_decision_before_revocation(*args: Any, **kwargs: Any) -> Any:
        nonlocal package_lookup_calls, selected_package_decision
        package_lookup_calls += 1
        if package_lookup_calls > 1:
            # Model the selected row being revoked between evaluation and a
            # second attempt to reconstruct the deferred claim.
            return {
                "decision": None,
                "ignored_local_integrity": None,
                "trust_status": {},
                "authority_revision": -1,
            }
        lookup = real_package_lookup(*args, **kwargs)
        decision = lookup["decision"]
        assert isinstance(decision, dict)
        selected_package_decision = decision
        return lookup

    with monkeypatch.context() as lookup_patch:
        lookup_patch.setattr(store, "resolve_policy_decision_lookup", resolve_package_decision_before_revocation)
        package_preflight = proxy._resolve_package_policy(artifact=package_artifact)
    assert package_preflight.artifact_digest == package_digest
    assert any(reason.get("code") == "saved_package_approval" for reason in package_preflight.evaluation.reasons)
    assert package_lookup_calls == 1
    assert package_preflight.pending_approval_reuse_decision is selected_package_decision

    result = proxy.run_session(
        _messages(
            tool_name="run_terminal_command",
            arguments=arguments,
            elicitation=False,
        )
    )

    assert marker_path.exists() is True
    assert result["responses"][2]["result"]["content"][0]["text"] == "forwarded"
    assert result["events"][2]["decision"] == "package-allow"
    assert store.list_approval_requests(limit=10) == []
    applied_events = store.list_events(limit=10, event_name="approval.policy_reuse_applied")
    applied_ids = {
        payload["decision_id"] for event in applied_events if isinstance((payload := event["payload"]), dict)
    }
    assert applied_ids == one_shot_ids
    with store._connect() as connection:
        remaining_rows = connection.execute(
            "select decision_id from policy_decisions where source = 'approval-gate'",
        ).fetchall()
    assert remaining_rows == []


@pytest.mark.parametrize(
    (
        "postclaim_digest",
        "claim_disposition",
        "postclaim_reselects_claimed_row",
        "expected_forward",
        "expected_context_matches",
    ),
    (
        ("guard-approval-context:v1:changed-package", "consumed", False, False, False),
        ("guard-approval-context:v1:preclaim-package", "retained", False, False, True),
        ("guard-approval-context:v1:preclaim-package", "retained", True, True, True),
    ),
)
def test_package_retry_validates_context_and_retained_authority_before_forward(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    postclaim_digest: str,
    claim_disposition: Literal["consumed", "retained"],
    postclaim_reselects_claimed_row: bool,
    expected_forward: bool,
    expected_context_matches: bool,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    store = GuardStore(context.guard_home)
    config = GuardConfig(
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        security_level="custom",
        risk_actions={"package_script": "review"},
    )
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(tmp_path / "package-postclaim-must-not-forward.json"),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
        current_config_provider=lambda: config,
    )
    arguments: dict[str, object] = {"command": "npm install minimist@1.2.8"}
    package_artifact = _package_artifact(
        context=context,
        harness="codex",
        config_path=proxy.config_path,
    )
    base_evaluation = evaluate_package_request_artifact(
        artifact=package_artifact,
        store=store,
        workspace_dir=context.workspace_dir,
    )
    allowed_evaluation = replace(
        base_evaluation,
        decision="allow",
        policy_action="allow",
    )
    changed_evaluation = replace(
        base_evaluation,
        decision="review",
        policy_action="review",
    )
    execution_context = build_package_execution_context(
        workspace_dir=context.workspace_dir,
        artifact=package_artifact,
    )
    pending_package_allow = {"action": "allow", "decision_id": 901}
    preclaim_resolution = runtime_mcp_module._PackagePolicyResolution(
        base_evaluation=base_evaluation,
        evaluation=allowed_evaluation,
        current_action="review",
        workspace=context.workspace_dir,
        execution_context=execution_context,
        artifact_digest="guard-approval-context:v1:preclaim-package",
        policy_workspace=str(context.workspace_dir),
        saved_policy_blocks=False,
        pending_approval_reuse_decision=pending_package_allow,
        approval_reuse_claim_disposition=claim_disposition,
    )
    postclaim_resolution = runtime_mcp_module._PackagePolicyResolution(
        base_evaluation=base_evaluation,
        evaluation=changed_evaluation,
        current_action="review",
        workspace=context.workspace_dir,
        execution_context=execution_context,
        artifact_digest=postclaim_digest,
        policy_workspace=str(context.workspace_dir),
        saved_policy_blocks=False,
        pending_approval_reuse_decision=(pending_package_allow if postclaim_reselects_claimed_row else None),
        approval_reuse_claim_disposition=(claim_disposition if postclaim_reselects_claimed_row else None),
    )
    tool_artifact = build_tool_call_artifact(
        harness="codex",
        server_name="workspace-tools",
        tool_name="run_terminal_command",
        source_scope="project",
        config_path=proxy.config_path,
        transport="stdio",
    )
    tool_decision = ToolCallDecision(
        action="allow",
        source="policy",
        signals=(),
        summary="current tool authority allows",
        current_action="allow",
    )
    catalog_fingerprint = runtime_mcp_module._tool_catalog_fingerprint(
        proxy._tool_catalog,
        state=proxy._tool_catalog_state,
    )
    tool_authority = runtime_mcp_module._ToolCallAuthority(
        artifact=tool_artifact,
        artifact_hash="guard-approval-context:v1:tool",
        decision=tool_decision,
        catalog_generation=proxy._tool_catalog_generation,
        catalog_state=proxy._tool_catalog_state,
        catalog_fingerprint=catalog_fingerprint,
    )
    claim_completed = False

    def resolve_package_policy(*, artifact: GuardArtifact) -> object:
        assert artifact.artifact_id == package_artifact.artifact_id
        return postclaim_resolution if claim_completed else preclaim_resolution

    def claim_and_change_context(
        decisions: tuple[dict[str, object], ...],
        **_kwargs: object,
    ) -> bool:
        nonlocal claim_completed
        assert decisions == (pending_package_allow,)
        claim_completed = True
        return True

    queued: dict[str, object] = {}

    def capture_package_queue(**kwargs: object) -> tuple[dict[str, Any], dict[str, Any]]:
        queued.update(kwargs)
        return (
            {"jsonrpc": "2.0", "id": 3, "error": {"code": -32001}},
            {"decision": "queue-package-approval"},
        )

    forwarded: dict[str, object] = {}

    def capture_package_forward(**kwargs: object) -> tuple[dict[str, Any], dict[str, Any]]:
        forwarded.update(kwargs)
        return (
            {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "forwarded"}]}},
            {"decision": "forward-package"},
        )

    monkeypatch.setattr(runtime_mcp_module, "evaluate_tool_call", lambda **_kwargs: tool_decision)
    monkeypatch.setattr(proxy, "_resolve_package_policy", resolve_package_policy)
    monkeypatch.setattr(proxy, "_resolve_tool_call_authority", lambda **_kwargs: tool_authority)
    monkeypatch.setattr(store, "claim_approval_reuse_decisions", claim_and_change_context)
    monkeypatch.setattr(proxy, "_queue_package_approval_response", capture_package_queue)
    monkeypatch.setattr(proxy, "_record_package_forward", capture_package_forward)

    response, event = proxy._handle_package_request(
        message={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "run_terminal_command", "arguments": arguments},
        },
        child_stdin=io.StringIO(),
        child_stdout=io.StringIO(),
        client_input=None,
        server_output=None,
        tool_name="run_terminal_command",
        params={"name": "run_terminal_command", "arguments": arguments},
        artifact=package_artifact,
        tool_artifact=tool_artifact,
        tool_artifact_hash=tool_authority.artifact_hash,
        tool_decision=tool_decision,
        tool_scanner_evidence=(),
        package_resolution=preclaim_resolution,
        expected_catalog_generation=proxy._tool_catalog_generation,
        expected_catalog_state=proxy._tool_catalog_state,
        expected_catalog_fingerprint=catalog_fingerprint,
    )

    assert claim_completed is True
    if expected_forward:
        assert response["result"]["content"][0]["text"] == "forwarded"
        assert event["decision"] == "forward-package"
        assert queued == {}
        assert forwarded["policy_action"] == "allow"
        return
    assert response["error"]["code"] == -32001
    assert event["decision"] == "queue-package-approval"
    assert queued["artifact_hash"] == postclaim_resolution.artifact_digest
    assert queued["policy_action"] == "require-reapproval"
    scanner_evidence = queued["scanner_evidence"]
    assert isinstance(scanner_evidence, tuple)
    assert scanner_evidence[-1]["source"] == "approval_reuse"
    assert scanner_evidence[-1]["status"] == "rejected"
    assert scanner_evidence[-1]["reason_code"] == "approval_reuse_context_changed_after_claim"
    assert scanner_evidence[-1]["context_matches"] is expected_context_matches
    assert scanner_evidence[-1]["current_action"] == "review"
    if claim_disposition == "retained":
        assert scanner_evidence[-1]["claimed_authority_matches"] is False
        assert scanner_evidence[-1]["effective_action"] == "require-reapproval"
    else:
        assert scanner_evidence[-1]["effective_action"] == "review"


def test_mcp_executable_identity_uses_launch_cwd_and_stays_pinned_after_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    process_cwd = tmp_path / "guard-process-cwd"
    process_cwd.mkdir()
    workspace_server = context.workspace_dir / "fixture-server"
    decoy_server = process_cwd / "fixture-server"
    replacement_source = f"#!{sys.executable}\nraise SystemExit(92)\n"
    server_source = "\n".join(
        (
            f"#!{sys.executable}",
            "import json",
            "import sys",
            "from pathlib import Path",
            f"replacement_source = {replacement_source!r}",
            "for line in sys.stdin:",
            "    message = json.loads(line)",
            "    method = message.get('method')",
            "    if method == 'initialize':",
            "        result = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}}, "
            "                  'serverInfo': {'name': 'relative', 'version': '1.0.0'}}",
            "        Path(__file__).write_text(replacement_source, encoding='utf-8')",
            "    elif method == 'tools/list':",
            "        result = {'tools': [{'name': 'safe_echo', 'description': 'Safe echo', "
            "                             'inputSchema': {'type': 'object', 'properties': {}}}]} ",
            "    else:",
            "        result = {'content': [{'type': 'text', 'text': 'workspace-server'}]}",
            "    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': result}), flush=True)",
        )
    )
    workspace_server.write_text(server_source, encoding="utf-8")
    workspace_server.chmod(0o755)
    launched_digest = hashlib.sha256(workspace_server.read_bytes()).hexdigest()
    decoy_server.write_text(f"#!{sys.executable}\nraise SystemExit(91)\n", encoding="utf-8")
    decoy_server.chmod(0o755)
    monkeypatch.chdir(process_cwd)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    captured: dict[str, object] = {}

    def _capture_tool_call(**kwargs: object) -> ToolCallDecision:
        captured["artifact"] = kwargs["artifact"]
        return ToolCallDecision(action="allow", source="heuristic", signals=(), summary="safe")

    monkeypatch.setattr(runtime_mcp_module, "evaluate_tool_call", _capture_tool_call)
    proxy = CodexMcpGuardProxy(
        server_name="relative-server",
        command=["./fixture-server"],
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
        current_config_provider=lambda: proxy.config,
    )

    result = proxy.run_session(_messages(tool_name="safe_echo", arguments={}, elicitation=False))

    assert result["responses"][2]["result"]["content"][0]["text"] == "workspace-server"
    captured_artifact = captured["artifact"]
    assert isinstance(captured_artifact, GuardArtifact)
    server_fingerprint = captured_artifact.metadata["server_fingerprint"]
    assert isinstance(server_fingerprint, dict)
    executable = server_fingerprint["resolved_executable"]
    assert isinstance(executable, dict)
    assert executable["path"] == str(workspace_server.resolve())
    assert executable["launch_cwd"] == str(context.workspace_dir.resolve())
    assert workspace_server.read_text(encoding="utf-8") == replacement_source
    assert executable["sha256"] == launched_digest
    assert executable["sha256"] != hashlib.sha256(workspace_server.read_bytes()).hexdigest()
    assert executable["sha256"] != hashlib.sha256(decoy_server.read_bytes()).hexdigest()


def test_interpreted_mcp_server_binds_script_bytes_and_pins_them_for_the_running_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    process_cwd = tmp_path / "guard-process-cwd"
    process_cwd.mkdir()
    server_script = context.workspace_dir / "server.py"
    replacement_source = "raise SystemExit(93)\n"
    server_source = "\n".join(
        (
            "import json",
            "import sys",
            "from pathlib import Path",
            f"replacement_source = {replacement_source!r}",
            "for line in sys.stdin:",
            "    message = json.loads(line)",
            "    method = message.get('method')",
            "    if method == 'initialize':",
            "        result = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}}, "
            "                  'serverInfo': {'name': 'interpreted', 'version': '1.0.0'}}",
            "        Path(__file__).write_text(replacement_source, encoding='utf-8')",
            "    elif method == 'tools/list':",
            "        result = {'tools': [{'name': 'safe_echo', 'description': 'Safe echo', "
            "                             'inputSchema': {'type': 'object', 'properties': {}}}]} ",
            "    else:",
            "        result = {'content': [{'type': 'text', 'text': 'interpreted-server'}]}",
            "    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': result}), flush=True)",
        )
    )
    server_script.write_text(server_source, encoding="utf-8")
    original_digest = hashlib.sha256(server_script.read_bytes()).hexdigest()
    launch_args = ("-u", "server.py")
    first_identity = runtime_mcp_module._resolved_executable_identity(
        sys.executable,
        launch_cwd=context.workspace_dir,
        launch_args=launch_args,
    )
    unchanged_identity = runtime_mcp_module._resolved_executable_identity(
        sys.executable,
        launch_cwd=context.workspace_dir,
        launch_args=launch_args,
    )
    assert first_identity == unchanged_identity
    first_entrypoint = first_identity["entrypoint"]
    assert isinstance(first_entrypoint, dict)
    assert first_entrypoint["sha256"] == original_digest
    server_script.write_text("raise SystemExit(94)\n", encoding="utf-8")
    replaced_identity = runtime_mcp_module._resolved_executable_identity(
        sys.executable,
        launch_cwd=context.workspace_dir,
        launch_args=launch_args,
    )
    replaced_entrypoint = replaced_identity["entrypoint"]
    assert isinstance(replaced_entrypoint, dict)
    assert replaced_entrypoint["sha256"] != first_entrypoint["sha256"]
    server_script.write_text(server_source, encoding="utf-8")
    monkeypatch.chdir(process_cwd)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    captured: dict[str, object] = {}

    def _capture_tool_call(**kwargs: object) -> ToolCallDecision:
        captured["artifact"] = kwargs["artifact"]
        return ToolCallDecision(action="allow", source="heuristic", signals=(), summary="safe")

    monkeypatch.setattr(runtime_mcp_module, "evaluate_tool_call", _capture_tool_call)
    proxy = CodexMcpGuardProxy(
        server_name="interpreted-server",
        command=[sys.executable, *launch_args],
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
        current_config_provider=lambda: config,
    )

    result = proxy.run_session(_messages(tool_name="safe_echo", arguments={}, elicitation=False))

    assert result["responses"][2]["result"]["content"][0]["text"] == "interpreted-server"
    captured_artifact = captured["artifact"]
    assert isinstance(captured_artifact, GuardArtifact)
    server_fingerprint = captured_artifact.metadata["server_fingerprint"]
    assert isinstance(server_fingerprint, dict)
    launch_identity = server_fingerprint["resolved_executable"]
    assert isinstance(launch_identity, dict)
    entrypoint = launch_identity["entrypoint"]
    assert isinstance(entrypoint, dict)
    assert entrypoint["kind"] == "python-script"
    assert entrypoint["path"] == str(server_script.resolve())
    assert entrypoint["sha256"] == original_digest
    assert server_script.read_text(encoding="utf-8") == replacement_source
    assert entrypoint["sha256"] != hashlib.sha256(server_script.read_bytes()).hexdigest()


def test_python_module_entrypoint_is_content_bound_and_unresolved_package_launcher_disables_reuse(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    package_dir = workspace / "guard_server"
    package_dir.mkdir(parents=True)
    module_main = package_dir / "__main__.py"
    module_main.write_text("print('version-one')\n", encoding="utf-8")
    first_module_identity = runtime_mcp_module._resolved_executable_identity(
        sys.executable,
        launch_cwd=workspace,
        launch_args=("-m", "guard_server"),
    )
    first_entrypoint = first_module_identity["entrypoint"]
    assert isinstance(first_entrypoint, dict)
    assert first_entrypoint["kind"] == "python-package-main"
    assert first_entrypoint["path"] == str(module_main.resolve())
    module_main.write_text("print('version-two')\n", encoding="utf-8")
    changed_module_identity = runtime_mcp_module._resolved_executable_identity(
        sys.executable,
        launch_cwd=workspace,
        launch_args=("-m", "guard_server"),
    )
    changed_entrypoint = changed_module_identity["entrypoint"]
    assert isinstance(changed_entrypoint, dict)
    assert changed_entrypoint["sha256"] != first_entrypoint["sha256"]

    first_launcher_identity = runtime_mcp_module._resolved_executable_identity(
        "npx",
        launch_cwd=workspace,
        launch_args=("-y", "@modelcontextprotocol/server-filesystem"),
    )
    second_launcher_identity = runtime_mcp_module._resolved_executable_identity(
        "npx",
        launch_cwd=workspace,
        launch_args=("-y", "@modelcontextprotocol/server-filesystem"),
    )
    first_launcher_entrypoint = first_launcher_identity["entrypoint"]
    second_launcher_entrypoint = second_launcher_identity["entrypoint"]
    assert isinstance(first_launcher_entrypoint, dict)
    assert isinstance(second_launcher_entrypoint, dict)
    assert first_launcher_entrypoint["status"] == "unproven"
    assert first_launcher_entrypoint["reason"] == "launcher_entrypoint_unresolved"
    assert first_launcher_entrypoint["reuse_nonce"] != second_launcher_entrypoint["reuse_nonce"]


def test_runtime_mcp_binds_only_configured_server_env_values_without_leaking_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    store = GuardStore(context.guard_home)
    config = GuardConfig(
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        security_level="custom",
        risk_actions={"mcp_dangerous_tool": "review"},
    )
    marker_path = tmp_path / "env-tool-call.json"

    def capture_artifact(*, configured_value: str, ambient_value: str) -> GuardArtifact:
        monkeypatch.setenv("MCP_CONFIGURED_TOKEN", configured_value)
        monkeypatch.setenv("UNRELATED_AMBIENT_VALUE", ambient_value)
        captured: dict[str, object] = {}

        def capture_tool_call(**kwargs: object) -> ToolCallDecision:
            captured["artifact"] = kwargs["artifact"]
            return ToolCallDecision(action="allow", source="heuristic", signals=(), summary="captured")

        monkeypatch.setattr(runtime_mcp_module, "evaluate_tool_call", capture_tool_call)
        proxy = CodexMcpGuardProxy(
            server_name="configured-env-server",
            command=_child_command(marker_path),
            context=context,
            store=store,
            config=config,
            source_scope="project",
            config_path=str(context.workspace_dir / ".codex" / "config.toml"),
            server_env_keys=("MCP_CONFIGURED_TOKEN",),
        )
        proxy.run_session(
            _messages(
                tool_name="dangerous_delete",
                arguments={"target": "marker.json"},
                elicitation=False,
            )
        )
        artifact = captured["artifact"]
        assert isinstance(artifact, GuardArtifact)
        return artifact

    secret_v1 = "runtime-mcp-secret-one"
    secret_v2 = "runtime-mcp-secret-two"
    first_artifact = capture_artifact(configured_value=secret_v1, ambient_value="ambient-one")
    ambient_changed_artifact = capture_artifact(configured_value=secret_v1, ambient_value="ambient-two")
    configured_changed_artifact = capture_artifact(configured_value=secret_v2, ambient_value="ambient-two")
    arguments = {"target": "marker.json"}
    first_hash = build_tool_call_hash(
        first_artifact,
        arguments,
        workspace=context.workspace_dir,
        config=config,
    )
    ambient_changed_hash = build_tool_call_hash(
        ambient_changed_artifact,
        arguments,
        workspace=context.workspace_dir,
        config=config,
    )
    configured_changed_hash = build_tool_call_hash(
        configured_changed_artifact,
        arguments,
        workspace=context.workspace_dir,
        config=config,
    )

    assert ambient_changed_hash == first_hash
    assert configured_changed_hash != first_hash
    serialized = json.dumps(configured_changed_artifact.metadata, sort_keys=True)
    assert secret_v1 not in serialized
    assert secret_v2 not in serialized
    assert "UNRELATED_AMBIENT_VALUE" not in serialized
    server_fingerprint = configured_changed_artifact.metadata["server_fingerprint"]
    assert isinstance(server_fingerprint, dict)
    assert len(str(server_fingerprint["configured_env_values_hash"])) == 64

    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=first_artifact.artifact_id,
            artifact_hash=first_hash,
            source="approval-gate",
        ),
        "2026-07-17T00:00:00+00:00",
    )
    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=configured_changed_artifact,
        artifact_hash=configured_changed_hash,
        arguments=arguments,
    )

    assert decision.action == "review"
    assert decision.approval_reuse_reason_code == "approval_reuse_capability_changed"


def test_runtime_mcp_start_passes_configured_code_loading_env_to_launch_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    node_command = shutil.which("node")
    if node_command is None:
        pytest.skip("node is required for the configured NODE_OPTIONS launch regression")
    (context.workspace_dir / "configured-preload.js").write_text("// configured preload\n", encoding="utf-8")
    (context.workspace_dir / "server.js").write_text("setInterval(() => {}, 1000);\n", encoding="utf-8")
    configured_value = "--require ./configured-preload.js"
    monkeypatch.setenv("NODE_OPTIONS", configured_value)
    proxy = CodexMcpGuardProxy(
        server_name="configured-code-loading-server",
        command=[node_command, "server.js"],
        context=context,
        store=GuardStore(context.guard_home),
        config=GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir),
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
        server_env_keys=("NODE_OPTIONS",),
    )

    process = proxy._start_process()
    try:
        launch_identity = proxy._active_executable_identity
        assert isinstance(launch_identity, dict)
        entrypoint = launch_identity["entrypoint"]
        assert isinstance(entrypoint, dict)
        assert entrypoint["status"] == "unproven"
        assert entrypoint["reason"] == "environment_options_unresolved"
        assert proxy._active_server_identity is not None
        assert proxy._active_server_env_values_hash == proxy._active_server_identity.env_values_hash
        serialized_identity = json.dumps(
            {
                "launch": launch_identity,
                "server_env_values_hash": proxy._active_server_env_values_hash,
            },
            sort_keys=True,
        )
        assert configured_value not in serialized_identity
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_policy_review_never_auto_forwards_and_all_surfaces_use_reapproval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    marker_path = tmp_path / "review-must-not-forward.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir),
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    monkeypatch.setattr(
        runtime_mcp_module,
        "evaluate_tool_call",
        lambda **_kwargs: ToolCallDecision(
            action="review",
            source="policy",
            signals=("current policy requires review",),
            summary="review required",
        ),
    )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(proxy, "_maybe_open_approval_center", lambda **_kwargs: None)

    result = proxy.run_session(_messages(tool_name="safe_echo", arguments={"value": "hello"}, elicitation=False))

    assert marker_path.exists() is False
    response = result["responses"][2]
    assert response["error"]["data"]["guardPolicyAction"] == "require-reapproval"
    event = result["events"][2]
    assert event["policy_action"] == "require-reapproval"
    request = store.list_approval_requests(limit=10)[0]
    assert request["policy_action"] == "require-reapproval"
    receipts = store.list_receipts(limit=10)
    assert len(receipts) == 1
    assert receipts[0]["policy_decision"] == "require-reapproval"


@pytest.mark.parametrize("terminal_action", ["block", "sandbox-required"])
def test_terminal_current_tool_action_is_not_downgraded_to_retryable_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_action: str,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    marker_path = tmp_path / f"terminal-{terminal_action}.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir),
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    monkeypatch.setattr(
        runtime_mcp_module,
        "evaluate_tool_call",
        lambda **_kwargs: ToolCallDecision(
            action=terminal_action,  # type: ignore[arg-type]
            source="policy",
            signals=("terminal current policy",),
            summary="terminal action",
        ),
    )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", _forbidden_daemon)

    result = proxy.run_session(_messages(tool_name="safe_echo", arguments={"value": "hello"}, elicitation=False))

    assert marker_path.exists() is False
    response = result["responses"][2]
    assert response["error"]["data"] == {
        "approvalRequests": [],
        "guardPolicyAction": terminal_action,
    }
    event = result["events"][2]
    assert event["policy_action"] == terminal_action
    assert event["approval_requests"] == []
    assert store.list_approval_requests(limit=10) == []
    receipts = store.list_receipts(limit=10)
    assert len(receipts) == 1
    assert receipts[0]["policy_decision"] == terminal_action


def test_runtime_mcp_redacts_secret_argument_fields_from_every_persisted_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    marker_path = tmp_path / "secret-arguments-must-not-forward.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir),
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    monkeypatch.setattr(
        runtime_mcp_module,
        "evaluate_tool_call",
        lambda **_kwargs: ToolCallDecision(
            action="review",
            source="policy",
            signals=("review secret-shaped request",),
            summary="review required",
        ),
    )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(proxy, "_maybe_open_approval_center", lambda **_kwargs: None)
    secrets = {
        "password": "password-value-unique",
        "credential": "credential-value-unique",
        "cookie": "cookie-value-unique",
        "apiKey": "api-key-value-unique",
        "token": "token-value-unique",
    }
    arguments: dict[str, object] = {
        "endpoint": "https://example.invalid/run?apiKey=query-api-key-unique&mode=safe",
        "nested": secrets,
        "visible": "keep-this-label",
    }

    result = proxy.run_session(_messages(tool_name="safe_echo", arguments=arguments, elicitation=False))

    persisted = {
        "result": result,
        "approval_requests": store.list_approval_requests(limit=10),
        "receipts": store.list_receipts(limit=10),
        "events": store.list_events(limit=20),
    }
    serialized = json.dumps(persisted, sort_keys=True, default=str)
    for secret in (*secrets.values(), "query-api-key-unique"):
        assert secret not in serialized
    assert "keep-this-label" in serialized
    assert "arguments-sha256:" in serialized
    assert len(store.list_receipts(limit=10)) == 1


def test_observe_mode_does_not_consume_exact_saved_tool_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    store = GuardStore(context.guard_home)
    config = GuardConfig(
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        mode="observe",
        security_level="custom",
        risk_actions={"mcp_dangerous_tool": "review"},
    )
    marker_path = tmp_path / "observe-forwarded.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    arguments: dict[str, object] = {"target": ".env"}
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="workspace-tools",
        tool_name="dangerous_delete",
        source_scope="project",
        config_path=proxy.config_path,
        transport="stdio",
        server_fingerprint={
            "command": proxy.command,
            "configured_env_values_hash": proxy._session_server_env_values_hash(),
            "transport": "stdio",
            "resolved_executable": runtime_mcp_module._resolved_executable_identity(
                proxy.command[0],
                launch_cwd=context.workspace_dir,
                launch_args=proxy.command[1:],
            ),
            "tool_catalog_fingerprint": _child_tool_catalog_fingerprint(),
        },
        server_identity=proxy.server_identity,
        tool_schema={"type": "object", "properties": {"target": {"type": "string"}}},
        tool_description="Dangerous delete",
    )
    artifact_hash = build_tool_call_hash(artifact, arguments, workspace=context.workspace_dir, config=config)
    approval_id = store.record_local_once_approval(
        request_id="observe-unused-approval",
        harness="codex",
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        workspace=str(context.workspace_dir),
        publisher=artifact.publisher,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2027-07-17T00:00:00+00:00",
    )
    assert approval_id is not None
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(proxy, "_maybe_open_approval_center", lambda **_kwargs: None)

    result = proxy.run_session(_messages(tool_name="dangerous_delete", arguments=arguments, elicitation=False))

    assert marker_path.exists()
    assert result["events"][2]["decision"] == "observe-tool-call"
    with sqlite3.connect(store.path) as connection:
        claimed_at = connection.execute(
            "select claimed_at from guard_local_once_approvals where approval_id = ?",
            (approval_id,),
        ).fetchone()[0]
    assert claimed_at is None
    assert store.list_events(event_name="approval.local_once_applied") == []


def test_observe_mode_reprobes_terminal_tool_policy_immediately_before_forward(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        mode="observe",
    )
    marker_path = tmp_path / "observe-terminal-reprobe-must-not-forward.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    decisions = iter(
        (
            ToolCallDecision(
                action="review",
                source="policy",
                signals=("initial review",),
                summary="initial review",
            ),
            ToolCallDecision(
                action="block",
                source="policy",
                signals=("terminal policy changed before launch",),
                summary="terminal block",
            ),
        )
    )
    monkeypatch.setattr(runtime_mcp_module, "evaluate_tool_call", lambda **_kwargs: next(decisions))
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", _forbidden_daemon)

    result = proxy.run_session(_messages(tool_name="safe_echo", arguments={"value": "hello"}, elicitation=False))

    assert marker_path.exists() is False
    response = result["responses"][2]
    assert response["error"]["data"] == {
        "approvalRequests": [],
        "guardPolicyAction": "block",
    }
    assert result["events"][2]["decision"] == "terminal-block"
    assert result["events"][2]["policy_action"] == "block"
    assert store.list_approval_requests(limit=10) == []
    receipts = store.list_receipts(limit=10)
    assert len(receipts) == 1
    assert receipts[0]["policy_decision"] == "block"


def test_runtime_mcp_rebuilds_tool_authority_after_exact_claim_before_forward(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    store = GuardStore(context.guard_home)
    review_config = GuardConfig(
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        security_level="custom",
        risk_actions={"mcp_dangerous_tool": "review"},
    )
    current_config = [review_config]
    marker_path = tmp_path / "postclaim-tool-must-not-forward.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=review_config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
        current_config_provider=lambda: current_config[0],
    )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(proxy, "_maybe_open_approval_center", lambda **_kwargs: None)
    messages = _messages(
        tool_name="dangerous_delete",
        arguments={"target": ".env"},
        elicitation=False,
    )

    first = proxy.run_session(messages)

    assert first["responses"][2]["error"]["code"] == -32001
    assert marker_path.exists() is False
    request = store.list_approval_requests(limit=1)[0]
    artifact_id = str(request["artifact_id"])
    artifact_hash = str(request["artifact_hash"])
    approval_id = store.record_local_once_approval(
        request_id="runtime-mcp-postclaim-freshness",
        harness="codex",
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        workspace=str(context.workspace_dir),
        publisher=None,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None
    block_config = replace(
        review_config,
        artifact_actions={artifact_id: "block"},
    )
    real_claim = store.claim_approval_reuse_decisions

    def claim_then_tighten_policy(
        decisions: tuple[dict[str, object], ...],
        **kwargs: object,
    ) -> bool:
        claimed = real_claim(decisions, **kwargs)
        if claimed:
            current_config[0] = block_config
        return claimed

    monkeypatch.setattr(store, "claim_approval_reuse_decisions", claim_then_tighten_policy)

    second = proxy.run_session(messages)

    assert marker_path.exists() is False
    response = second["responses"][2]
    assert response["error"]["data"] == {
        "approvalRequests": [],
        "guardPolicyAction": "block",
    }
    event = second["events"][2]
    assert event["decision"] == "terminal-block"
    assert event["policy_action"] == "block"
    assert event["scanner_evidence"][-1] == {
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": "approval_reuse_context_changed_after_claim",
        "context_matches": False,
        "current_action": "block",
        "effective_action": "block",
    }
    claim_events = store.list_events(event_name="approval.local_once_applied")
    assert len(claim_events) == 1
    assert claim_events[0]["payload"]["approval_id"] == approval_id
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "block"


@pytest.mark.parametrize("delete_after_claim", (False, True))
def test_runtime_mcp_retained_tool_policy_requires_same_row_after_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    delete_after_claim: bool,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    store = GuardStore(context.guard_home)
    config = GuardConfig(
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        security_level="custom",
        risk_actions={"mcp_dangerous_tool": "review"},
    )
    marker_path = tmp_path / "retained-tool-policy-must-not-forward.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
        current_config_provider=lambda: config,
    )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(proxy, "_maybe_open_approval_center", lambda **_kwargs: None)
    messages = _messages(
        tool_name="dangerous_delete",
        arguments={"target": ".env"},
        elicitation=False,
    )
    first = proxy.run_session(messages)
    assert first["responses"][2]["error"]["code"] == -32001
    request = store.list_approval_requests(limit=1)[0]
    artifact_id = str(request["artifact_id"])
    artifact_hash = str(request["artifact_hash"])
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact_id,
            artifact_hash=artifact_hash,
            workspace=str(context.workspace_dir),
            source="approval-gate",
        ),
        "2026-07-17T00:00:00+00:00",
    )
    original_claim = store.claim_approval_reuse_decisions

    def claim_then_delete_retained_row(
        decisions: tuple[dict[str, object], ...],
        **kwargs: object,
    ) -> bool:
        assert len(decisions) == 1
        assert store.approval_reuse_claim_disposition(decisions[0]) == "retained"
        claimed = original_claim(decisions, **kwargs)
        if claimed and delete_after_claim:
            decision_id = decisions[0].get("decision_id")
            assert isinstance(decision_id, int) and not isinstance(decision_id, bool)
            with store._connect() as connection:
                connection.execute("delete from policy_decisions where decision_id = ?", (decision_id,))
        return claimed

    monkeypatch.setattr(store, "claim_approval_reuse_decisions", claim_then_delete_retained_row)

    second = proxy.run_session(messages)

    if not delete_after_claim:
        assert marker_path.exists() is True
        assert second["responses"][2]["result"]["content"][0]["text"] == "forwarded"
        return
    assert marker_path.exists() is False
    response = second["responses"][2]
    assert response["error"]["data"]["guardPolicyAction"] == "require-reapproval"
    event = second["events"][2]
    assert event["decision"] == "queue-approval"
    assert event["scanner_evidence"][-1] == {
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": "approval_reuse_context_changed_after_claim",
        "context_matches": True,
        "claimed_authority_matches": False,
        "current_action": "review",
        "effective_action": "require-reapproval",
    }


def _prepare_runtime_mcp_exact_review_retry(
    *,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    marker_name: str,
) -> tuple[
    HarnessContext,
    GuardStore,
    CodexMcpGuardProxy,
    Path,
    list[dict[str, Any]],
    str,
    str,
    str,
]:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    store = GuardStore(context.guard_home)
    config = GuardConfig(
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        security_level="custom",
        risk_actions={"mcp_dangerous_tool": "review"},
    )
    marker_path = tmp_path / marker_name
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
        current_config_provider=lambda: config,
    )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(proxy, "_maybe_open_approval_center", lambda **_kwargs: None)
    messages = _messages(
        tool_name="dangerous_delete",
        arguments={"target": ".env"},
        elicitation=False,
    )
    first = proxy.run_session(messages)
    assert first["responses"][2]["error"]["code"] == -32001
    assert marker_path.exists() is False
    request = store.list_approval_requests(limit=1)[0]
    artifact_id = str(request["artifact_id"])
    artifact_hash = str(request["artifact_hash"])
    approval_id = store.record_local_once_approval(
        request_id=f"{marker_name}-approval",
        harness="codex",
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        workspace=str(context.workspace_dir),
        publisher=None,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None
    return (
        context,
        store,
        proxy,
        marker_path,
        messages,
        artifact_id,
        artifact_hash,
        approval_id,
    )


def test_runtime_mcp_tool_catalog_fingerprint_is_canonical_and_complete() -> None:
    first = {
        "safe_echo": {
            "description": "Safe echo",
            "input_schema": {
                "type": "object",
                "properties": {"message": {"type": "string", "description": "Text"}},
            },
        },
        "dangerous_delete": {
            "description": "Dangerous delete",
            "input_schema": {
                "properties": {"target": {"type": "string"}},
                "type": "object",
            },
        },
    }
    reordered = {
        "dangerous_delete": {
            "input_schema": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
            },
            "description": "Dangerous delete",
        },
        "safe_echo": {
            "input_schema": {
                "properties": {"message": {"description": "Text", "type": "string"}},
                "type": "object",
            },
            "description": "Safe echo",
        },
    }
    changed_sibling_schema = {
        **reordered,
        "safe_echo": {
            **reordered["safe_echo"],
            "input_schema": {
                "properties": {"message": {"description": "Text", "type": "number"}},
                "type": "object",
            },
        },
    }

    baseline = runtime_mcp_module._tool_catalog_fingerprint(first)

    assert baseline == runtime_mcp_module._tool_catalog_fingerprint(reordered)
    assert baseline != runtime_mcp_module._tool_catalog_fingerprint(changed_sibling_schema)
    assert baseline != runtime_mcp_module._tool_catalog_fingerprint(
        {**reordered, "new_tool": {"description": "New", "input_schema": {"type": "object"}}}
    )


def test_runtime_mcp_saved_allow_is_not_reused_before_complete_catalog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    store = GuardStore(context.guard_home)
    config = GuardConfig(
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        security_level="custom",
        risk_actions={"mcp_dangerous_tool": "review"},
    )
    marker_path = tmp_path / "unobserved-catalog-must-not-forward.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
        current_config_provider=lambda: config,
    )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(proxy, "_maybe_open_approval_center", lambda **_kwargs: None)
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "dangerous_delete", "arguments": {"target": ".env"}},
        },
    ]
    first = proxy.run_session(messages)
    assert first["responses"][1]["error"]["code"] == -32001
    request = store.list_approval_requests(limit=1)[0]
    approval_id = store.record_local_once_approval(
        request_id="unobserved-catalog-approval",
        harness="codex",
        artifact_id=str(request["artifact_id"]),
        artifact_hash=str(request["artifact_hash"]),
        workspace=str(context.workspace_dir),
        publisher=None,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None

    second = proxy.run_session(messages)

    assert marker_path.exists() is False
    assert second["responses"][1]["error"]["data"]["guardPolicyAction"] == "require-reapproval"
    assert second["events"][1]["scanner_evidence"][-1]["reason_code"] == ("approval_reuse_tool_catalog_incomplete")
    assert store.list_events(event_name="approval.local_once_applied") == []


def test_runtime_mcp_drains_idle_list_changed_before_saved_approval_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    store = GuardStore(context.guard_home)
    config = GuardConfig(
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        security_level="custom",
        risk_actions={"mcp_dangerous_tool": "review"},
    )
    marker_path = tmp_path / "idle-invalidation-must-not-forward.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_idle_catalog_invalidation_child_command(
            marker_path,
            tmp_path / "idle-invalidation-session.txt",
        ),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
        current_config_provider=lambda: config,
    )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(proxy, "_maybe_open_approval_center", lambda **_kwargs: None)
    messages = _messages(
        tool_name="dangerous_delete",
        arguments={"target": ".env"},
        elicitation=False,
    )
    first = proxy.run_session(messages)
    assert first["responses"][2]["error"]["code"] == -32001
    request = store.list_approval_requests(limit=1)[0]
    approval_id = store.record_local_once_approval(
        request_id="idle-list-changed-approval",
        harness="codex",
        artifact_id=str(request["artifact_id"]),
        artifact_hash=str(request["artifact_hash"]),
        workspace=str(context.workspace_dir),
        publisher=None,
        action="allow",
        created_at="2026-07-18T00:00:00+00:00",
        expires_at="2099-07-18T00:00:00+00:00",
    )
    assert approval_id is not None

    second = proxy.run_session(messages)

    assert marker_path.exists() is False
    assert second["responses"][2]["error"]["data"]["guardPolicyAction"] == "require-reapproval"
    assert second["events"][2]["decision"] == "queue-approval"
    assert proxy._tool_catalog_state == "invalidated"
    assert store.list_events(event_name="approval.local_once_applied") == []
    with sqlite3.connect(store.path) as connection:
        claimed_at = connection.execute(
            "select claimed_at from guard_local_once_approvals where approval_id = ?",
            (approval_id,),
        ).fetchone()[0]
    assert claimed_at is None


def test_runtime_mcp_process_boundary_clears_cross_session_response_buffers(tmp_path: Path) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_cross_session_buffer_child_command(tmp_path / "buffer-reset-session.txt"),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )

    first = proxy.run_session([{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}}])
    assert first["responses"][0]["id"] == 1
    assert proxy._buffered_child_responses == {}
    proxy._buffered_client_responses["2"] = [{"jsonrpc": "2.0", "id": 2, "result": {"stale": True}}]

    second = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
    )

    tools = second["responses"][1]["result"]["tools"]
    assert [tool["name"] for tool in tools] == ["current_session_tool"]
    assert proxy._tool_catalog_state == "complete"
    assert set(proxy._tool_catalog) == {"current_session_tool"}
    assert proxy._buffered_child_responses == {}
    assert proxy._buffered_client_responses == {}


def test_runtime_mcp_final_prewrite_drain_catches_notification_after_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _context_value, store, proxy, marker_path, messages, _artifact_id, _artifact_hash, approval_id = (
        _prepare_runtime_mcp_exact_review_retry(
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            marker_name="postclaim-notification-must-not-forward.json",
        )
    )
    real_claim = store.claim_approval_reuse_decisions

    def claim_then_emit_list_changed(
        decisions: tuple[dict[str, object], ...],
        **kwargs: object,
    ) -> bool:
        claimed = real_claim(decisions, **kwargs)
        if claimed:
            output_queue = proxy._child_output_queue
            assert output_queue is not None
            output_queue.put(
                runtime_mcp_module._ChildOutputFrame(
                    line=json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "method": "notifications/tools/list_changed",
                            "params": {},
                        }
                    )
                    + "\n"
                )
            )
        return claimed

    monkeypatch.setattr(store, "claim_approval_reuse_decisions", claim_then_emit_list_changed)

    result = proxy.run_session(messages)

    assert marker_path.exists() is False
    assert result["responses"][2]["error"]["data"]["guardPolicyAction"] == "require-reapproval"
    boundary_evidence = result["events"][2]["scanner_evidence"][-1]
    assert boundary_evidence["reason_code"] == "tool_catalog_changed_at_execution_boundary"
    assert boundary_evidence["phase"] == "immediately_before_forward"
    claim_events = store.list_events(event_name="approval.local_once_applied")
    assert len(claim_events) == 1
    assert claim_events[0]["payload"]["approval_id"] == approval_id
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "require-reapproval"


def test_runtime_mcp_exact_claim_binds_unchanged_full_advertised_catalog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _context_value, store, proxy, marker_path, messages, _artifact_id, _artifact_hash, approval_id = (
        _prepare_runtime_mcp_exact_review_retry(
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            marker_name="unchanged-catalog-forwarded.json",
        )
    )

    result = proxy.run_session(messages)

    assert marker_path.exists() is True
    assert result["responses"][2]["result"]["content"][0]["text"] == "forwarded"
    assert result["events"][2]["decision"] == "policy-allow"
    assert all(
        evidence.get("reason_code") != "approval_reuse_context_changed_after_claim"
        for evidence in result["events"][2].get("scanner_evidence", [])
        if isinstance(evidence, dict)
    )
    claim_events = store.list_events(event_name="approval.local_once_applied")
    assert len(claim_events) == 1
    assert claim_events[0]["payload"]["approval_id"] == approval_id


def test_runtime_mcp_exact_claim_fails_closed_when_current_config_refresh_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _context_value, store, proxy, marker_path, messages, _artifact_id, _artifact_hash, approval_id = (
        _prepare_runtime_mcp_exact_review_retry(
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            marker_name="runtime-config-refresh-failure-must-not-forward.json",
        )
    )

    def unavailable_config() -> GuardConfig:
        raise OSError("current config unavailable")

    proxy._current_config_provider = unavailable_config

    result = proxy.run_session(messages)

    assert marker_path.exists() is False
    response = result["responses"][2]
    assert response["error"]["data"]["guardPolicyAction"] == "require-reapproval"
    event = result["events"][2]
    assert event["decision"] == "queue-approval"
    assert event["scanner_evidence"][-1] == {
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": "approval_reuse_current_config_refresh_failed",
        "effective_action": "require-reapproval",
    }
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "require-reapproval"
    assert receipt["scanner_evidence"][-1] == event["scanner_evidence"][-1]
    claim_events = store.list_events(event_name="approval.local_once_applied")
    assert len(claim_events) == 1
    assert claim_events[0]["payload"]["approval_id"] == approval_id


def test_runtime_mcp_exact_claim_rejects_different_tool_catalog_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _context_value, store, proxy, marker_path, messages, _artifact_id, _artifact_hash, approval_id = (
        _prepare_runtime_mcp_exact_review_retry(
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            marker_name="changed-sibling-tool-must-not-forward.json",
        )
    )
    real_claim = store.claim_approval_reuse_decisions

    def claim_then_change_sibling_tool(
        decisions: tuple[dict[str, object], ...],
        **kwargs: object,
    ) -> bool:
        claimed = real_claim(decisions, **kwargs)
        if claimed:
            safe_echo = dict(proxy._tool_catalog["safe_echo"])
            safe_echo["description"] = "Safe echo with a changed advertised capability"
            proxy._tool_catalog["safe_echo"] = safe_echo
        return claimed

    monkeypatch.setattr(store, "claim_approval_reuse_decisions", claim_then_change_sibling_tool)

    result = proxy.run_session(messages)

    assert marker_path.exists() is False
    response = result["responses"][2]
    assert response["error"]["data"]["guardPolicyAction"] == "require-reapproval"
    event = result["events"][2]
    assert event["decision"] == "queue-approval"
    assert event["scanner_evidence"][-1] == {
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": "approval_reuse_context_changed_after_claim",
        "context_matches": False,
        "current_action": "review",
        "effective_action": "review",
    }
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "require-reapproval"
    assert receipt["scanner_evidence"][-1] == event["scanner_evidence"][-1]
    claim_events = store.list_events(event_name="approval.local_once_applied")
    assert len(claim_events) == 1
    assert claim_events[0]["payload"]["approval_id"] == approval_id


def test_runtime_mcp_same_context_saved_block_after_claim_has_truthful_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, store, proxy, marker_path, messages, artifact_id, artifact_hash, approval_id = (
        _prepare_runtime_mcp_exact_review_retry(
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            marker_name="same-context-saved-block-must-not-forward.json",
        )
    )
    assert context.workspace_dir is not None
    real_claim = store.claim_approval_reuse_decisions

    def claim_then_save_exact_block(
        decisions: tuple[dict[str, object], ...],
        **kwargs: object,
    ) -> bool:
        claimed = real_claim(decisions, **kwargs)
        if claimed:
            store.upsert_policy(
                PolicyDecision(
                    harness="codex",
                    scope="artifact",
                    action="block",
                    artifact_id=artifact_id,
                    artifact_hash=artifact_hash,
                    workspace=str(context.workspace_dir),
                    source="local",
                    reason="fresh exact block after one-shot claim",
                ),
                "2026-07-17T00:01:00+00:00",
            )
        return claimed

    monkeypatch.setattr(store, "claim_approval_reuse_decisions", claim_then_save_exact_block)

    result = proxy.run_session(messages)

    assert marker_path.exists() is False
    response = result["responses"][2]
    assert response["error"]["data"] == {
        "approvalRequests": [],
        "guardPolicyAction": "block",
    }
    event = result["events"][2]
    assert event["decision"] == "block-stored-policy"
    assert event["scanner_evidence"][-1]["reason_code"] == "approval_reuse_saved_block"
    assert all(
        evidence.get("reason_code") != "approval_reuse_context_changed_after_claim"
        for evidence in event["scanner_evidence"]
        if isinstance(evidence, dict)
    )
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "block"
    assert receipt["scanner_evidence"][-1]["reason_code"] == "approval_reuse_saved_block"
    assert all(
        evidence.get("reason_code") != "approval_reuse_context_changed_after_claim"
        for evidence in receipt["scanner_evidence"]
        if isinstance(evidence, dict)
    )
    claim_events = store.list_events(event_name="approval.local_once_applied")
    assert len(claim_events) == 1
    assert claim_events[0]["payload"]["approval_id"] == approval_id


def test_runtime_mcp_quarantines_child_when_entrypoint_changes_during_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    server_script = context.workspace_dir / "spawn-race-server.py"
    server_script.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
    proxy = CodexMcpGuardProxy(
        server_name="spawn-race",
        command=[sys.executable, str(server_script)],
        context=context,
        store=GuardStore(context.guard_home),
        config=GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir),
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    real_popen = runtime_mcp_module.subprocess.Popen
    processes: list[Any] = []

    def mutate_after_spawn(*args: Any, **kwargs: Any) -> Any:
        process = real_popen(*args, **kwargs)
        processes.append(process)
        server_script.write_text("raise SystemExit(93)\n", encoding="utf-8")
        return process

    monkeypatch.setattr(runtime_mcp_module.subprocess, "Popen", mutate_after_spawn)

    with pytest.raises(RuntimeError, match="launch identity changed"):
        proxy._start_process()

    assert processes and processes[0].poll() is not None
    assert proxy._active_runtime_launch_identity is None
    assert proxy._active_executable_identity is None
