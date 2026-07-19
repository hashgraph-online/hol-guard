"""Codex live browser approval authority and receipt finalization regressions."""

from __future__ import annotations

import argparse
import copy
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approvals import apply_approval_resolution, wait_for_approval_requests
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.cli import commands_hook_runtime_finish as finish_module
from codex_plugin_scanner.guard.cli import commands_support_interaction as interaction_module
from codex_plugin_scanner.guard.cli.commands import add_guard_root_parser, run_guard_command
from codex_plugin_scanner.guard.cli.commands_hook_runtime_state import (
    RuntimeArtifactHookState,
    set_runtime_artifact_hook_final_action,
)
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardApprovalRequest, GuardArtifact
from codex_plugin_scanner.guard.policy.engine import build_decision_v2
from codex_plugin_scanner.guard.receipts import build_receipt
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.approval_context import build_approval_context_token
from codex_plugin_scanner.guard.store import GuardStore


def _context_token() -> str:
    return build_approval_context_token(
        identity={"artifact_id": "codex:project:Bash"},
        content={"command": "printf ok"},
        capabilities={"action_type": "shell_command"},
        policy={"current_action": "review"},
        sandbox={"mode": "host"},
    )


def _artifact() -> GuardArtifact:
    return GuardArtifact(
        artifact_id="codex:project:Bash",
        name="Bash request",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=".codex/config.toml",
        command="printf ok",
    )


def _action_envelope() -> GuardActionEnvelope:
    return GuardActionEnvelope(
        schema_version=1,
        action_id="action-browser-review",
        harness="codex",
        event_name="PostToolUse",
        action_type="shell_command",
        workspace="/workspace",
        workspace_hash="workspace-hash",
        tool_name="Bash",
        command="printf ok",
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        raw_payload_redacted={"tool_name": "Bash"},
    ).with_pre_execution_result("review")


def _resolved_request(store: GuardStore, token: str) -> GuardApprovalRequest:
    request = GuardApprovalRequest(
        request_id="request-browser-review",
        harness="codex",
        artifact_id="codex:project:Bash",
        artifact_name="Bash request",
        artifact_hash=token,
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path=".codex/config.toml",
        review_command="hol-guard approvals approve request-browser-review",
        approval_url="http://127.0.0.1:4455/requests/request-browser-review",
        launch_target="printf ok",
    )
    store.add_approval_request(request, "2026-07-17T00:00:00+00:00")
    apply_approval_resolution(
        store=store,
        request_id=request.request_id,
        action="allow",
        scope="artifact",
        workspace=None,
        reason="approved exact current request",
        now="2026-07-17T00:00:01+00:00",
    )
    store.seed_request_resume(
        request_id=request.request_id,
        operation_id="operation-browser-review",
        harness="codex",
        strategy="codex-app-server-thread",
        supported=True,
        thread_id="thread-browser-review",
        now="2026-07-17T00:00:00+00:00",
    )
    return request


def test_exact_browser_allow_finalizes_every_authoritative_surface_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    token = _context_token()
    request = _resolved_request(store, token)
    envelope = _action_envelope()
    artifact = _artifact()
    decision_v2 = build_decision_v2("review", reason="review").to_dict()
    receipt = build_receipt(
        harness="codex",
        artifact_id=artifact.artifact_id,
        artifact_hash=token,
        policy_decision="review",
        capabilities_summary="runtime tool action",
        changed_capabilities=["tool_action_request"],
        provenance_summary="runtime tool request evaluated from .codex/config.toml",
        artifact_name=artifact.name,
        source_scope=artifact.source_scope,
        scanner_evidence=[{"source": "policy_composition", "authoritative_action": "review"}],
        approval_source="approval_center",
    )
    response_payload: dict[str, object] = {
        "recorded": False,
        "harness": "codex",
        "artifact_id": artifact.artifact_id,
        "artifact_hash": token,
        "artifact_name": artifact.name,
        "artifact_type": artifact.artifact_type,
        "policy_action": "review",
        "risk_summary": "Current policy requires review.",
        "decision_v2_json": decision_v2,
        "policy_composition": {"current_composed_action": "review", "authoritative_action": "review"},
        "operation_id": "operation-browser-review",
        "operation": {"operation_id": "operation-browser-review", "status": "waiting_on_approval"},
        "approval_requests": [request.to_dict()],
    }
    state = RuntimeArtifactHookState(
        action_envelope=envelope,
        artifact_id=artifact.artifact_id,
        artifact_name=artifact.name,
        browser_approval_daemon_client=None,
        changed_capabilities=["tool_action_request"],
        decision_signals=(),
        decision_v2_payload=decision_v2,
        event_name="PostToolUse",
        initial_policy_action="review",
        package_evaluation=None,
        policy_action="review",
        receipt=receipt,
        requested_policy_action="review",
        response_payload=response_payload,
        risk_summary="Current policy requires review.",
        runtime_artifact=artifact,
        runtime_artifact_hash=token,
        scanner_evidence_payload=[],
        stored_policy_action=None,
    )
    statuses: list[dict[str, object]] = []

    class _DaemonClient:
        def update_operation_status(self, **kwargs: object) -> None:
            statuses.append(dict(kwargs))

    state.browser_approval_daemon_client = _DaemonClient()
    fresh_state = copy.deepcopy(state)
    set_runtime_artifact_hook_final_action(fresh_state, "allow")
    emitted_actions: list[str] = []
    usage: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        finish_module,
        "_emit_native_hook_response",
        lambda **kwargs: emitted_actions.append(str(kwargs["policy_action"])),
    )
    monkeypatch.setattr(
        finish_module,
        "_record_harness_usage_for_hook",
        lambda **kwargs: usage.append(
            (
                str(kwargs["policy_action"]),
                kwargs["action_envelope"].pre_execution_result,
            )
        ),
    )

    rc = finish_module._finalize_runtime_artifact_hook(
        state,
        argparse.Namespace(harness="codex", json=False),
        config=GuardConfig(store.guard_home, None, approval_wait_timeout_seconds=1),
        output_stream=StringIO(),
        payload={"hook_event_name": "PostToolUse", "tool_name": "Bash"},
        store=store,
        post_wait_revalidator=lambda: fresh_state,
    )

    assert rc == 0
    assert fresh_state.policy_action == "allow"
    assert fresh_state.response_payload["policy_action"] == "allow"
    assert fresh_state.response_payload["resolved_policy_action"] == "allow"
    assert fresh_state.response_payload["decision_v2_json"]["action"] == "allow"
    assert "paused" not in str(fresh_state.response_payload["trigger_summary"]).lower()
    assert "reviewed" in str(fresh_state.response_payload["trigger_summary"]).lower()
    assert "allows" in str(fresh_state.response_payload["why_now"]).lower()
    assert "allows" in str(fresh_state.response_payload["risk_headline"]).lower()
    assert fresh_state.response_payload["policy_composition"]["authoritative_action"] == "allow"
    assert fresh_state.response_payload["operation"]["status"] == "completed"
    assert fresh_state.response_payload["operation_status"] == "completed"
    assert fresh_state.response_payload["continuation"] == {
        "status": "resumed",
        "resolution_action": "allow",
        "strategy": "live-hook",
    }
    assert statuses == [{"operation_id": "operation-browser-review", "status": "completed"}]
    assert emitted_actions == ["allow"]
    assert usage == [("allow", "allow")]
    tool_receipts = [
        item for item in store.list_receipts(limit=10) if item["provenance_summary"] != "Guard approval decision"
    ]
    assert len(tool_receipts) == 1
    assert tool_receipts[0]["policy_decision"] == "allow"
    assert tool_receipts[0]["approval_source"] == "browser"
    assert tool_receipts[0]["approval_request_id"] == request.request_id
    assert tool_receipts[0]["action_envelope_json"]["pre_execution_result"] == "allow"
    assert any(
        item.get("source") == "policy_composition" and item.get("authoritative_action") == "allow"
        for item in tool_receipts[0]["scanner_evidence"]
    )
    assert any(
        item.get("source") == "browser_approval_resolution" and item.get("authoritative_action") == "allow"
        for item in tool_receipts[0]["scanner_evidence"]
    )
    resume = store.get_request_resume(request.request_id)
    assert resume is not None
    assert resume["status"] == "resumed"
    assert resume["resolution_action"] == "allow"


def test_fresh_sandbox_requirement_after_browser_wait_is_authoritative_everywhere(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    token = _context_token()
    request = _resolved_request(store, token)
    artifact = _artifact()
    decision_v2 = build_decision_v2("review", reason="review").to_dict()
    receipt = build_receipt(
        harness="codex",
        artifact_id=artifact.artifact_id,
        artifact_hash=token,
        policy_decision="review",
        capabilities_summary="runtime tool action",
        changed_capabilities=["tool_action_request"],
        provenance_summary="runtime tool request evaluated from .codex/config.toml",
        artifact_name=artifact.name,
        source_scope=artifact.source_scope,
        scanner_evidence=[{"source": "policy_composition", "authoritative_action": "review"}],
        approval_source="approval_center",
    )
    response_payload: dict[str, object] = {
        "recorded": False,
        "harness": "codex",
        "artifact_id": artifact.artifact_id,
        "artifact_hash": token,
        "artifact_name": artifact.name,
        "artifact_type": artifact.artifact_type,
        "policy_action": "review",
        "risk_summary": "Current policy requires review.",
        "decision_v2_json": decision_v2,
        "policy_composition": {"current_composed_action": "review", "authoritative_action": "review"},
        "operation_id": "operation-browser-review",
        "operation": {"operation_id": "operation-browser-review", "status": "waiting_on_approval"},
        "approval_requests": [request.to_dict()],
    }
    state = RuntimeArtifactHookState(
        action_envelope=_action_envelope(),
        artifact_id=artifact.artifact_id,
        artifact_name=artifact.name,
        browser_approval_daemon_client=None,
        changed_capabilities=["tool_action_request"],
        decision_signals=(),
        decision_v2_payload=decision_v2,
        event_name="PostToolUse",
        initial_policy_action="review",
        package_evaluation=None,
        policy_action="review",
        receipt=receipt,
        requested_policy_action="review",
        response_payload=response_payload,
        risk_summary="Current policy requires review.",
        runtime_artifact=artifact,
        runtime_artifact_hash=token,
        scanner_evidence_payload=[],
        stored_policy_action=None,
    )
    statuses: list[dict[str, object]] = []

    class _DaemonClient:
        def update_operation_status(self, **kwargs: object) -> None:
            statuses.append(dict(kwargs))

    state.browser_approval_daemon_client = _DaemonClient()
    fresh_state = copy.deepcopy(state)
    fresh_composition = fresh_state.response_payload["policy_composition"]
    assert isinstance(fresh_composition, dict)
    fresh_composition["current_composed_action"] = "sandbox-required"
    set_runtime_artifact_hook_final_action(fresh_state, "sandbox-required")
    emitted_actions: list[str] = []
    usage: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        finish_module,
        "_emit_native_hook_response",
        lambda **kwargs: emitted_actions.append(str(kwargs["policy_action"])),
    )
    monkeypatch.setattr(
        finish_module,
        "_record_harness_usage_for_hook",
        lambda **kwargs: usage.append(
            (
                str(kwargs["policy_action"]),
                kwargs["action_envelope"].pre_execution_result,
            )
        ),
    )

    rc = finish_module._finalize_runtime_artifact_hook(
        state,
        argparse.Namespace(harness="codex", json=False),
        config=GuardConfig(store.guard_home, None, approval_wait_timeout_seconds=1),
        output_stream=StringIO(),
        payload={"hook_event_name": "PostToolUse", "tool_name": "Bash"},
        store=store,
        post_wait_revalidator=lambda: fresh_state,
    )

    assert rc == 0
    assert fresh_state.policy_action == "sandbox-required"
    assert fresh_state.response_payload["policy_action"] == "sandbox-required"
    assert fresh_state.response_payload["resolved_policy_action"] == "sandbox-required"
    assert fresh_state.response_payload["decision_v2_json"]["action"] == "ask"
    assert fresh_state.response_payload["policy_composition"] == {
        "current_composed_action": "sandbox-required",
        "authoritative_action": "sandbox-required",
    }
    assert fresh_state.response_payload["operation_status"] == "blocked"
    assert fresh_state.response_payload["continuation"] == {
        "status": "blocked",
        "resolution_action": "sandbox-required",
        "strategy": "live-hook",
    }
    assert "requires a sandbox" in str(fresh_state.response_payload["review_hint"])
    assert statuses == [{"operation_id": "operation-browser-review", "status": "blocked"}]
    assert emitted_actions == ["sandbox-required"]
    assert usage == [("sandbox-required", "sandbox-required")]
    tool_receipts = [
        item for item in store.list_receipts(limit=10) if item["provenance_summary"] != "Guard approval decision"
    ]
    assert len(tool_receipts) == 1
    assert tool_receipts[0]["policy_decision"] == "sandbox-required"
    assert tool_receipts[0]["action_envelope_json"]["pre_execution_result"] == "sandbox-required"
    assert any(
        item.get("source") == "policy_composition" and item.get("authoritative_action") == "sandbox-required"
        for item in tool_receipts[0]["scanner_evidence"]
    )
    assert any(
        item.get("source") == "browser_approval_resolution" and item.get("authoritative_action") == "sandbox-required"
        for item in tool_receipts[0]["scanner_evidence"]
    )
    resume = store.get_request_resume(request.request_id)
    assert resume is not None
    assert resume["status"] == "blocked"
    assert resume["resolution_action"] == "sandbox-required"
    assert resume["reason"] == "sandbox_required_not_resumed"


def _parse_guard_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    return parser.parse_args(argv)


def test_current_terminal_block_is_not_queued_or_browser_approved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    (guard_home / "config.toml").write_text("approval_wait_timeout_seconds = 120\n", encoding="utf-8")

    def unexpected(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("terminal Codex actions must not enter the approval queue or browser wait")

    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", unexpected)
    monkeypatch.setattr(guard_commands_module, "queue_blocked_approvals", unexpected)
    monkeypatch.setattr(guard_commands_module, "wait_for_approval_requests", unexpected)
    output = StringIO()
    stdout = StringIO()
    with redirect_stdout(stdout):
        rc = run_guard_command(
            _parse_guard_args(
                [
                    "hook",
                    "--home",
                    str(tmp_path / "home"),
                    "--guard-home",
                    str(guard_home),
                    "--workspace",
                    str(workspace),
                    "--harness",
                    "codex",
                    "--policy-action",
                    "block",
                ]
            ),
            input_text=json.dumps(
                {
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "printf ok"},
                    "tool_response": {"stdout": "ok"},
                    "source_scope": "project",
                    "cwd": str(workspace),
                }
            ),
            output_stream=output,
        )
    output.write(stdout.getvalue())

    assert rc == 0
    native_payload = json.loads(output.getvalue())
    assert native_payload["decision"] == "block"
    assert native_payload["continue"] is False
    assert "/requests/" not in str(native_payload)
    store = GuardStore(guard_home)
    assert store.list_approval_requests(limit=10) == []
    receipts = store.list_receipts(limit=10)
    assert len(receipts) == 1
    assert receipts[0]["policy_decision"] == "block"
    assert receipts[0]["action_envelope_json"]["pre_execution_result"] == "block"


@pytest.mark.parametrize("terminal_action", ["block", "sandbox-required"])
def test_terminal_actions_are_not_browser_wait_candidates(terminal_action: str) -> None:
    args = argparse.Namespace(harness="codex", json=False)

    assert not guard_commands_module._codex_can_use_browser_approval(
        args,
        event_name="PostToolUse",
        policy_action=terminal_action,
    )


@pytest.mark.parametrize(
    ("resolution_action", "current_token", "expected_validation"),
    [
        ("block", "same", None),
        ("allow", "changed", "approval_context_changed"),
    ],
)
def test_block_or_changed_context_resolution_remains_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resolution_action: str,
    current_token: str,
    expected_validation: str | None,
) -> None:
    monkeypatch.setattr(interaction_module, "wait_for_approval_requests", wait_for_approval_requests)
    store = GuardStore(tmp_path / "guard-home")
    approved_token = _context_token()
    request = GuardApprovalRequest(
        request_id="request-fail-closed",
        harness="codex",
        artifact_id="codex:project:Bash",
        artifact_name="Bash request",
        artifact_hash=approved_token,
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path=".codex/config.toml",
        review_command="hol-guard approvals approve request-fail-closed",
        approval_url="http://127.0.0.1:4455/requests/request-fail-closed",
        launch_target="printf ok",
    )
    store.add_approval_request(request, "2026-07-17T00:00:00+00:00")
    apply_approval_resolution(
        store=store,
        request_id=request.request_id,
        action=resolution_action,
        scope="artifact",
        workspace=None,
        reason="browser resolution",
        now="2026-07-17T00:00:01+00:00",
    )
    expected_token = (
        approved_token
        if current_token == "same"
        else build_approval_context_token(
            identity={"artifact_id": "codex:project:Bash"},
            content={"command": "printf changed"},
            capabilities={"action_type": "shell_command"},
            policy={"current_action": "require-reapproval"},
            sandbox={"mode": "host"},
        )
    )
    statuses: list[str] = []

    class _DaemonClient:
        def update_operation_status(self, **kwargs: object) -> None:
            statuses.append(str(kwargs["status"]))

    response_payload: dict[str, object] = {
        "artifact_id": request.artifact_id,
        "artifact_hash": expected_token,
        "operation_id": "operation-fail-closed",
        "operation": {"operation_id": "operation-fail-closed", "status": "waiting_on_approval"},
        "approval_requests": [request.to_dict()],
    }

    decision = guard_commands_module._codex_browser_approval_decision(
        args=argparse.Namespace(harness="codex", json=False),
        event_name="PostToolUse",
        policy_action="require-reapproval",
        response_payload=response_payload,
        store=store,
        config=GuardConfig(store.guard_home, None, approval_wait_timeout_seconds=1),
        daemon_client=_DaemonClient(),
        expected_artifact_hash=expected_token,
        fresh_context_provider=lambda: {
            "artifact_id": request.artifact_id,
            "artifact_hash": expected_token,
            "current_action": "require-reapproval",
            "authoritative_action": "block",
        },
    )

    assert decision == "block"
    assert statuses == ["blocked"]
    assert response_payload["operation_status"] == "blocked"
    assert response_payload["continuation"] == {
        "status": "blocked",
        "resolution_action": "block",
        "strategy": "live-hook",
    }
    if expected_validation is not None:
        assert response_payload["browser_resolution_validation"] == expected_validation


@pytest.mark.parametrize(
    ("fresh_action", "change_context", "expected_validation"),
    [
        ("review", True, "approval_context_changed"),
        ("block", False, "current_policy_became_terminal"),
        ("sandbox-required", False, "current_policy_became_terminal"),
    ],
)
def test_browser_allow_is_revalidated_against_context_recomputed_after_wait(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_action: str,
    change_context: bool,
    expected_validation: str,
) -> None:
    monkeypatch.setattr(interaction_module, "wait_for_approval_requests", wait_for_approval_requests)
    store = GuardStore(tmp_path / "guard-home")
    approved_token = _context_token()
    request = _resolved_request(store, approved_token)
    fresh_token = (
        build_approval_context_token(
            identity={"artifact_id": "codex:project:Bash"},
            content={"command": "printf changed"},
            capabilities={"action_type": "shell_command"},
            policy={"current_action": fresh_action},
            sandbox={"mode": "host"},
        )
        if change_context
        else approved_token
    )
    response_payload: dict[str, object] = {
        "artifact_id": request.artifact_id,
        "artifact_hash": approved_token,
        "operation_id": "operation-browser-revalidation",
        "operation": {"operation_id": "operation-browser-revalidation", "status": "waiting_on_approval"},
        "approval_requests": [request.to_dict()],
    }

    decision = guard_commands_module._codex_browser_approval_decision(
        args=argparse.Namespace(harness="codex", json=False),
        event_name="PostToolUse",
        policy_action="review",
        response_payload=response_payload,
        store=store,
        config=GuardConfig(store.guard_home, None, approval_wait_timeout_seconds=1),
        expected_artifact_hash=approved_token,
        fresh_context_provider=lambda: {
            "artifact_id": request.artifact_id,
            "artifact_hash": fresh_token,
            "current_action": fresh_action,
            "authoritative_action": fresh_action,
        },
    )

    expected_decision = "sandbox-required" if fresh_action == "sandbox-required" else "block"
    assert decision == expected_decision
    assert response_payload["operation_status"] == "blocked"
    assert response_payload["browser_resolution_validation"] == expected_validation
    assert response_payload["continuation"] == {
        "status": "blocked",
        "resolution_action": expected_decision,
        "strategy": "live-hook",
    }


@pytest.mark.parametrize(
    "fresh_authoritative_action",
    ["review", "require-reapproval", "sandbox-required", "block"],
)
def test_browser_allow_requires_fresh_authoritative_allow_after_atomic_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_authoritative_action: str,
) -> None:
    monkeypatch.setattr(interaction_module, "wait_for_approval_requests", wait_for_approval_requests)
    store = GuardStore(tmp_path / "guard-home")
    approved_token = _context_token()
    request = _resolved_request(store, approved_token)
    response_payload: dict[str, object] = {
        "artifact_id": request.artifact_id,
        "artifact_hash": approved_token,
        "operation_id": "operation-browser-authority",
        "operation": {"operation_id": "operation-browser-authority", "status": "waiting_on_approval"},
        "approval_requests": [request.to_dict()],
    }

    decision = guard_commands_module._codex_browser_approval_decision(
        args=argparse.Namespace(harness="codex", json=False),
        event_name="PostToolUse",
        policy_action="review",
        response_payload=response_payload,
        store=store,
        config=GuardConfig(store.guard_home, None, approval_wait_timeout_seconds=1),
        expected_artifact_hash=approved_token,
        fresh_context_provider=lambda: {
            "artifact_id": request.artifact_id,
            "artifact_hash": approved_token,
            "current_action": "review",
            "authoritative_action": fresh_authoritative_action,
        },
    )

    expected_decision = "sandbox-required" if fresh_authoritative_action == "sandbox-required" else "block"
    assert decision == expected_decision
    assert response_payload["operation_status"] == "blocked"
    assert response_payload["browser_resolution_validation"] == ("fresh_authoritative_action_not_allowed")
    assert response_payload["continuation"] == {
        "status": "blocked",
        "resolution_action": expected_decision,
        "strategy": "live-hook",
    }


def test_browser_allow_without_fresh_context_provider_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(interaction_module, "wait_for_approval_requests", wait_for_approval_requests)
    store = GuardStore(tmp_path / "guard-home")
    approved_token = _context_token()
    request = _resolved_request(store, approved_token)
    response_payload: dict[str, object] = {
        "artifact_id": request.artifact_id,
        "artifact_hash": approved_token,
        "operation_id": "operation-browser-no-fresh-context",
        "operation": {
            "operation_id": "operation-browser-no-fresh-context",
            "status": "waiting_on_approval",
        },
        "approval_requests": [request.to_dict()],
    }

    decision = guard_commands_module._codex_browser_approval_decision(
        args=argparse.Namespace(harness="codex", json=False),
        event_name="PostToolUse",
        policy_action="review",
        response_payload=response_payload,
        store=store,
        config=GuardConfig(store.guard_home, None, approval_wait_timeout_seconds=1),
        expected_artifact_hash=approved_token,
    )

    assert decision == "block"
    assert response_payload["browser_resolution_validation"] == "fresh_context_unavailable"
    assert response_payload["operation_status"] == "blocked"
