"""Codex live browser approval authority and receipt finalization regressions."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approvals import apply_approval_resolution, wait_for_approval_requests
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.cli import commands_support_interaction as interaction_module
from codex_plugin_scanner.guard.cli.commands import add_guard_root_parser
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardApprovalRequest, GuardArtifact
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.approval_context import build_approval_context_token
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_facade_isolation import restore_cli_facade_approval_hooks


def teardown_module() -> None:
    """Reset facade overrides propagated into lazily imported CLI modules."""

    restore_cli_facade_approval_hooks()


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


def _parse_guard_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    return parser.parse_args(argv)


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
