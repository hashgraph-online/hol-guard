"""Default denial keeps transport execution and approval surfaces closed."""

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.cli import render
from codex_plugin_scanner.guard.cli.protect_approvals import _queue_local_protect_approvals
from codex_plugin_scanner.guard.cli.protect_output import _protect_payload_for_human_output
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_tool_calls import ToolCallDecision
from codex_plugin_scanner.guard.native_daemon_lifecycle import NativeDaemonLifecycleError
from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy, OpenCodeMcpGuardProxy, runtime_mcp
from codex_plugin_scanner.guard.store import GuardStore
from tests.silent_review_assertions import assert_silent_review_recorded
from tests.test_guard_protect_approval_guidance import _pending_package_payload
from tests.test_guard_runtime_mcp_saved_blocks import _child_command, _context, _messages, _package_artifact


@pytest.fixture(autouse=True)
def _native_package_context(package_intent_native, native_mcp_probe, monkeypatch) -> None:
    original = _context

    def enrolled_context(tmp_path: Path):
        context = original(tmp_path)
        native_mcp_probe(context.guard_home)
        return context

    monkeypatch.setitem(globals(), "_context", enrolled_context)


def _unexpected_prompt(*args, **kwargs):
    pytest.fail("default denial must not open an approval prompt")


def test_local_package_denial_preserves_receipt_and_exposes_decision_wait(tmp_path):
    context = _context(tmp_path)
    payload = _pending_package_payload()
    original_receipt = deepcopy(payload["receipt"])
    store = GuardStore(context.guard_home)
    _queue_local_protect_approvals(
        payload,
        store=store,
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        ensure_approval_daemon=_unexpected_prompt,
        approval_delivery_payload=_unexpected_prompt,
        localize_pending_approval_copy=_unexpected_prompt,
    )
    assert payload["executed"] is False
    assert payload["policy_action"] == "block"
    assert payload["receipt"] == original_receipt
    assert "Current package policy" in payload["review_hint"]
    request_id = store.list_approval_requests(status="pending")[0]["request_id"]
    assert f"hol-guard approvals wait {request_id} --json" in payload["review_hint"]
    assert payload["approval_resume"]["request_id"] == request_id
    assert payload["approval_requests"] == []
    assert_silent_review_recorded(store)


_LIVE_DAEMON_URL = "http://127.0.0.1:61234"


def _held_package_install_output(tmp_path, capsys, monkeypatch, *, token: bool, daemon_url: str | None):
    from codex_plugin_scanner.guard.daemon import manager

    def live_daemon_url(_home):
        if isinstance(daemon_url, Exception):
            raise daemon_url
        return daemon_url

    monkeypatch.setattr(manager, "load_guard_daemon_url", live_daemon_url)
    context = _context(tmp_path)
    context.guard_home.chmod(0o700)
    if token:
        token_path = context.guard_home / "daemon-auth-token"
        token_path.write_text("synthetic-daemon-token", encoding="utf-8")
        token_path.chmod(0o600)
    payload = _pending_package_payload()
    store = GuardStore(context.guard_home)
    _queue_local_protect_approvals(
        payload,
        store=store,
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        ensure_approval_daemon=_unexpected_prompt,
        approval_delivery_payload=_unexpected_prompt,
        localize_pending_approval_copy=_unexpected_prompt,
    )
    request = store.list_approval_requests(status="pending")[0]
    human_payload = _protect_payload_for_human_output(payload, guard_home=context.guard_home)
    render.emit_guard_payload("protect", human_payload, False)
    return human_payload, request, capsys.readouterr().out


def test_local_package_denial_prints_signed_link_to_the_running_daemon(tmp_path, capsys, monkeypatch):
    payload, request, output = _held_package_install_output(
        tmp_path, capsys, monkeypatch, token=True, daemon_url=_LIVE_DAEMON_URL
    )

    review_url = f"{_LIVE_DAEMON_URL}/requests/{request['request_id']}"
    assert payload["supply_chain_evaluation"]["user_copy"]["dashboard_url"].startswith(f"{review_url}#guard-token=gld1.")
    assert f"{review_url}#guard-token=gld1." in output
    assert request["request_id"] in output
    assert "synthetic-daemon-token" not in output


@pytest.mark.parametrize(
    ("token", "daemon_url"),
    [
        (False, _LIVE_DAEMON_URL),
        (True, None),
        (True, NativeDaemonLifecycleError("native_daemon_lifecycle_fact_unknown")),
    ],
    ids=["no-daemon-token", "no-running-daemon", "daemon-lookup-fails"],
)
def test_local_package_denial_without_an_openable_link_keeps_wait_guidance(
    tmp_path, capsys, monkeypatch, token, daemon_url
):
    payload, request, output = _held_package_install_output(
        tmp_path, capsys, monkeypatch, token=token, daemon_url=daemon_url
    )

    user_copy = payload["supply_chain_evaluation"]["user_copy"]
    assert user_copy["dashboard_url"] is None
    assert f"hol-guard approvals wait {request['request_id']}" in user_copy["harness_message"]
    assert "could not create a signed approval link" not in user_copy["harness_message"]
    assert request["request_id"] in output
    assert "#guard-token=" not in output
    assert "could not create a signed approval link" not in output


def test_local_package_malformed_config_stays_blocked(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    (context.guard_home / "config.toml").write_text("[invalid\n", encoding="utf-8")
    payload = _pending_package_payload()
    original_receipt = deepcopy(payload["receipt"])
    _queue_local_protect_approvals(
        payload,
        store=store,
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        ensure_approval_daemon=_unexpected_prompt,
        approval_delivery_payload=_unexpected_prompt,
        localize_pending_approval_copy=_unexpected_prompt,
    )
    assert payload["policy_action"] == "block"
    assert payload["receipt"] == original_receipt
    assert "hol-guard approvals wait" in payload["review_hint"]
    assert payload["approval_requests"] == []
    assert_silent_review_recorded(store)


def test_mcp_package_denial_preserves_reason_and_policy_source(tmp_path, monkeypatch):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=["unused"],
        context=context,
        store=store,
        config=GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir),
        source_scope="project",
        config_path=str(context.workspace_dir / "config.json"),
    )
    monkeypatch.setattr(runtime_mcp, "ensure_guard_daemon", _unexpected_prompt)
    artifact = _package_artifact(context=context, harness="codex", config_path=proxy.config_path)
    original_evaluation = {
        "decision": "review",
        "reasons": [{"code": "changed-package", "message": "Digest no longer matches."}],
        "packages": [{"name": "example", "version": "1.0"}],
        "risk_summary": "Package integrity changed.",
        "user_copy": {
            "title": "Review package",
            "summary": "Package changed",
            "dashboard_url": "http://127.0.0.1:4455/requests/example",
            "next_step": "Open Guard to approve",
            "harness_message": "Ask the user to approve",
        },
    }
    evaluation_snapshot = deepcopy(original_evaluation)
    evaluation = SimpleNamespace(
        risk_summary="Package integrity changed.",
        reasons=({"code": "changed-package", "message": "Digest no longer matches."},),
        user_copy=SimpleNamespace(title="Review", summary="Package changed", harness_message="Review package"),
        to_dict=lambda: original_evaluation,
    )
    response, event = proxy._queue_package_approval_response(
        message_id=1,
        artifact=artifact,
        artifact_hash="a" * 64,
        tool_name="install_package",
        params={"name": "install_package", "arguments": {}},
        package_evaluation=evaluation,
        policy_action="require-reapproval",
        scanner_evidence=(),
    )
    assert response["error"]["data"]["guardPolicyAction"] == "block"
    assert "Package integrity changed" in response["error"]["message"]
    assert "Digest no longer matches" in response["error"]["message"]
    details = response["error"]["data"]["supplyChainEvaluation"]
    assert details["reasons"] == original_evaluation["reasons"]
    assert details["packages"] == original_evaluation["packages"]
    assert details["decision"] == "block"
    assert details["user_copy"]["dashboard_url"] is None
    assert "safe, permitted alternative" in details["user_copy"]["next_step"]
    assert original_evaluation == evaluation_snapshot
    assert event["prompted"] is False
    assert response["error"]["data"]["approvalRequests"] == []
    assert_silent_review_recorded(store)
    assert store.list_receipts(limit=1)[0]["approval_source"] == "policy"


@pytest.mark.parametrize("proxy_class", [CodexMcpGuardProxy, OpenCodeMcpGuardProxy])
def test_default_mcp_review_blocks_without_prompt_or_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proxy_class: Any,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    marker = tmp_path / "must-not-execute.json"
    proxy = proxy_class(
        server_name="workspace-tools",
        command=_child_command(marker),
        context=context,
        store=store,
        config=GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir),
        source_scope="project",
        config_path=str(context.workspace_dir / "config.json"),
    )
    monkeypatch.setattr(
        runtime_mcp,
        "evaluate_tool_call",
        lambda **_kwargs: ToolCallDecision(
            action="review",
            policy_action="review",
            source="policy",
            signals=("review required",),
            summary="review required",
        ),
    )

    def unexpected_prompt(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("default review must not open an approval surface")

    monkeypatch.setattr(runtime_mcp, "ensure_guard_daemon", unexpected_prompt)
    result = proxy.run_session(_messages(tool_name="safe_echo", arguments={}, elicitation=True))
    assert not marker.exists()
    assert_silent_review_recorded(store)
    response = result["responses"][2]
    assert response["error"]["data"]["approvalRequests"] == []
    assert "safe, permitted alternative" in response["error"]["message"]
