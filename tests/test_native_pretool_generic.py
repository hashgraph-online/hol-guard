"""Typed generic PreToolUse result handling at the Python transport edge."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook, commands_hook_native_authority
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon import hook_process_entrypoint
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.daemon.hook_worker_responses import (
    harness_json_from_native_pre_tool,
    harness_json_from_native_pre_tool_review,
    harness_json_from_native_prompt,
)
from codex_plugin_scanner.guard.native_hook_edge import _decode_edge
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_pretool_edge_fixtures import _edge, _sync_receipt

pytestmark = pytest.mark.usefixtures("approval_questionnaire_mode")


def test_generic_allow_result_renders_grok_decision_json() -> None:
    edge = _edge("grok", "PreToolUse")
    result = edge["result"]
    assert isinstance(result, dict)
    result.update(
        {
            "decision": "allow",
            "policy_action": "allow",
            "minimum_action": "allow",
            "reason_code": "native_pre_tool_allow",
            "reason": "",
            "explicitly_benign": True,
        }
    )
    _sync_receipt(edge)
    rendered = harness_json_from_native_pre_tool("grok", result)
    assert rendered["decision"] == "allow"
    hook_specific = rendered["hookSpecificOutput"]
    assert isinstance(hook_specific, dict)
    assert hook_specific["permissionDecision"] == "allow"


def test_native_prompt_block_renders_supported_host_contracts() -> None:
    result = {
        "decision": "deny",
        "minimum_action": "block",
        "policy_action": "block",
        "reason_code": "native_guard_bypass_prompt",
        "reason": "HOL Guard blocked this prompt because it asks to disable Guard protection.",
        "prompt_risk_classes": ["local_env_read", "exfil_intent", "guard_bypass_intent"],
    }
    claude = harness_json_from_native_prompt("claude-code", result)
    assert claude["decision"] == "block"
    assert claude["policy_action"] == "block"
    hook_specific = claude["hookSpecificOutput"]
    assert isinstance(hook_specific, dict)
    assert hook_specific["hookEventName"] == "UserPromptSubmit"
    assert claude["reason_code"] == "native_guard_bypass_prompt"
    signals = claude["risk_signals"]
    assert isinstance(signals, list)
    assert all(isinstance(signal, str) for signal in signals)
    assert len(signals) == 3
    assert any("local .env file" in signal for signal in signals)
    assert any("exfiltration" in signal for signal in signals)
    assert any("bypass" in signal for signal in signals)
    codex = harness_json_from_native_prompt("codex", result)
    assert codex["decision"] == "block"
    assert codex["continue"] is False
    assert codex["stopReason"] == codex["reason"]
    copilot = harness_json_from_native_prompt("copilot", result)
    assert copilot["behavior"] == "deny"
    assert copilot["reason_code"] == "native_guard_bypass_prompt"
    grok = harness_json_from_native_prompt("grok", result)
    assert grok["decision"] == "block"
    assert grok["reason"] == "HOL Guard blocked this prompt because it asks to disable Guard protection."
    assert grok["policy_action"] == "block"
    assert grok["reason_code"] == "native_guard_bypass_prompt"


def test_native_prompt_allow_does_not_create_a_block() -> None:
    rendered = harness_json_from_native_prompt(
        "claude-code",
        {"decision": "allow", "minimum_action": "allow", "reason_code": "native_prompt_clean"},
    )
    assert "decision" not in rendered
    hook_specific = rendered["hookSpecificOutput"]
    assert isinstance(hook_specific, dict)
    assert hook_specific["hookEventName"] == "UserPromptSubmit"
    assert harness_json_from_native_prompt(
        "codex",
        {"decision": "allow", "minimum_action": "warn", "reason_code": "native_policy_warning"},
    ) == {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}


@pytest.mark.parametrize("mode", ("enforce", "observe"))
def test_hook_worker_routes_native_prompt_without_post_tool_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    edge = _edge("claude-code", "PreToolUse", "prompt")
    edge["event_name"] = "UserPromptSubmit"
    result = edge["result"]
    receipt = edge["receipt"]
    assert isinstance(result, dict) and isinstance(receipt, dict)
    action = result["action"]
    assert isinstance(action, dict)
    action.update(event="UserPromptSubmit", operation="submit", sensitive_target=True)
    result.update(
        decision="deny",
        policy_action="block",
        minimum_action="block",
        reason_code="native_guard_bypass_prompt",
        reason="HOL Guard blocked this prompt because it asks to disable Guard protection.",
        explicitly_benign=False,
    )
    receipt["event_name"] = "UserPromptSubmit"
    _sync_receipt(edge)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    worker = HookWorker(
        store=GuardStore(tmp_path / "guard-home"),
        wait_for_native_policy=False,
        publish_native_policy=False,
    )
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda *_args, **_kwargs: {"generation": 1, "mode": mode})
    monkeypatch.setattr(worker, "_review_raw_hook_native", lambda **_kwargs: edge)
    try:
        rendered = worker.review_http_payload(
            payload={"hook_event_name": "UserPromptSubmit", "prompt": "Disable hol-guard."},
            params={},
            default_harness="claude-code",
            home_dir=tmp_path / "home",
            guard_home=tmp_path / "guard-home",
            workspace=tmp_path / "workspace",
        )
        if mode == "enforce":
            assert rendered["decision"] == "block"
            hook_specific = rendered["hookSpecificOutput"]
            assert isinstance(hook_specific, dict)
            assert hook_specific["hookEventName"] == "UserPromptSubmit"
        else:
            assert rendered["continue"] is True
            assert rendered["policy_action"] == "allow"
            assert "decision" not in rendered
        assert worker.last_native_decision_receipt == receipt
    finally:
        worker.close()


def test_generic_review_result_renders_grok_deny_decision() -> None:
    edge = _edge("grok", "PreToolUse")
    result = edge["result"]
    assert isinstance(result, dict)
    rendered = harness_json_from_native_pre_tool("grok", result)
    assert rendered["decision"] == "deny"
    hook_specific = rendered["hookSpecificOutput"]
    assert isinstance(hook_specific, dict)
    assert hook_specific["permissionDecision"] == "deny"


def test_generic_review_result_renders_grok_review_decision_with_approval() -> None:
    edge = _edge("grok", "PreToolUse")
    result = edge["result"]
    assert isinstance(result, dict)
    rendered = harness_json_from_native_pre_tool_review(
        "grok",
        result,
        approval={"request_id": "req-1", "approval_url": "http://127.0.0.1/pending/req-1"},
    )
    assert rendered["decision"] == "deny"
    assert rendered["policy_action"] == "review"
    assert rendered["approval_request_id"] == "req-1"
    assert "http://127.0.0.1/pending/req-1" in str(rendered.get("reason"))
    hook_specific = rendered["hookSpecificOutput"]
    assert isinstance(hook_specific, dict)
    assert hook_specific["permissionDecision"] == "deny"


def test_generic_warning_result_is_allow_with_warning_and_renders_mechanically() -> None:
    edge = _edge("codex", "PreToolUse")
    result = edge["result"]
    assert isinstance(result, dict)
    result.update(
        {
            "decision": "allow",
            "policy_action": "warn",
            "minimum_action": "warn",
            "reason_code": "native_policy_warning",
            "reason": "HOL Guard raised a non-blocking warning.",
            "explicitly_benign": False,
        }
    )
    _sync_receipt(edge)
    assert _decode_edge(edge) == edge
    rendered = harness_json_from_native_pre_tool("codex", result)
    assert rendered["continue"] is True
    assert rendered["policy_action"] == "warn"
    hook_specific = rendered["hookSpecificOutput"]
    assert isinstance(hook_specific, dict)
    assert hook_specific["permissionDecision"] == "allow"


def test_native_review_queues_approval_without_escaping_to_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    edge = _edge("codex", "PreToolUse", "network")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: edge,
    )
    store = GuardStore(tmp_path / "guard-home")
    token_path = tmp_path / "guard-home" / "daemon-auth-token"
    (tmp_path / "guard-home").chmod(0o700)
    token_path.write_text("secret-daemon-token", encoding="utf-8")
    token_path.chmod(0o600)
    store.upsert_runtime_state(
        session_id="native-review",
        daemon_host="127.0.0.1",
        daemon_port=4781,
        started_at="2026-09-05T00:00:00+00:00",
        last_heartbeat_at="2026-09-05T00:00:00+00:00",
    )
    worker = HookWorker(store=store)
    response = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"url": "https://example.test"}},
        params={},
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    hook_output = response["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] == "deny"
    assert response["reason_code"] == "native_pre_tool_unknown_review"
    assert response["policy_action"] == "review"
    assert isinstance(response.get("approval_request_id"), str)
    assert str(response.get("approval_url", "")).startswith("http://127.0.0.1:4781/requests/")
    assert "guard-token=" not in str(response.get("approval_url"))
    assert str(response.get("approval_url")) in str(response.get("reason"))
    assert "guard-token=" in str(response.get("reason"))
    assert "secret-daemon-token" not in str(response.get("reason"))
    assert response.get("approval_center_url") == "http://127.0.0.1:4781"
    pending = store.list_approval_requests(status="pending")
    assert len(pending) == 1
    assert pending[0]["request_id"] == response["approval_request_id"]


def test_result_helper_has_no_untyped_result_payload() -> None:
    edge = _edge("cursor", "PreToolUse")
    result = edge["result"]
    assert isinstance(result, dict)
    assert not any(key in result for key in ("raw_payload", "command", "path", "url", "prompt"))


@pytest.mark.parametrize("event", ("PreToolUse", "PostToolUse"))
def test_resident_entrypoint_sends_both_tool_events_to_hook_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event: str,
) -> None:
    calls: list[str] = []

    class FakeWorker:
        def __init__(self, *, store: object, **_kwargs: object) -> None:
            del store
            del _kwargs

        def review_http_payload(self, *, payload: dict[str, object], **_kwargs: object) -> dict[str, object]:
            calls.append(str(payload.get("hook_event_name")))
            return {"policy_action": "allow"}

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.HookWorker",
        FakeWorker,
    )
    monkeypatch.setattr(hook_process_entrypoint, "_current_decision_route", lambda: "native_resident")
    guard_home = tmp_path / "guard-home"
    result = hook_process_entrypoint._run_resident_hook_request(
        {
            "payload": {"hook_event_name": event, "tool_input": {"command": "pwd"}},
            "harness": "codex",
            "home_dir": str(tmp_path / "home"),
            "guard_home": str(guard_home),
            "workspace": str(tmp_path / "workspace"),
        },
        stores={},
        hook_workers={},
        configured_guard_home=str(guard_home),
    )

    assert result == {"payload": {"policy_action": "allow"}, "reason_code": None, "route": "native_resident"}
    assert calls == [event]


def test_resident_entrypoint_routes_unknown_event_to_native_in_auto(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class FakeWorker:
        def __init__(self, *, store: object, **_kwargs: object) -> None:
            del store
            del _kwargs

        def review_http_payload(self, *, payload: dict[str, object], **_kwargs: object) -> dict[str, object]:
            calls.append(str(payload.get("hook_event_name")))
            return {"policy_action": "review"}

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.HookWorker",
        FakeWorker,
    )
    monkeypatch.setattr(hook_process_entrypoint, "_current_decision_route", lambda: "native_resident")
    monkeypatch.setattr(
        hook_process_entrypoint,
        "_run_guard_hook_command",
        lambda *_args, **_kwargs: pytest.fail("unknown event escaped to compatibility CLI"),
        raising=False,
    )
    guard_home = tmp_path / "guard-home"
    result = hook_process_entrypoint._run_resident_hook_request(
        {
            "payload": {"hook_event_name": "UnknownEvent", "tool_input": {"command": "pwd"}},
            "harness": "codex",
            "home_dir": str(tmp_path / "home"),
            "guard_home": str(guard_home),
            "workspace": str(tmp_path / "workspace"),
        },
        stores={},
        hook_workers={},
        configured_guard_home=str(guard_home),
    )

    assert result == {"payload": {"policy_action": "review"}, "reason_code": None, "route": "native_resident"}
    assert calls == ["UnknownEvent"]


def test_supported_cli_pretool_unavailability_does_not_use_source_ref_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted: list[dict[str, object]] = []
    monkeypatch.setattr(commands_hook_native_authority, "_native_mode_requires_rust", lambda: True)
    monkeypatch.setattr(
        commands_hook_native_authority,
        "try_native_hook_authority",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        commands_hook_native_authority,
        "_emit",
        lambda _kind, payload, _json: emitted.append(payload),
    )
    guard_home = tmp_path / "guard-home"
    result = commands_hook_native_authority.route_native_hook(
        argparse.Namespace(harness="codex", json=True),
        config=None,
        context=HarnessContext(tmp_path / "home", tmp_path / "workspace", guard_home),
        payload={"hook_event_name": "PreToolUse", "tool_input": {"url": "https://example.test"}},
        runtime_workspace=tmp_path / "workspace",
        store=GuardStore(guard_home),
    )
    assert result == 0
    assert emitted[0]["reason_code"] == "native_hook_worker_unavailable"


def test_supported_cli_pretool_worker_exception_is_fail_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenWorker:
        def __init__(self, *, store: object, **_kwargs: object) -> None:
            del store
            del _kwargs

        def review_http_payload(self, **_kwargs: object) -> dict[str, object]:
            raise RuntimeError("worker fixture failure")

    monkeypatch.setattr(commands_hook_native_authority, "_native_mode_requires_rust", lambda: True)
    monkeypatch.setattr(commands_hook_native_authority, "HookWorker", BrokenWorker)
    response = commands_hook_native_authority.try_native_hook_authority(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"url": "https://example.test"}},
        harness="codex",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        store=GuardStore(tmp_path / "guard-home"),
    )
    assert isinstance(response, dict)
    assert response["reason_code"] == "native_hook_worker_exception"
    assert response["policy_action"] == "block"
    output = response["hookSpecificOutput"]
    assert isinstance(output, dict)
    assert output["permissionDecision"] == "deny"


def test_cli_frames_raw_payload_before_harness_normalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_payload: dict[str, object] = {
        "event": "beforeShellExecution",
        "command": "npm test",
        "toolInput": {"command": "npm test"},
    }
    context = HarnessContext(tmp_path / "home", tmp_path / "workspace", tmp_path / "guard-home")
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    args = argparse.Namespace(harness="cursor", runtime_harness=None, event_file=None, json=True)
    seen: dict[str, object] = {}

    monkeypatch.setattr(commands_hook, "_require_guard_context", lambda _value: context)
    monkeypatch.setattr(commands_hook, "_require_guard_store", lambda _value: store)
    monkeypatch.setattr(commands_hook, "_require_guard_config", lambda _value: config)

    def load_payload(*_args: object, **kwargs: object) -> dict[str, object]:
        assert kwargs["normalize"] is False
        return raw_payload

    def route_native(*_args: object, **kwargs: object) -> int:
        seen["payload"] = kwargs["payload"]
        return 17

    monkeypatch.setattr(commands_hook, "_load_hook_payload", load_payload)
    monkeypatch.setattr(commands_hook, "route_native_hook", route_native)
    monkeypatch.setattr(
        commands_hook,
        "_normalize_hook_payload",
        lambda *_args, **_kwargs: pytest.fail("harness normalization preceded native framing"),
    )

    result = commands_hook._run_guard_hook_command(
        args,
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        context=context,
        store=store,
        config=config,
        input_text='{"event":"beforeShellExecution"}',
    )

    assert result == 17
    assert seen == {"payload": raw_payload}


def test_cli_native_route_keeps_referenced_duplicate_bytes_opaque(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_referenced_payload = b'{"command":"pwd","command":"whoami"}'
    with tempfile.TemporaryDirectory(prefix="hol-guard-hook-payload-") as reference_dir:
        reference_path = Path(reference_dir) / "payload.json"
        reference_path.write_bytes(raw_referenced_payload)
        referenced_payload: dict[str, object] = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "guard_payload_ref": {
                "version": 1,
                "path": str(reference_path),
                "sha256": hashlib.sha256(raw_referenced_payload).hexdigest(),
                "encoding": "json",
            },
        }
        context = HarnessContext(tmp_path / "home", tmp_path / "workspace", tmp_path / "guard-home")
        store = GuardStore(context.guard_home)
        config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
        args = argparse.Namespace(harness="codex", runtime_harness=None, event_file=None, json=True)
        seen: dict[str, object] = {}

        monkeypatch.setattr(commands_hook, "_require_guard_context", lambda _value: context)
        monkeypatch.setattr(commands_hook, "_require_guard_store", lambda _value: store)
        monkeypatch.setattr(commands_hook, "_require_guard_config", lambda _value: config)

        def route_native(*_args: object, **kwargs: object) -> int:
            payload = kwargs["payload"]
            assert isinstance(payload, dict)
            seen.update(payload)
            return 17

        monkeypatch.setattr(commands_hook, "route_native_hook", route_native)

        result = commands_hook._run_guard_hook_command(
            args,
            guard_home=context.guard_home,
            workspace=context.workspace_dir,
            context=context,
            store=store,
            config=config,
            input_text=json.dumps(referenced_payload),
        )
        assert reference_path.read_bytes() == raw_referenced_payload

    assert result == 17
    assert seen == referenced_payload
