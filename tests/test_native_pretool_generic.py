"""Typed generic PreToolUse result handling at the Python transport edge."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import tempfile
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook, commands_hook_native_authority
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon.hook_fail_closed import render_pre_tool, render_pre_tool_review
from codex_plugin_scanner.guard.daemon.hook_native_exact_action import native_exact_action
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
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
    rendered = render_pre_tool("grok", result)
    assert rendered["decision"] == "allow"
    hook_specific = rendered["hookSpecificOutput"]
    assert isinstance(hook_specific, dict)
    assert hook_specific["permissionDecision"] == "allow"


def test_generic_review_result_renders_grok_deny_decision() -> None:
    edge = _edge("grok", "PreToolUse")
    result = edge["result"]
    assert isinstance(result, dict)
    rendered = render_pre_tool("grok", result)
    assert rendered["decision"] == "deny"
    hook_specific = rendered["hookSpecificOutput"]
    assert isinstance(hook_specific, dict)
    assert hook_specific["permissionDecision"] == "deny"


def test_generic_review_result_renders_grok_review_decision_with_approval() -> None:
    edge = _edge("grok", "PreToolUse")
    result = edge["result"]
    assert isinstance(result, dict)
    rendered = render_pre_tool_review(
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
    rendered = render_pre_tool("codex", result)
    assert rendered["continue"] is True
    assert rendered["policy_action"] == "warn"
    hook_specific = rendered["hookSpecificOutput"]
    assert isinstance(hook_specific, dict)
    assert hook_specific["permissionDecision"] == "allow"
    assert "permissionDecisionReason" not in hook_specific


@pytest.mark.parametrize("harness", ["claude-code", "codex", "zcode", "omp", "pi", "grok"])
def test_policy_floor_warning_on_proven_allow_is_silent(harness: str) -> None:
    result = {
        "decision": "allow",
        "policy_action": "warn",
        "minimum_action": "warn",
        "reason_code": "native_policy_warning",
        "reason": "HOL Guard raised a non-blocking warning under the installed native policy.",
    }
    rendered = render_pre_tool(harness, result)
    assert rendered["policy_action"] == "warn"
    assert "notice" not in rendered
    assert "reason" not in rendered
    hook_specific = rendered.get("hookSpecificOutput", {})
    assert isinstance(hook_specific, dict)
    assert "permissionDecisionReason" not in hook_specific


@pytest.mark.parametrize(
    ("reason_code", "reason"),
    [
        ("native_risk_warning", "HOL Guard noticed risk signals."),
        ("native_policy_observed_floor", "HOL Guard observed a stricter installed native policy floor."),
    ],
)
def test_intrinsic_and_observed_floor_warnings_still_reach_the_harness(reason_code: str, reason: str) -> None:
    result = {
        "decision": "allow",
        "policy_action": "warn",
        "minimum_action": "warn",
        "reason_code": reason_code,
        "reason": reason,
    }
    omp = render_pre_tool("omp", result)
    assert omp["notice"] == "warning"
    codex = render_pre_tool("codex", result)
    hook_specific = codex["hookSpecificOutput"]
    assert isinstance(hook_specific, dict)
    assert hook_specific["permissionDecisionReason"] == reason


def test_native_review_queues_approval_without_escaping_to_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    edge = _edge("codex", "PreToolUse", "network")
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

    # The approval wait is offered only for a review the agent's retry can match.
    def evidence(**kwargs: Any) -> tuple[str | None, str | None, str | None]:
        return (f"native-review-v4:{'ab' * 32}:ask:review:review:r", *native_exact_action(**kwargs))

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_native_review_approval.native_review_evidence",
        evidence,
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


def test_supported_cli_pretool_unavailability_does_not_use_source_ref_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted: list[dict[str, object]] = []
    monkeypatch.setattr(
        commands_hook_native_authority,
        "try_native_hook_authority",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        commands_hook_native_authority,
        "_emit_native_hook_json_document",
        lambda payload, **_kwargs: emitted.append(payload),
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
    # codex PreToolUse denies via the hookSpecificOutput.permissionDecision
    # envelope; rc stays 0 so codex honors the deny rather than reading the
    # nonzero rc as a hook error and permitting.
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

        def _apply_structured_unavailable_overlay(
            self, response: dict[str, object], **_kwargs: object
        ) -> dict[str, object]:
            return response

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


def test_supported_cli_pretool_worker_exception_is_recorded_in_the_guard_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenWorker:
        def __init__(self, *, store: object, **_kwargs: object) -> None:
            del store
            del _kwargs

        def review_http_payload(self, **_kwargs: object) -> dict[str, object]:
            raise RuntimeError("worker fixture failure")

        def _apply_structured_unavailable_overlay(
            self, response: dict[str, object], **_kwargs: object
        ) -> dict[str, object]:
            return response

    monkeypatch.setattr(commands_hook_native_authority, "HookWorker", BrokenWorker)
    guard_home = tmp_path / "guard-home"
    response = commands_hook_native_authority.try_native_hook_authority(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"url": "https://example.test"}},
        harness="codex",
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace=tmp_path / "workspace",
        store=GuardStore(guard_home),
    )

    assert isinstance(response, dict)
    assert response["reason_code"] == "native_hook_worker_exception"
    record = json.loads((guard_home / "logs" / "daemon.log").read_text(encoding="utf-8").splitlines()[-1])
    assert record["event"] == "native_hook_worker_exception"
    assert record["detail"] == "harness=codex event=PreToolUse"
    assert "worker fixture failure" in record["exception"]
    # The wire response stays free of local detail; the log carries it.
    assert "worker fixture failure" not in json.dumps(response)


def test_supported_cli_pretool_worker_exception_points_stderr_at_the_guard_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A denied tool call the operator cannot explain is a defect of its own.

    The wire document is a fixed deny with no detail, so a bounded line names
    the failure and points at the Guard log. Hook stderr can reach the
    harness, so the exception message and traceback stay out of it.
    """

    class BrokenWorker:
        def __init__(self, *, store: object, **_kwargs: object) -> None:
            del store
            del _kwargs

        def review_http_payload(self, **_kwargs: object) -> dict[str, object]:
            raise RuntimeError("worker fixture failure")

        def _apply_structured_unavailable_overlay(
            self, response: dict[str, object], **_kwargs: object
        ) -> dict[str, object]:
            return response

    monkeypatch.setattr(commands_hook_native_authority, "HookWorker", BrokenWorker)
    with caplog.at_level(logging.WARNING, logger=commands_hook_native_authority.__name__):
        commands_hook_native_authority.try_native_hook_authority(
            payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "git status"}},
            harness="claude-code",
            home_dir=tmp_path / "home",
            guard_home=tmp_path / "guard-home",
            workspace=tmp_path / "workspace",
            store=GuardStore(tmp_path / "guard-home"),
        )
    records = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert records, "the swallowed exception left no trace"
    message = records[0].getMessage()
    assert "RuntimeError" in message
    assert "claude-code" in message
    assert "Guard daemon log" in message
    assert "worker fixture failure" not in message
    assert records[0].exc_info is None


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
