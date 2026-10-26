"""A guarded MCP tools/call writes and reads through one fused resident exchange."""

from __future__ import annotations

import collections
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_execution
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy
from codex_plugin_scanner.guard.proxy import native_mcp_child_io as native_child_io_module
from codex_plugin_scanner.guard.proxy import runtime_mcp as runtime_mcp_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_runtime_mcp_saved_blocks import _child_command, _context, _messages

pytestmark = [pytest.mark.usefixtures("bundle_first_cloud"), pytest.mark.usefixtures("package_intent_native")]

_LIST_CHANGED = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {}}


def _proxy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_mcp_probe) -> tuple[CodexMcpGuardProxy, Path]:
    context = _context(tmp_path)
    native_mcp_probe(context.guard_home)
    marker = tmp_path / "marker.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(marker),
        context=context,
        store=GuardStore(context.guard_home),
        config=GuardConfig(
            mode="enforce",
            default_action="allow",
            guard_home=context.guard_home,
            workspace=context.workspace_dir,
        ),
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(proxy, "_maybe_open_approval_center", lambda **_kwargs: None)
    return proxy, marker


def _call_messages() -> list[dict[str, object]]:
    return _messages(tool_name="safe_echo", arguments={"value": "hello"}, elicitation=False)


def test_guarded_call_spends_one_stdio_send_and_one_poll(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_mcp_probe
) -> None:
    proxy, _marker = _proxy(tmp_path, monkeypatch, native_mcp_probe)
    operations: collections.Counter[str] = collections.Counter()
    real = native_execution.native_resident_client_request

    def spy(**kwargs):
        operations[json.loads(kwargs["payload"])["operation"]] += 1
        return real(**kwargs)

    monkeypatch.setattr(native_execution, "native_resident_client_request", spy)
    messages = _call_messages()
    proxy.run_session(messages[:2])
    setup = collections.Counter(operations)
    operations.clear()
    result = proxy.run_session(messages)
    assert "result" in result["responses"][2], result["responses"][2]
    spent = operations - setup
    # One catalog poll before the decision and one fused quiet edge, write and read.
    assert spent["mcp_stdio_session_send"] <= 1, dict(spent)
    assert spent["mcp_stdio_session_recv"] <= 1, dict(spent)


def test_frame_during_the_quiet_edge_blocks_the_call_before_it_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_mcp_probe
) -> None:
    proxy, marker = _proxy(tmp_path, monkeypatch, native_mcp_probe)
    seen: list[str] = []

    def boundary(session_id, message, **_kwargs):
        seen.append(str(message["method"]))
        return {"outcome": "boundary", "written": False, "event_kind": "child_notification", "frame": _LIST_CHANGED}

    monkeypatch.setattr(native_child_io_module, "mcp_stdio_session_exchange_native", boundary)
    result = proxy.run_session(_call_messages())
    assert seen == ["tools/call"]
    assert marker.exists() is False
    assert "error" in result["responses"][2]
    assert result["responses"][2]["error"]["data"]["transportOutcome"] == "not-forwarded"
    assert result["events"][2]["policy_action"] == "require-reapproval"
    assert proxy._tool_catalog_state == "invalidated"


def test_silent_child_after_the_write_times_out_like_a_separate_recv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_mcp_probe
) -> None:
    proxy, marker = _proxy(tmp_path, monkeypatch, native_mcp_probe)
    monkeypatch.setattr(
        native_child_io_module,
        "mcp_stdio_session_exchange_native",
        lambda *_args, **_kwargs: {"outcome": "timeout", "written": True},
    )
    result = proxy.run_session(_call_messages())
    assert marker.exists() is False
    assert "timed out" in json.dumps(result["responses"][2])


def test_unusable_exchange_answer_fails_the_call_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_mcp_probe
) -> None:
    proxy, marker = _proxy(tmp_path, monkeypatch, native_mcp_probe)
    monkeypatch.setattr(native_child_io_module, "mcp_stdio_session_exchange_native", lambda *_a, **_k: None)
    with pytest.raises(RuntimeError, match="exchange failed"):
        proxy.run_session(_call_messages())
    assert marker.exists() is False


def test_malformed_outcome_counts_a_failure_not_a_streak_reset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import types

    from codex_plugin_scanner.guard import native_mcp_stdio_exchange

    captured: dict[str, object] = {}

    def fake_request(**kwargs):
        captured.update(kwargs)
        return {"status": "sent", "payload": {"outcome": "gibberish"}}

    identity = types.SimpleNamespace(sha256="identity-hash")
    monkeypatch.setattr(native_mcp_stdio_exchange, "_resident_request", fake_request)
    monkeypatch.setattr(
        native_mcp_stdio_exchange,
        "native_runtime_status",
        lambda: types.SimpleNamespace(identity=identity),
    )
    failures: list[dict[str, object]] = []
    successes: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        native_mcp_stdio_exchange,
        "native_record_resident_failure",
        lambda *_a, **k: failures.append(k),
    )
    monkeypatch.setattr(
        native_mcp_stdio_exchange,
        "native_record_resident_success",
        lambda *a: successes.append(a),
    )

    answer = native_mcp_stdio_exchange.mcp_stdio_session_exchange_native(
        "sess-1",
        {"id": 1, "method": "tools/call"},
        guard_home=tmp_path,
        quiet_seconds=0.005,
        response_timeout_seconds=30.0,
    )

    assert answer is None
    assert failures == [{"reason": "native_mcp_stdio_exchange_unusable"}]
    assert successes == []
    # Quiet + quiet extension + write window + response + transport margin.
    assert captured["timeout_seconds"] == 0.005 + 1.0 + 5.0 + 30.0 + 2.0
    assert captured["record_success"] is False


def test_unknown_outcome_and_good_outcome_record_health_appropriately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import types

    from codex_plugin_scanner.guard import native_mcp_stdio_exchange

    replies = iter(
        [
            {"status": "sent", "payload": {"outcome": "response", "written": True, "frame": {"id": 1}}},
            {"status": "error", "payload": "child_write_failed"},
        ]
    )
    monkeypatch.setattr(native_mcp_stdio_exchange, "_resident_request", lambda **_: next(replies))
    monkeypatch.setattr(
        native_mcp_stdio_exchange,
        "native_runtime_status",
        lambda: types.SimpleNamespace(identity=types.SimpleNamespace(sha256="h")),
    )
    successes: list[tuple[object, ...]] = []
    failures: list[dict[str, object]] = []
    monkeypatch.setattr(native_mcp_stdio_exchange, "native_record_resident_success", lambda *a: successes.append(a))
    monkeypatch.setattr(
        native_mcp_stdio_exchange, "native_record_resident_failure", lambda *_a, **k: failures.append(k)
    )

    good = native_mcp_stdio_exchange.mcp_stdio_session_exchange_native(
        "s", {}, guard_home=tmp_path, quiet_seconds=0.0, response_timeout_seconds=1.0
    )
    refused = native_mcp_stdio_exchange.mcp_stdio_session_exchange_native(
        "s", {}, guard_home=tmp_path, quiet_seconds=0.0, response_timeout_seconds=1.0
    )
    assert good == {"outcome": "response", "written": True, "frame": {"id": 1}}
    assert refused is None
    assert len(successes) == 2  # usable outcome and bound refusal both answer
    assert failures == []
