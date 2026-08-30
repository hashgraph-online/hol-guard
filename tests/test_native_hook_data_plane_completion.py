from __future__ import annotations

import ast
import json
from pathlib import Path

from codex_plugin_scanner.guard.config import hook_fast_path_enabled
from codex_plugin_scanner.guard.native_runtime import native_mode

ROOT = Path(__file__).resolve().parents[1]


def _source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _function(relative: str, name: str) -> str:
    source = _source(relative)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            segment = ast.get_source_segment(source, node)
            assert segment is not None
            return segment
    raise AssertionError(f"missing function {relative}:{name}")


def test_no_environment_configuration_selects_native_fast_path(monkeypatch) -> None:
    monkeypatch.delenv("HOL_GUARD_NATIVE", raising=False)
    monkeypatch.delenv("HOL_GUARD_NATIVE_BINARY", raising=False)
    monkeypatch.delenv("HOL_GUARD_HOOK_FAST_PATH", raising=False)

    assert native_mode() == "auto"
    assert hook_fast_path_enabled() is True


def test_daemon_default_path_uses_raw_native_edge_without_python_semantics() -> None:
    path = "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
    production = _function(path, "review_http_payload")
    compatibility = _function(path, "_review_explicit_python_compatibility")

    assert 'mode in {"off", "shadow"}' in production
    assert "review_hook_edge_native" in production
    assert "self.engine.review(" not in production
    assert "_request_from_payload(" not in production
    assert "HookWorkerUnsupported" not in production

    assert "self.engine.review(" in compatibility
    assert 'event_name != "PostToolUse"' in compatibility


def test_cli_source_ref_reference_path_is_explicit_compatibility_only() -> None:
    path = "src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py"
    native = _function(path, "try_native_hook_authority")
    route = _function(path, "try_native_or_source_ref_hook")

    assert 'native_mode() not in {"auto", "force"}' in native
    assert "HookWorker(store=store).review_http_payload(" in native
    assert "except" not in native
    assert "_try_source_ref_fast_path" in route
    assert "native_result is not None" in route


def test_production_resident_send_delegates_client_protocol_to_rust() -> None:
    source = _source("src/codex_plugin_scanner/guard/native_runtime_resident.py")
    class_start = source.index("class _ResidentService:")
    send_start = source.index("    def _send(", class_start)
    send_end = source.index("\n    def _ensure_started(", send_start)
    send = source[send_start:send_end]

    assert "resident-client" in send
    assert "run_isolated_hook_process" in send
    assert "_send_authenticated_unix_request" not in send
    assert "_send_authenticated_loopback_request" not in send
    assert "socket.create_connection" not in send


def test_ownership_manifest_requires_rust_default_and_explicit_compatibility() -> None:
    manifest = json.loads(_source("ci/rust-authority-ownership.v1.json"))
    assert manifest["default_runtime_contract"] == {
        "native_mode_without_environment": "auto",
        "hook_fast_path_without_environment": True,
        "path_runtime_search": False,
        "decision_time_runtime_download": False,
        "automatic_python_semantic_fallback": False,
    }
    assert manifest["explicit_compatibility"] == {
        "modes": ["off", "shadow"],
        "python_reference_evaluator": True,
        "automatic_entry_from_native_failure": False,
        "default_selected": False,
    }
    surfaces = manifest["surfaces"]
    assert surfaces["hook_edge"]["event_and_action_extraction"] == "rust"
    assert surfaces["hook_edge"]["python_semantic_envelope_parsing"] is False
    assert surfaces["resident_client"]["authentication"] == "rust"
    assert surfaces["resident_client"]["framing"] == "rust"
    assert surfaces["resident_client"]["socket_io"] == "rust"
    assert set(surfaces["decision_critical_io"].values()) == {"rust"}


def test_runtime_source_exposes_native_hook_edge_and_resident_client() -> None:
    runtime = _source("rust/crates/guard-runtime/src/main.rs")
    oneshot = _source("rust/crates/guard-runtime/src/oneshot.rs")
    client = _source("rust/crates/guard-runtime/src/resident_client.rs")

    assert '"hook-edge-v2"' in runtime
    assert '"resident-client-v1"' in runtime
    assert 'command == "hook-edge"' in runtime
    assert 'command == "resident-client"' in runtime
    assert "evaluate_hook_edge_value" in oneshot
    assert "native_pre_tool_unsupported_review" in oneshot
    assert "REQUEST_MAGIC" in client
    assert "RESPONSE_MAGIC" in client
