"""Tests for Rust PreToolUse authority transport and daemon fail-closed behavior."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker, HookWorkerUnsupported
from codex_plugin_scanner.guard.native_pretool import (
    _decode_pre_tool,
    native_pre_tool_policy_floor,
    review_pre_tool_native,
)
from codex_plugin_scanner.guard.native_route_receipt import (
    native_hook_route,
    record_native_hook_route,
    reset_native_hook_route,
)
from codex_plugin_scanner.guard.native_runtime import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
)
from codex_plugin_scanner.guard.store import GuardStore


def _native_allow(command: str) -> dict[str, Any]:
    return {
        "authority": "rust",
        "decision": "allow",
        "minimum_action": "allow",
        "policy_action": "allow",
        "reason_code": "native_exact_safe_command",
        "reason": "The Rust command authority proved this bounded command explicitly benign.",
        "explicitly_benign": True,
        "command_model": {"normalized_text": command},
    }


def _native_block(command: str) -> dict[str, Any]:
    return {
        "authority": "rust",
        "decision": "deny",
        "minimum_action": "block",
        "policy_action": "block",
        "reason_code": "native_destructive_command",
        "reason": "HOL Guard blocked a destructive command before execution.",
        "explicitly_benign": False,
        "command_model": {"normalized_text": command},
    }


def test_decode_pre_tool_rejects_unbound_command_model() -> None:
    payload = _native_allow("pwd")
    payload["command_model"] = {"normalized_text": "whoami"}
    assert _decode_pre_tool(payload, command="pwd") is None


def test_unavailable_native_pretool_records_fail_safe_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="force",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    reset_native_hook_route()

    assert (
        review_pre_tool_native(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )
    assert native_hook_route() == "native_fail_safe"


def test_missing_pretool_feature_records_fail_safe_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"runtime")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="auto",
            available=True,
            compatible=True,
            reason="ready",
            identity=NativeRuntimeIdentity(
                path=runtime,
                size=runtime.stat().st_size,
                mtime_ns=runtime.stat().st_mtime_ns,
                sha256="0" * 64,
            ),
            capabilities=NativeRuntimeCapabilities(
                protocol_version=2,
                runtime_version="test",
                rule_digest="1" * 64,
                build_sha="2" * 40,
                target="test",
                features=("resident-protocol-v2",),
            ),
        ),
    )
    reset_native_hook_route()

    assert (
        review_pre_tool_native(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )
    assert native_hook_route() == "native_fail_safe"


def test_policy_floor_uses_native_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.review_pre_tool_native",
        lambda *_args, **_kwargs: _native_block("rm -rf /"),
    )
    assert (
        native_pre_tool_policy_floor(
            "rm -rf /",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        == "block"
    )


def test_policy_floor_defers_contextual_git_helper_review_to_python(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native_review = _native_block("git diff --check")
    native_review.update(
        {
            "decision": "deny",
            "minimum_action": "review",
            "policy_action": "review",
            "reason_code": "native_git_helper_context_review",
        }
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.review_pre_tool_native",
        lambda *_args, **_kwargs: native_review,
    )

    assert (
        native_pre_tool_policy_floor(
            "git diff --check",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


def test_policy_floor_fails_closed_when_native_is_forced_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.review_pre_tool_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="force",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    assert (
        native_pre_tool_policy_floor(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        == "block"
    )


def test_policy_floor_skips_when_native_mode_is_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.review_pre_tool_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: NativeRuntimeStatus(mode="off", available=True, compatible=True, reason="off"),
    )
    assert (
        native_pre_tool_policy_floor(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


def test_hook_worker_returns_native_allow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_pre_tool_native",
        lambda *_args, **_kwargs: _native_allow("pwd"),
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
        params={},
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["policy_action"] == "allow"
    assert result["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_hook_worker_clears_native_route_before_python_review_continuation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native_review = _native_block("git push")
    native_review["minimum_action"] = "review"
    native_review["policy_action"] = "review"

    def review_with_resident_receipt(*_args: object, **_kwargs: object) -> dict[str, Any]:
        record_native_hook_route("native_resident")
        return native_review

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_pre_tool_native",
        review_with_resident_receipt,
    )
    reset_native_hook_route()
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))

    with pytest.raises(HookWorkerUnsupported, match="CLI approval coordination"):
        worker.review_http_payload(
            payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "git push"}},
            params={},
            default_harness="codex",
            home_dir=tmp_path / "home",
            guard_home=tmp_path / "guard-home",
            workspace=tmp_path / "workspace",
        )

    assert native_hook_route() == "python_semantic"


def test_full_cli_review_continuation_keeps_python_terminal_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    home = tmp_path / "home"
    workspace.mkdir()
    home.mkdir()
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=workspace, default_action="review")
    native_review = _native_block("git push")
    native_review["minimum_action"] = "review"
    native_review["policy_action"] = "review"

    def review_with_resident_receipt(*_args: object, **_kwargs: object) -> dict[str, Any]:
        record_native_hook_route("native_resident")
        return native_review

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_pre_tool_native",
        review_with_resident_receipt,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.review_pre_tool_native",
        review_with_resident_receipt,
    )
    reset_native_hook_route()

    result = commands_hook._run_guard_hook_command(
        argparse.Namespace(
            artifact_id=None,
            artifact_name=None,
            event_file=None,
            harness="codex",
            json=True,
            policy_action=None,
            runtime_harness=None,
        ),
        guard_home=guard_home,
        workspace=workspace,
        context=HarnessContext(home, workspace, guard_home),
        store=store,
        config=config,
        input_text=json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git push"},
            }
        ),
        output_stream=io.StringIO(),
    )

    assert result == 0
    assert native_hook_route() == "python_semantic"


def test_hook_worker_fails_closed_when_forced_native_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "force",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="force",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "deny"
    assert result["reason_code"] == "native_pre_tool_unavailable"


def test_hook_worker_fails_closed_when_auto_pretool_native_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="auto",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "deny"
    assert result["reason_code"] == "native_pre_tool_unavailable"


def test_hook_worker_falls_back_when_native_mode_is_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "off",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_pre_tool_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_runtime_status",
        lambda: NativeRuntimeStatus(mode="off", available=True, compatible=True, reason="off"),
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    with pytest.raises(HookWorkerUnsupported, match="native PreToolUse runtime is off"):
        worker.review_http_payload(
            payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
            params={},
            default_harness="pi",
            home_dir=tmp_path / "home",
            guard_home=tmp_path / "guard-home",
            workspace=tmp_path / "workspace",
        )


def test_hook_worker_fails_closed_for_non_command_pretool_without_native_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "src/foo.ts"}},
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "deny"
    assert result["reason_code"] == "native_pre_tool_unavailable"


def test_hook_worker_leaves_out_of_scope_events_to_existing_handling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: pytest.fail("out-of-scope event reached the native edge"),
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    with pytest.raises(HookWorkerUnsupported, match="fast path supports"):
        worker.review_http_payload(
            payload={"hook_event_name": "PermissionRequest", "tool_input": {"command": "pwd"}},
            params={},
            default_harness="claude-code",
            home_dir=tmp_path / "home",
            guard_home=tmp_path / "guard-home",
            workspace=tmp_path / "workspace",
        )
