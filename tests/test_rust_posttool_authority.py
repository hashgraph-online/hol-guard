"""Tests for Rust PostToolUse authority fail-closed daemon behavior."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_hook_native_authority import try_native_hook_authority
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeStatus
from codex_plugin_scanner.guard.store import GuardStore


def _post_tool_payload() -> dict[str, object]:
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/foo.ts"},
        "tool_response": [{"type": "text", "text": "export const value = 1;\n"}],
    }


def test_hook_worker_fails_closed_when_forced_posttool_native_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_post_tool_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "force",
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload=_post_tool_payload(),
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "deny"
    assert result["reason_code"] == "native_post_tool_unavailable"


def test_hook_worker_fails_closed_when_available_native_posttool_returns_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_post_tool_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="auto",
            available=True,
            compatible=True,
            reason="ok",
        ),
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload=_post_tool_payload(),
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "deny"
    assert result["reason_code"] == "native_post_tool_unavailable"


def test_hook_worker_fails_closed_when_auto_native_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = {"native": 0}

    def _missing_native(*_args: object, **_kwargs: object) -> None:
        called["native"] += 1
        return None

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        _missing_native,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
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
        payload=_post_tool_payload(),
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert called["native"] == 1
    assert result["decision"] == "deny"
    assert result["reason_code"] == "native_post_tool_unavailable"


class _ActivityWriter:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def submit_command_activity(
        self,
        *,
        harness: str,
        event: str,
        payload: object,
        succeeded: bool,
    ) -> bool:
        self.calls.append({"harness": harness, "event": event, "payload": payload, "succeeded": succeeded})
        return True


def test_hook_worker_records_activity_when_auto_native_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_post_tool_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    writer = _ActivityWriter()
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"), activity_writer=writer)
    result = worker.review_http_payload(
        payload=_post_tool_payload(),
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["reason_code"] == "native_post_tool_unavailable"
    assert worker._engine is None
    assert len(writer.calls) == 1
    assert writer.calls[0]["event"] == "PostToolUse"
    assert writer.calls[0]["harness"] == "pi"


def test_cli_auto_posttool_uses_native_worker_not_python_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_hook_native_authority.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_post_tool_native",
        lambda *_args, **_kwargs: None,
    )
    result = try_native_hook_authority(
        payload=_post_tool_payload(),
        harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        store=GuardStore(tmp_path / "guard-home"),
    )
    assert result is not None
    assert result["reason_code"] == "native_post_tool_unavailable"


def test_cli_off_mode_leaves_python_source_ref_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_hook_native_authority.native_mode",
        lambda: "off",
    )
    result = try_native_hook_authority(
        payload=_post_tool_payload(),
        harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        store=GuardStore(tmp_path / "guard-home"),
    )
    assert result is None


def test_native_policy_snapshot_generation_is_stable_for_same_policy(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.native_policy_snapshot import native_policy_snapshot

    digest = "a" * 64
    first = native_policy_snapshot(guard_home=tmp_path, rule_digest=digest, observe_mode=False)
    second = native_policy_snapshot(guard_home=tmp_path, rule_digest=digest, observe_mode=False)
    assert first["generation"] == second["generation"]
    assert isinstance(first["generation"], int)


def test_native_policy_snapshot_generation_advances_when_mode_changes(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.native_policy_snapshot import native_policy_snapshot

    digest = "a" * 64
    enforce = native_policy_snapshot(guard_home=tmp_path, rule_digest=digest, observe_mode=False)
    observe = native_policy_snapshot(guard_home=tmp_path, rule_digest=digest, observe_mode=True)
    restored = native_policy_snapshot(guard_home=tmp_path, rule_digest=digest, observe_mode=False)
    enforce_generation = enforce["generation"]
    observe_generation = observe["generation"]
    restored_generation = restored["generation"]
    assert isinstance(enforce_generation, int)
    assert isinstance(observe_generation, int)
    assert isinstance(restored_generation, int)
    assert observe_generation > enforce_generation
    assert restored_generation > observe_generation


def test_native_policy_snapshot_generation_is_shared_across_processes(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    script = (
        "import json,sys; from pathlib import Path; "
        "from codex_plugin_scanner.guard.native_policy_snapshot import native_policy_snapshot; "
        "print(json.dumps(native_policy_snapshot(rule_digest='a'*64, "
        "observe_mode=sys.argv[2]=='observe', guard_home=Path(sys.argv[1]))['generation']))"
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")

    def generation(mode: str) -> int:
        output = subprocess.check_output(
            [sys.executable, "-c", script, str(guard_home), mode],
            env=environment,
            text=True,
        )
        value = json.loads(output)
        assert isinstance(value, int) and not isinstance(value, bool)
        return value

    first = generation("enforce")
    assert generation("enforce") == first
    observe = generation("observe")
    restored = generation("enforce")
    assert observe > first
    assert restored > observe


def test_native_policy_snapshot_rejects_corrupt_shared_generation(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.native_policy_snapshot import (
        NativePolicySnapshotError,
        native_policy_snapshot,
    )

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "native-policy-generation.json").write_text("{}", encoding="utf-8")
    with pytest.raises(NativePolicySnapshotError, match="native_policy_generation_state_invalid"):
        native_policy_snapshot(rule_digest="a" * 64, observe_mode=False, guard_home=guard_home)
