"""Tests for Rust PostToolUse authority fail-closed daemon behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_hook_native_authority import try_native_hook_authority
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore


def _post_tool_payload() -> dict[str, object]:
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/foo.ts"},
        "tool_response": [{"type": "text", "text": "export const value = 1;\n"}],
    }


def _force_auto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "auto")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_hook_native_authority.native_mode",
        lambda: "auto",
    )


def test_hook_worker_fails_closed_when_native_hook_edge_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_auto(monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_hook_edge_native",
        lambda **_kwargs: None,
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
    assert result["reason_code"] == "native_hook_edge_unavailable"


def test_hook_worker_fails_closed_when_native_hook_edge_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_auto(monkeypatch)

    def broken_edge(**_kwargs: object) -> None:
        raise RuntimeError("native transport failed")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_hook_edge_native",
        broken_edge,
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
    assert result["reason_code"] == "native_hook_edge_unavailable"


def test_hook_worker_calls_native_hook_edge_once_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_auto(monkeypatch)
    called = {"native": 0}

    def missing_native(**_kwargs: object) -> None:
        called["native"] += 1
        return None

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_hook_edge_native",
        missing_native,
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
    assert result["reason_code"] == "native_hook_edge_unavailable"


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
        self.calls.append(
            {"harness": harness, "event": event, "payload": payload, "succeeded": succeeded}
        )
        return True


def test_hook_worker_records_activity_when_native_hook_edge_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_auto(monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_hook_edge_native",
        lambda **_kwargs: None,
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
    assert result["reason_code"] == "native_hook_edge_unavailable"
    assert worker._engine is None
    assert len(writer.calls) == 1
    assert writer.calls[0]["event"] == "PostToolUse"
    assert writer.calls[0]["harness"] == "pi"


def test_cli_posttool_uses_native_hook_edge_not_python_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_auto(monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_hook_edge_native",
        lambda **_kwargs: None,
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
    assert result["reason_code"] == "native_hook_edge_unavailable"


def test_cli_explicit_off_selects_compatibility_instead_of_native_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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


def test_native_policy_snapshot_generation_is_stable_for_same_policy() -> None:
    from codex_plugin_scanner.guard.native_policy_snapshot import native_policy_snapshot

    digest = "a" * 64
    first = native_policy_snapshot(rule_digest=digest, observe_mode=False)
    second = native_policy_snapshot(rule_digest=digest, observe_mode=False)
    assert first["generation"] == second["generation"]
    assert isinstance(first["generation"], int)


def test_native_posttool_allow_is_rendered_without_python_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_auto(monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_hook_edge_native",
        lambda **_kwargs: {
            "authority": "rust",
            "event_name": "PostToolUse",
            "decision": "allow",
            "model_output_action": "allow_original",
            "notice": "none",
            "reason_code": "output_scan_allow",
        },
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload=_post_tool_payload(),
        params={},
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result == {
        "policy_action": "allow",
        "reason_code": "output_scan_allow",
        "hookSpecificOutput": {"hookEventName": "PostToolUse"},
    }
