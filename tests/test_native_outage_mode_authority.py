"""CLI and capacity failures use authenticated mode authority, never local edits."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook_native_authority as cli
from codex_plugin_scanner.guard.daemon import server as daemon
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_policy_snapshot import native_policy_snapshot_v3
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _config
from .test_native_policy_snapshot_cache_binding import _write_resident_authority


@pytest.mark.parametrize("state", ["observe", "enforce", "missing", "expired", "tampered"])
@pytest.mark.parametrize(
    "failure", ["worker_exception", "worker_none", "capacity", "disabled_legacy_path", "cli_disabled"]
)
def test_outage_mode_requires_authenticated_unexpired_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str, failure: str
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    # The local edit always asks for Watch. Only the signed authority may allow it.
    (guard_home / "config.toml").write_text('mode = "observe"\nprotection_posture = "watch"\n', encoding="utf-8")
    master = b"m" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "test-key"))
    if state != "missing":
        config = _config()
        watch = state in {"observe", "expired"}
        config.update(mode="observe" if watch else "enforce")
        config.update(protection_posture="watch" if watch else "protected")
        now_ms = int(time.time() * 1_000)
        snapshot = native_policy_snapshot_v3(
            config=config,
            guard_home=guard_home,
            runtime_identity="a" * 64,
            rule_digest="b" * 64,
            policy_integrity_key=master,
            issued_at_ms=now_ms - 60_000,
            expires_at_ms=now_ms - 1 if state == "expired" else now_ms + 60_000,
        )
        if state == "tampered":
            snapshot["mode"] = "observe"
        _write_resident_authority(guard_home, snapshot, master)
    payload = {"hook_event_name": "PreToolUse", "tool_input": {"command": "printf fixture > output.txt"}}
    if failure == "disabled_legacy_path":
        worker = HookWorker(store=store, wait_for_native_policy=False, publish_native_policy=False)
        monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker_native.native_mode", lambda: "off")
        try:
            response = worker._review_pre_tool_http(
                payload,
                harness="codex",
                home_dir=tmp_path / "home",
                guard_home=guard_home,
                workspace=None,
            )
        finally:
            worker.close()
    elif failure == "capacity":
        handler = object.__new__(daemon._GuardDaemonHandler)
        handler.server = Mock(store=store)
        monkeypatch.setattr(handler, "_validated_fail_safe_hook_paths", lambda _params: (None, None))
        response = handler._runtime_hook_capacity_response(
            payload, {}, default_harness="codex", native_authoritative=True
        )
    else:
        worker = Mock()
        if failure == "worker_exception":
            worker.review_http_payload.side_effect = RuntimeError("injected unavailable native worker")
        else:
            worker.review_http_payload.return_value = None
        monkeypatch.setattr(cli, "HookWorker", lambda **_kwargs: worker)
        monkeypatch.setattr(cli, "_native_mode_requires_rust", lambda: failure != "cli_disabled")
        responses = []
        monkeypatch.setattr(cli, "_emit", lambda _name, value, _json: responses.append(value))
        if failure == "worker_exception":
            response = cli.try_native_hook_authority(
                payload=payload,
                harness="codex",
                home_dir=tmp_path / "home",
                guard_home=guard_home,
                workspace=None,
                store=store,
            )
        monkeypatch.setattr(
            cli,
            "try_native_hook_authority",
            lambda **_kwargs: response if failure == "worker_exception" else None,
        )
        status = cli.route_native_hook(
            Mock(harness="codex", json=True),
            config=None,
            context=HarnessContext(home_dir=tmp_path / "home", guard_home=guard_home, workspace_dir=None),
            payload=payload,
            runtime_workspace=None,
            store=store,
        )
        assert status == 0
        assert len(responses) == 1
        response = responses[0]
    assert response["hookSpecificOutput"]["permissionDecision"] == (
        "allow" if state == "observe" and failure not in {"disabled_legacy_path", "cli_disabled"} else "deny"
    )
