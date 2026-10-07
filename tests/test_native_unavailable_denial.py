"""Protected native-worker requests cannot become allows after evaluation fails."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize("harness", ["codex", "claude-code", "copilot", "cursor", "pi", "omp", "zcode", "grok"])
@pytest.mark.parametrize("watch", [False, True])
def test_native_worker_unavailable_preserves_explicit_protection_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: str, watch: bool
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    config = guard_home / "config.toml"
    config_bytes = (
        b'mode = "observe"\nprotection_posture = "watch"\n'
        if watch
        else b'mode = "enforce"\nprotection_posture = "protected"\n'
    )
    config.write_bytes(config_bytes)
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "auto")
    # The stub bypasses the transport that normally replaces each request's
    # failure code. Do not inherit a previous request's control-binding error.
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker_native.native_resident_client_failure_code",
        lambda: "native_client_process_failed",
    )
    observed_modes: list[bool] = []

    def unavailable_native(**kwargs):
        observed_modes.append(kwargs["observe_mode"])
        return None

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native", unavailable_native)
    worker = HookWorker(store=GuardStore(guard_home))
    monkeypatch.setattr(
        worker,
        "_native_policy_snapshot",
        lambda _workspace, **_kwargs: {"mode": "observe" if watch else "enforce"},
    )
    try:
        response = worker.review_http_payload(
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "printf fixture > output.txt"},
            },
            params={},
            default_harness=harness,
            home_dir=tmp_path / "home",
            guard_home=guard_home,
            workspace=tmp_path / "workspace",
        )
    finally:
        worker.close()
    assert config.read_bytes() == config_bytes
    assert observed_modes == [watch]
    assert response["reason_code"] == "native_pre_tool_unavailable"
    specific = response.get("hookSpecificOutput", {})
    assert isinstance(specific, dict)
    decision = response.get("decision", specific.get("permissionDecision"))
    assert decision == ("allow" if watch else "deny")


def test_missing_mode_authority_does_not_infer_watch_from_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    config = guard_home / "config.toml"
    config_bytes = b'mode = "observe"\nprotection_posture = "watch"\n'
    config.write_bytes(config_bytes)
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "auto")
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native", lambda **_kwargs: None)
    worker = HookWorker(store=GuardStore(guard_home))
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda *_args, **_kwargs: None)
    try:
        response = worker.review_http_payload(
            payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "printf fixture > output.txt"}},
            params={},
            default_harness="codex",
            home_dir=tmp_path / "home",
            guard_home=guard_home,
            workspace=tmp_path / "workspace",
        )
    finally:
        worker.close()
    assert config.read_bytes() == config_bytes
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
