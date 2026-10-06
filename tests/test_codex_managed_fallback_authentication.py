"""Every managed fallback must authenticate even after a signed worker failure."""

from __future__ import annotations

import json
import sys
import threading
import time
from http.server import HTTPServer
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge_flow as flow
from tests.codex_daemon_hook_bridge_fixtures import _DaemonHandler, _write_authenticated_daemon_files


def test_authenticated_worker_failure_cannot_launch_unverified_fallback(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    marker = tmp_path / "untrusted-child.marker"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    _DaemonHandler.response_body = json.dumps({"reason_code": "daemon_hook_process_failed"}).encode()
    causes = []
    try:
        response, overloaded, integrity_failed = flow.bridge_review_response(
            state_path=guard_home / "daemon-state.json",
            fallback_command=[sys.executable, "-c", f"from pathlib import Path;Path({str(marker)!r}).touch()"],
            start_command=[sys.executable, "-c", "raise SystemExit(1)"],
            query=f"guard-home={guard_home}",
            data=json.dumps({"hook_event_name": "PreToolUse"}),
            deadline=time.monotonic() + 3,
            manifest_path=guard_home / "managed/codex/hooks-missing.manifest.json",
            config_json="untrusted-fixture-contract",
            failure_causes=causes,
        )
    finally:
        daemon.shutdown()
        thread.join(timeout=5)
        daemon.server_close()
    assert not marker.exists(), "A signed worker failure does not authenticate fallback argv"
    assert response is None
    assert not overloaded
    assert integrity_failed
    assert causes[0] == {"stage": "daemon_worker", "reason_code": "daemon_worker_failed"}
    assert causes[1]["stage"] == "launcher_validation"


@pytest.mark.parametrize("daemon_result", [None, {"reason_code": "daemon_hook_process_failed"}])
def test_worker_fault_preserves_authenticated_fallback_decisions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    daemon_result,
) -> None:
    calls = []
    denial = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"}}

    class AuthenticatedLaunch:
        def run_fallback(self, command, *, data, timeout_seconds):
            assert command == ["authenticated-fallback"]
            assert data == "fixture-payload"
            assert 0 < timeout_seconds <= 3
            calls.append("fallback")
            return json.dumps(denial)

        def run_start(self, *_args, **_kwargs):
            pytest.fail("A worker-failure response must not start another daemon")

    def validate(**_kwargs):
        calls.append("validation")
        return AuthenticatedLaunch()

    def unverified_fallback(*_args, **_kwargs):
        pytest.fail("A validated launch must not use the unverified fallback path")

    monkeypatch.setattr(flow, "_daemon_response", lambda **_kwargs: daemon_result)
    monkeypatch.setattr(flow, "trusted_hook_launch", validate)
    monkeypatch.setattr(flow, "_run_local_fallback", unverified_fallback)
    response, overloaded, integrity_failed = flow.bridge_review_response(
        state_path=tmp_path / "daemon-state.json",
        fallback_command=["authenticated-fallback"],
        start_command=["unused-start"],
        query="",
        data="fixture-payload",
        deadline=time.monotonic() + 3,
        manifest_path=tmp_path / "managed/codex/hooks-fixture.manifest.json",
        config_json="fixture",
    )
    assert response == denial
    assert not overloaded
    assert not integrity_failed
    assert calls == ["validation", "fallback"]


def test_empty_daemon_result_cannot_skip_managed_launch_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "untrusted-child.marker"
    monkeypatch.setattr(flow, "_daemon_response", lambda **_kwargs: None)
    response, _, integrity_failed = flow.bridge_review_response(
        state_path=tmp_path / "daemon-state.json",
        fallback_command=[sys.executable, "-c", f"from pathlib import Path;Path({str(marker)!r}).touch()"],
        start_command=[sys.executable, "-c", "raise SystemExit(1)"],
        query="",
        data="{}",
        deadline=time.monotonic() + 2,
        manifest_path=tmp_path / "managed/codex/hooks-missing.manifest.json",
        config_json="fixture",
    )
    assert not marker.exists()
    assert response is None
    assert integrity_failed
