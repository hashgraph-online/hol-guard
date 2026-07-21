from __future__ import annotations

import json
import threading
import urllib.parse
import urllib.request
from argparse import Namespace
from pathlib import Path
from typing import TextIO

import pytest

from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def _pi_hook_request(*, daemon: GuardDaemonServer, guard_home: str, call_id: str) -> urllib.request.Request:
    query = urllib.parse.urlencode({"guard-home": guard_home, "home": guard_home})
    return urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?{query}",
        data=json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_call_id": call_id,
                "tool_name": "read",
                "tool_input": {"path": "README.md"},
            }
        ).encode(),
        headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
        method="POST",
    )


def test_pi_hook_is_not_queued_behind_unrelated_overlay_free_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_started = threading.Event()
    release_first = threading.Event()

    def fake_run_guard_command(args: Namespace, *, input_text: str, output_stream: TextIO) -> int:
        del args
        payload = json.loads(input_text)
        if payload["tool_call_id"] == "first":
            first_started.set()
            assert release_first.wait(timeout=2)
        output_stream.write('{"decision":"allow"}')
        return 0

    monkeypatch.setattr(guard_commands_module, "run_guard_command", fake_run_guard_command)
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    first_result: list[dict[str, object]] = []

    def run_first() -> None:
        request = _pi_hook_request(daemon=daemon, guard_home=str(store.guard_home), call_id="first")
        with urllib.request.urlopen(request, timeout=3) as response:
            first_result.append(json.loads(response.read()))

    first_thread = threading.Thread(target=run_first)
    first_thread.start()
    try:
        assert first_started.wait(timeout=1)
        request = _pi_hook_request(daemon=daemon, guard_home=str(store.guard_home), call_id="second")
        with urllib.request.urlopen(request, timeout=1) as response:
            second_result = json.loads(response.read())
    finally:
        release_first.set()
        first_thread.join(timeout=3)
        daemon.stop()

    assert second_result == {"decision": "allow"}
    assert first_result == [{"decision": "allow"}]


def test_pi_extension_keeps_fallbacks_inside_outer_hook_deadline(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
    )

    assert "const GUARD_TIMEOUT_MS = 8000;" in source
    assert "const GUARD_DAEMON_TIMEOUT_MS = 2500;" in source
    assert "const GUARD_CLI_TIMEOUT_MS = 4500;" in source
    assert "timeout: GUARD_CLI_TIMEOUT_MS" in source
