"""The daemon frees a hook's review slot before the hook's answer is sent."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize("decision", [{"decision": "allow"}, None])
def test_hook_slot_is_free_before_the_answer_is_written(tmp_path, monkeypatch, decision) -> None:
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
    # Keep the Pi hook on the scheduler instead of the resident's direct lane.
    monkeypatch.setenv("HOL_GUARD_PI_DIRECT_HOOK", "0")
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    scheduler = daemon._server.runtime_hook_scheduler
    review_active: list[int] = []
    write_active: list[int] = []

    def review(_handler, *_args, **_kwargs) -> dict[str, object] | None:
        review_active.append(scheduler.stats()["active"])
        return decision

    original_write = daemon_server_module._GuardDaemonHandler._write_json

    def write(handler, payload, **kwargs) -> None:
        if handler.path.startswith("/v1/hooks/"):
            write_active.append(scheduler.stats()["active"])
        original_write(handler, payload, **kwargs)

    monkeypatch.setattr(daemon_server_module._GuardDaemonHandler, "_handle_runtime_hook_fast", review)
    monkeypatch.setattr(daemon_server_module._GuardDaemonHandler, "_write_json", write)
    query = urllib.parse.urlencode({"guard-home": str(store.guard_home), "workspace": str(workspace)})
    daemon.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?{query}",
            data=json.dumps(
                {"hook_event_name": "PreToolUse", "tool_name": "read", "tool_input": {"path": "README.md"}}
            ).encode(),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            answer = json.loads(response.read())
        # The client holds its answer, so the scheduler must already be idle.
        stats = scheduler.stats()
    finally:
        daemon.stop()

    assert isinstance(answer, dict)
    if decision is not None:
        assert answer == decision
    assert review_active == [1]
    assert write_active == [0]
    assert stats["active"] == 0
    assert stats["completed"] == 1
