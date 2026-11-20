"""The resident library call behind ``POST /v1/requests/<id>/live-decision``.

The waiting Codex hook bridge posts the exact hook input here once the
request is resolved. Without this call the native daemon answered 404 and
the bridge printed the original deny, so an approved command never ran.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.hook_review.hook_worker import HookWorker
from codex_plugin_scanner.guard.library_calls import REGISTRY, run_library_call
from codex_plugin_scanner.guard.live_process_identity import (
    CODEX_BROWSER_WAIT_PROCESS_KEY,
    CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
    current_process_identity,
)
from codex_plugin_scanner.guard.routes import hook_calls
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_review_codex_live_wait import _allow_once


@pytest.fixture
def resident_servers() -> Iterator[None]:
    yield
    with hook_calls._SERVERS_LOCK:
        servers = list(hook_calls._SERVERS.values())
        hook_calls._SERVERS.clear()
    for server in servers:
        worker = server.__dict__.get("hook_worker")
        if worker is not None:
            worker.close()
        server.server_close()


def _call(guard_home: Path, args: dict[str, object]) -> dict[str, object]:
    request = json.dumps({"call": "hook.codex_live_decision", "args": args}).encode("utf-8")
    return run_library_call(guard_home, request)


def test_the_call_is_registered() -> None:
    assert REGISTRY["hook.codex_live_decision"] is hook_calls.codex_live_decision


def test_malformed_arguments_are_refused(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    assert _call(guard_home, {"request_id": "r-1"})["error"]["message"] == "invalid_arguments"  # type: ignore[index]
    assert _call(guard_home, {"request_id": "", "payload": {}})["error"]["message"] == "invalid_arguments"  # type: ignore[index]


@pytest.mark.parametrize("hook_input", ["approved", "changed-command", "changed-session"])
def test_live_decision_releases_only_the_approved_codex_action(
    live_hook_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    resident_servers: None,
    hook_input: str,
) -> None:
    home = live_hook_root / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    store = GuardStore(home / ".hol-guard")
    update_guard_settings(store.guard_home, {"blocked_request_mode": "ask"})
    scratch = workspace / "sandbox-dir"
    scratch.mkdir()
    (scratch / "notes.txt").write_text("disposable maintenance fixture\n", encoding="utf-8")
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "session_id": "codex-live-decision-route",
        "tool_use_id": "call-first",
        "tool_name": "Bash",
        "tool_input": {"command": f"rm -rf {scratch}"},
        "cwd": str(workspace),
        CODEX_BROWSER_WAIT_PROCESS_KEY: current_process_identity(),
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 120,
    }
    worker = HookWorker(store=store, workspace=workspace)
    try:
        first = worker.review_http_payload(
            payload={**payload, "guard_remaining_ms": 60_000},
            params={},
            default_harness="codex",
            home_dir=home,
            guard_home=store.guard_home,
            workspace=workspace,
        )
    finally:
        worker.close()
    assert first["policy_action"] == "review", first
    request_id = str(first["approval_request_id"])
    _allow_once(store, request_id, workspace)

    posted = dict(payload)
    if hook_input == "changed-command":
        posted["tool_input"] = {"command": f"rm -rf {workspace / 'another-dir'}"}
    elif hook_input == "changed-session":
        posted["session_id"] = "another-session"
    answer = _call(
        store.guard_home,
        {"request_id": request_id, "home_dir": str(home), "payload": {"hook_input": json.dumps(posted)}},
    )

    reply = answer["ok"]
    assert isinstance(reply, dict), answer
    assert reply["no_store"] is False
    body = reply["body"]
    assert isinstance(body, dict)
    if hook_input == "approved":
        assert reply["status"] == 200, reply
        assert body["completed"] is True
        assert body["action"] == "allow"
        resume = store.get_request_resume(request_id)
        assert resume is not None
        assert resume["status"] == "sent"
    else:
        assert reply["status"] == 409, reply
        assert body["completed"] is False
        assert body.get("action") != "allow"
    # Admission only: the fixture removal is never executed.
    assert scratch.is_dir()
