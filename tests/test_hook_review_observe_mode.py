"""Watch-only behavior for resident hook output review."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from http.client import HTTPResponse
from pathlib import Path
from typing import Protocol, cast

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from tests.daemon_hook_test_client import open_authenticated_claude_request


class _Metrics:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def record(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


class _DaemonServerAccess(Protocol):
    auth_token: str
    hook_worker: HookWorker


def test_watch_only_daemon_worker_exception_does_not_block_harnesses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    guard_home.mkdir()
    workspace.mkdir()
    _ = (guard_home / "config.toml").write_text('mode = "observe"\n', encoding="utf-8")
    monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "1")
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    daemon.start()
    server_access = cast(_DaemonServerAccess, vars(daemon)["_server"])

    def fail_review(**_kwargs: object) -> dict[str, object]:
        raise RuntimeError("resident worker failed")

    monkeypatch.setattr(server_access.hook_worker, "review_http_payload", fail_review)
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/delivery.ts"},
        "guard_source_ref": {
            "version": 1,
            "path": "src/delivery.ts",
            "tool_input_path": "src/delivery.ts",
            "output_sha256": "0" * 64,
            "output_chars": 10,
        },
    }

    try:
        results: dict[str, dict[str, object]] = {}
        for harness in ("pi", "claude-code"):
            query = urllib.parse.urlencode(
                {
                    "guard-home": str(guard_home),
                    "home": str(tmp_path),
                    "workspace": str(workspace),
                }
            )
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/hooks/{harness}?{query}",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": server_access.auth_token,
                },
                method="POST",
            )
            response = cast(
                HTTPResponse,
                open_authenticated_claude_request(daemon, request, timeout=5)
                if harness == "claude-code"
                else urllib.request.urlopen(request, timeout=5),
            )
            with response:
                results[harness] = json.loads(response.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert results["pi"]["decision"] == "allow"
    assert results["pi"]["reason_code"] == "daemon_worker_exception"
    assert results["claude-code"]["continue"] is True
    assert results["claude-code"]["reason_code"] == "daemon_worker_exception"
