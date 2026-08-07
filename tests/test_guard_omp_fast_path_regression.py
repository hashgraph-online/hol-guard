from __future__ import annotations

import json
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPResponse
from pathlib import Path
from typing import TypeGuard, cast

import pytest

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def _is_string_object_dict(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in cast(dict[object, object], value))


def test_omp_post_tool_read_burst_uses_resident_scanner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    store = GuardStore(home_dir)
    monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "1")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    query = urllib.parse.urlencode(
        {
            "guard-home": str(home_dir),
            "home": str(home_dir),
            "workspace": str(workspace),
        }
    )
    endpoint = f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?{query}"
    safe_output = "Safe skill instructions for local development.\n" * 700

    def review(index: int) -> dict[str, object]:
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(
                {
                    "hook_event_name": "PostToolUse",
                    "tool_call_id": f"omp-read-{index}",
                    "tool_name": "read",
                    "tool_input": {"path": f"skill://routine-{index}"},
                    "tool_response": [{"type": "text", "text": safe_output}],
                }
            ).encode(),
            headers={
                "Content-Type": "application/json",
                "X-Guard-Token": daemon._server.auth_token,  # pyright: ignore[reportPrivateUsage]
            },
            method="POST",
        )
        with cast(HTTPResponse, urllib.request.urlopen(request, timeout=3)) as response:
            result = cast(object, json.loads(response.read()))
        assert _is_string_object_dict(result)
        return result

    try:
        with ThreadPoolExecutor(max_workers=24) as executor:
            results = list(executor.map(review, range(24)))
        worker_stats = daemon._server.hook_process_runner.stats()  # pyright: ignore[reportPrivateUsage]
    finally:
        daemon.stop()

    assert all(result.get("decision") == "allow" for result in results)
    assert all(result.get("reason_code") == "output_scan_allow" for result in results)
    assert worker_stats["timeouts"] == 0
    assert worker_stats["restarts"] == 0
