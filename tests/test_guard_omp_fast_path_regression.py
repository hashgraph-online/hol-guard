from __future__ import annotations

import hashlib
import json
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPResponse
from pathlib import Path
from typing import TypeGuard, cast

import pytest

from codex_plugin_scanner.guard.daemon import server as daemon_server_module
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
    monkeypatch.setattr(daemon_server_module, "_RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS", 5.0)
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
    normalized_output = safe_output.rstrip("\n")
    source_refs: list[dict[str, object]] = []
    for index in range(24):
        source_path = workspace / f"routine-{index}.md"
        _ = source_path.write_text(safe_output, encoding="utf-8")
        source_refs.append(
            {
                "version": 1,
                "kind": "source_file",
                "path": source_path.name,
                "tool_input_path": source_path.name,
                "output_sha256": hashlib.sha256(normalized_output.encode("utf-8")).hexdigest(),
                "output_chars": len(normalized_output),
            }
        )

    def review(index: int) -> dict[str, object]:
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(
                {
                    "hook_event_name": "PostToolUse",
                    "tool_call_id": f"omp-read-{index}",
                    "tool_name": "Read",
                    "tool_input": {"file_path": source_refs[index]["path"]},
                    "guard_source_ref": source_refs[index],
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
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(review, range(24)))
        worker_stats = daemon._server.hook_process_runner.stats()  # pyright: ignore[reportPrivateUsage]
    finally:
        daemon.stop()

    assert all(result.get("decision") == "allow" for result in results), results
    assert all(result.get("model_output_action") == "allow_original" for result in results)
    assert all(result.get("reason_code") == "source_full_scan_allow" for result in results)
    assert worker_stats["timeouts"] == 0
    assert worker_stats["restarts"] == 0


def test_omp_source_search_identifiers_do_not_trigger_output_secret_review(
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

    def review(output: str) -> dict[str, object]:
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(
                {
                    "hook_event_name": "PostToolUse",
                    "tool_call_id": "omp-source-search",
                    "tool_name": "Grep",
                    "tool_input": {
                        "pattern": "rawCommand|redactedCommand|token",
                        "path": "src",
                    },
                    "tool_response": output,
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
        clean = review(
            "\n".join(
                (
                    "src/command.ts: const candidates = [row.redactedCommand, row.rawCommand];",
                    "src/types.ts: readonly redactionState: string;",
                    "",
                )
            )
        )
        secret = review("src/config.ts: auth_token = 'live-secret-value-1234567890'\n")
    finally:
        daemon.stop()

    assert clean["decision"] == "allow"
    assert clean["model_output_action"] == "allow_original"
    assert clean["reason_code"] == "output_scan_allow"
    assert secret["decision"] == "deny"
    assert secret["model_output_action"] == "block"
    assert secret["reason_code"] == "output_secret_match"
