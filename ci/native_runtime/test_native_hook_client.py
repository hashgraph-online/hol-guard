from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import pytest

from ci.native_runtime.native_hook_client_support import (
    _invoke,
    _request,
    _result,
    _state_files,
    _terminate_process,
    _terminate_state_process,
    _write_forged_state,
)
from ci.native_runtime.native_hook_client_support import native_runtime as _native_runtime_fixture  # noqa: F401
from ci.native_runtime.resident_test_support import process_is_alive


def test_native_hook_client_reuses_one_authenticated_generation(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path)
    first = _invoke(runtime, state_dir, request)
    second = _invoke(runtime, state_dir, request)
    assert first["schema"] == "guard-hook-edge-result.v2"
    assert first["authority"] == "rust"
    assert first["harness"] == "claude-code"
    assert first["event_name"] == "PreToolUse"
    assert _result(first)["minimum_action"] == "allow"
    assert second == first
    assert len(_state_files(state_dir)) == 1


def test_native_hook_client_stop_reaps_managed_processes(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    _invoke(runtime, state_dir, _request(runtime, tmp_path))
    state_files = _state_files(state_dir)
    assert len(state_files) == 1
    state = json.loads(state_files[0].read_text(encoding="utf-8"))
    process_ids: list[int] = []
    for key in ("process_id", "owner_process_id"):
        process_id = state[key]
        assert isinstance(process_id, int) and process_id > 0
        process_ids.append(process_id)

    result = subprocess.run(
        (str(runtime), "resident-stop", "--state-dir", str(state_dir)),
        check=False,
        capture_output=True,
        timeout=3,
    )
    assert result.returncode == 0, result.stderr
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and (
        _state_files(state_dir) or any(process_is_alive(process_id) for process_id in process_ids)
    ):
        time.sleep(0.01)
    assert not (_state_files(state_dir) or any(process_is_alive(process_id) for process_id in process_ids))


def test_release_resident_starts_without_authority_and_rejects_approval(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path, default_action="review")
    ordinary = _invoke(runtime, state_dir, request)
    assert ordinary["authority"] == "rust"
    assert _result(ordinary)["minimum_action"] == "review"

    envelope = json.loads(request)
    approval_request = json.dumps(
        {
            "operation": "approval_challenge",
            "request": {
                "schema": "guard-native-approval-challenge-request.v3",
                "version": 3,
                "envelope": envelope,
            },
        },
        separators=(",", ":"),
    ).encode()
    result = subprocess.run(
        (str(runtime), "resident-client", "--stdin", str(state_dir)),
        input=approval_request,
        check=False,
        capture_output=True,
        timeout=3,
    )
    assert result.returncode == 0
    response = json.loads(result.stdout)
    assert response["error"] == "native_approval_signing_authority_unavailable"


def test_native_hook_client_rejects_self_authenticated_forged_state(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    _write_forged_state(runtime, state_dir)
    response = _invoke(runtime, state_dir, _request(runtime, tmp_path))
    assert response["authority"] == "rust"
    assert _result(response)["minimum_action"] == "allow"
    assert len(_state_files(state_dir)) == 1


def test_native_hook_client_recovers_after_exact_managed_process_exit(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path)
    _invoke(runtime, state_dir, request)
    initial_state = _state_files(state_dir)[0]
    _terminate_state_process(initial_state)
    recovered = _invoke(runtime, state_dir, request)
    assert _result(recovered)["minimum_action"] == "allow"
    assert len(_state_files(state_dir)) == 1
    assert _state_files(state_dir)[0].name != initial_state.name


def test_native_hook_client_recovers_after_supervisor_exit(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path)
    _invoke(runtime, state_dir, request)
    initial_state = _state_files(state_dir)[0]
    state = json.loads(initial_state.read_text(encoding="utf-8"))
    owner_process_id = state["owner_process_id"]
    assert isinstance(owner_process_id, int) and owner_process_id > 0
    _terminate_process(owner_process_id)
    recovered = _invoke(runtime, state_dir, request)
    assert _result(recovered)["minimum_action"] == "allow"
    assert len(_state_files(state_dir)) == 1
    assert _state_files(state_dir)[0].name != initial_state.name


def test_native_hook_client_restart_budget_opens_circuit(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path)
    observed_generations: set[int] = set()
    for generation_index in range(3):
        response = _invoke(runtime, state_dir, request)
        assert response["authority"] == "rust"
        state_files = _state_files(state_dir)
        assert len(state_files) == 1
        state = json.loads(state_files[0].read_text(encoding="utf-8"))
        generation = state["generation"]
        assert isinstance(generation, int)
        observed_generations.add(generation)
        assert len(observed_generations) == generation_index + 1
        _terminate_state_process(state_files[-1])
    blocked = subprocess.run(
        (str(runtime), "hook-client", "--stdin", str(state_dir)),
        input=request,
        check=False,
        capture_output=True,
        timeout=3,
    )
    assert blocked.returncode != 0
    assert b"native_resident_restart_circuit_open" in blocked.stderr


@pytest.mark.parametrize(
    "tool_name,tool_input",
    [
        ("WebFetch", {"url": "https://example.test/docs", "prompt": "read"}),
        ("Read", {"file_path": ".env"}),
        ("mcp__filesystem__read", {"path": "README.md"}),
    ],
)
def test_current_resident_noncommand_review_reaches_exact_once_approval(
    native_runtime: tuple[Path, Path], tmp_path: Path, tool_name: str, tool_input: dict[str, str]
) -> None:
    from codex_plugin_scanner.guard.store import GuardStore
    from tests.test_native_noncommand_review_binding import _pause, _resolve, assert_current_review_roundtrip

    runtime, state_dir = native_runtime
    envelope = json.loads(_request(runtime, tmp_path, default_action="review"))
    envelope["harness"] = "cursor"
    envelope["raw_payload"] = {"tool_name": tool_name, "tool_input": tool_input}
    edge = _invoke(runtime, state_dir, json.dumps(envelope, separators=(",", ":")).encode())
    case = {
        "edge": edge,
        "payload": envelope["raw_payload"],
        "source": envelope["source"],
        "snapshot": envelope["policy_snapshot"],
    }
    receipt = edge["receipt"]
    assert isinstance(receipt, dict)
    assert receipt["review_scope"] == "noncommand"
    store = GuardStore(tmp_path / "approval-store")
    assert_current_review_roundtrip(store, case)
    original = _pause(store, case)
    old_id = _resolve(store, original, "cursor")
    changed = json.loads(json.dumps(envelope))
    field = next(iter(tool_input))
    changed["raw_payload"]["tool_input"][field] += "-changed"
    changed_edge = _invoke(runtime, state_dir, json.dumps(changed, separators=(",", ":")).encode())
    changed_receipt = changed_edge["receipt"]
    assert isinstance(changed_receipt, dict)
    assert changed_receipt["request_digest"] != receipt["request_digest"]
    response = _pause(store, {**case, "edge": changed_edge, "payload": changed["raw_payload"]})
    assert response["policy_action"] == "review"
    assert response["approval_request_id"] != old_id
    assert "approval_reuse_status" not in response
    assert _pause(store, case)["approval_reuse_status"] == "accepted"
