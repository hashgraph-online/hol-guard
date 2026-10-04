from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from native_hook_client_support import (
    _invoke,
    _request,
    _result,
    _state_files,
    _terminate_process,
    _terminate_state_process,
    _write_forged_state,
)
from native_hook_client_support import native_runtime as _native_runtime_fixture  # noqa: F401

from ci.native_runtime.native_process_test_support import process_is_alive


def _read_stream_frame(client: subprocess.Popen[bytes], timeout: float = 3) -> bytes:
    assert client.stdout is not None
    deadline = time.monotonic() + timeout

    def read_exact(size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "native stream frame timed out"
            ready, _, _ = select.select([client.stdout], [], [], remaining)
            assert ready, "native stream frame timed out"
            chunk = os.read(client.stdout.fileno(), size - len(chunks))
            assert chunk, "native stream closed before completing frame"
            chunks.extend(chunk)
        return bytes(chunks)

    size = int.from_bytes(read_exact(4), "big")
    assert 0 < size <= 4 * 1024 * 1024
    return read_exact(size)


@pytest.mark.parametrize("event", ["PreToolUse", "UserPromptSubmit"])
def test_same_runtime_in_distinct_frozen_extractions_reuses_resident(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
    event: str,
) -> None:
    runtime, state_dir = native_runtime
    first = tmp_path / "extraction-first" / runtime.name
    second = tmp_path / "extraction-second" / runtime.name
    first.parent.mkdir()
    second.parent.mkdir()
    shutil.copy2(runtime, first)
    shutil.copy2(runtime, second)
    request = _request(runtime, tmp_path)
    if event == "UserPromptSubmit":
        envelope = json.loads(request)
        envelope["harness"] = "zcode"
        envelope["event"] = event
        envelope["raw_payload"] = {
            "hookEventName": event,
            "userPrompt": "Summarize the README without changing files.",
        }
        request = json.dumps(envelope).encode()
    assert _result(_invoke(first, state_dir, request))["minimum_action"] == "allow"
    initial = _state_files(state_dir)
    assert _result(_invoke(second, state_dir, request))["minimum_action"] == "allow"
    assert _state_files(state_dir) == initial


@pytest.mark.skipif(os.name == "nt", reason="Windows does not unlink running executables")
def test_removed_frozen_extraction_releases_owner_even_with_live_client(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    extracted = tmp_path / "extraction" / runtime.name
    extracted.parent.mkdir()
    shutil.copy2(runtime, extracted)
    request = _request(runtime, tmp_path)
    assert _result(_invoke(extracted, state_dir, request))["minimum_action"] == "allow"
    state = json.loads(_state_files(state_dir)[0].read_text())
    # Keep a real client lease alive while its resident's onefile extraction disappears.
    client = subprocess.Popen(
        (str(extracted), "resident-client-stream", "--stdin", str(state_dir)),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert client.stdin is not None and client.stdout is not None
        client.stdin.write(len(request).to_bytes(4, "big") + request)
        client.stdin.flush()
        assert _result(json.loads(_read_stream_frame(client)))["minimum_action"] == "allow"
        extracted.unlink()
        deadline = time.monotonic() + 3
        while process_is_alive(state["process_id"]) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not process_is_alive(state["process_id"])
        assert _result(_invoke(runtime, state_dir, request))["minimum_action"] == "allow"
    finally:
        client.terminate()
        client.communicate(timeout=3)


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
    time.sleep(0.01)
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
