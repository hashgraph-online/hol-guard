from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
import stat
import subprocess
import time
from pathlib import Path

import pytest
from native_hook_client_support import (
    _authenticate_state,
    _connect_state,
    _hold_native_client_lease,
    _initialize_protected_scope,
    _invoke,
    _read_exact,
    _request,
    _state_files,
)
from native_hook_client_support import native_runtime as _native_runtime_fixture  # noqa: F401

from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key


def test_native_resident_contains_spoof_partial_frame_and_slow_client(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path)
    _invoke(runtime, state_dir, request)
    state = json.loads(_state_files(state_dir)[0].read_text(encoding="utf-8"))

    with _connect_state(state) as spoof:
        nonce = secrets.token_bytes(32)
        spoof.sendall(nonce)
        proof = _read_exact(spoof, 32)
        assert len(proof) == 32
        assert not hmac.compare_digest(
            proof,
            hmac.new(b"x" * 32, b"hol-guard-resident-server-v1\x00" + nonce, hashlib.sha256).digest(),
        )

    with _connect_state(state) as partial:
        _authenticate_state(partial, state)
        partial.sendall(b"HGR2\x00")

    with _connect_state(state) as slow:
        time.sleep(0.3)
        try:
            slow.sendall(b"late")
            assert slow.recv(1) == b""
        except OSError:
            pass

    recovered = _invoke(runtime, state_dir, request)
    assert recovered["authority"] == "rust"
    assert len(_state_files(state_dir)) == 1


def test_native_resident_returns_bounded_overload_signal(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path)
    _invoke(runtime, state_dir, request)
    with _hold_native_client_lease(runtime, state_dir):
        state = json.loads(_state_files(state_dir)[0].read_text(encoding="utf-8"))
        clients: list[socket.socket] = []
        last_request_id = b""
        try:
            for _index in range(49):
                client = _connect_state(state)
                client.settimeout(1)
                _authenticate_state(client, state)
                request_id = secrets.token_bytes(32)
                last_request_id = request_id
                client.sendall(b"HGR2" + request_id + hashlib.sha256(b"x").digest() + (1).to_bytes(4, "big"))
                clients.append(client)
            header = _read_exact(clients[-1], 72)
            assert header[:4] == b"HGS2"
            assert header[4:36] == last_request_id
            length = int.from_bytes(header[-4:], "big")
            response = json.loads(_read_exact(clients[-1], length))
            assert response == {"error": "native_overloaded", "retryable": True}
        finally:
            for client in clients:
                client.close()
    recovered = _invoke(runtime, state_dir, request)
    assert recovered["authority"] == "rust"


def test_unauthenticated_saturation_never_starts_parallel_generation(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path)
    _invoke(runtime, state_dir, request)
    state = json.loads(_state_files(state_dir)[0].read_text(encoding="utf-8"))
    clients = [_connect_state(state) for _index in range(21)]
    try:
        blocked = subprocess.run(
            (str(runtime), "hook-client", "--stdin", str(state_dir)),
            input=request,
            check=False,
            capture_output=True,
            timeout=3,
        )
        assert blocked.returncode != 0
        assert b"native_resident_live_request_failed" in blocked.stderr
        assert len(_state_files(state_dir)) == 1
    finally:
        for client in clients:
            client.close()
    recovered = _invoke(runtime, state_dir, request)
    assert recovered["authority"] == "rust"
    assert len(_state_files(state_dir)) == 1


def test_native_hook_client_recovers_only_stale_startup_lock(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    _initialize_protected_scope(runtime, state_dir)
    lock = state_dir / "startup.lock"
    runtime_digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
    stale_marker = f"999999:stale:{runtime_digest}:{'0' * 64}"
    lock.write_text(stale_marker, encoding="utf-8")
    if os.name != "nt":
        lock.chmod(0o600)
    old = time.time() - 15
    os.utime(lock, (old, old))
    response = _invoke(runtime, state_dir, _request(runtime, tmp_path))
    assert response["authority"] == "rust"
    lock_stat = lock.lstat()
    assert stat.S_ISREG(lock_stat.st_mode)
    assert not stat.S_ISLNK(lock_stat.st_mode)
    if os.name != "nt":
        assert stat.S_IMODE(lock_stat.st_mode) & 0o077 == 0
    marker = lock.read_text(encoding="utf-8")
    assert marker != stale_marker
    assert len(marker.encode("utf-8")) == lock_stat.st_size <= 4 * 1024
    marker_parts = marker.split(":")
    assert len(marker_parts) >= 4
    assert marker_parts[0].isdigit() and int(marker_parts[0]) > 0
    assert marker_parts[-2] == runtime_digest
    assert len(marker_parts[-1]) == 64
    assert all(character in "0123456789abcdefABCDEF" for character in marker_parts[-1])
    assert ":".join(marker_parts[1:-2])


def test_native_hook_client_rejects_duplicate_edge_keys_without_fallback(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    provision_native_policy_verifier_key(tmp_path, b"\x07" * 32)
    malformed = b'{"schema":"guard-hook-envelope.v2","schema":"other"}'
    result = subprocess.run(
        (str(runtime), "hook-client", "--stdin", str(state_dir)),
        input=malformed,
        check=False,
        capture_output=True,
        timeout=3,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout) == {
        "error": "native_request_invalid_json",
        "retryable": False,
    }


@pytest.mark.parametrize("command", ["hook-client", "resident-client"])
@pytest.mark.parametrize(
    "malformed, expected_error",
    [
        (b'{"schema":"guard-hook-envelope.v2","schema":"other"}', "native_request_invalid_json"),
        (b'{"nested":{"key":"first","key":"second"}}', "native_request_invalid_json"),
        (b'{} {"private":"synthetic-canary"}', "native_request_trailing_json"),
        (b'{"private":"synthetic-canary"', "native_request_invalid_json"),
    ],
)
def test_invalid_native_client_input_does_not_start_or_mutate_resident(
    native_runtime: tuple[Path, Path],
    command: str,
    malformed: bytes,
    expected_error: str,
) -> None:
    runtime, state_dir = native_runtime
    # No verifier key or resident state is needed to reject invalid JSON.
    assert list(state_dir.iterdir()) == []
    result = subprocess.run(
        (str(runtime), command, "--stdin", str(state_dir)),
        input=malformed,
        check=False,
        capture_output=True,
        timeout=3,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"error": expected_error, "retryable": False}
    assert result.stderr == b""
    assert list(state_dir.iterdir()) == []


def test_native_client_stream_rejects_invalid_frames_without_startup(
    native_runtime: tuple[Path, Path],
) -> None:
    runtime, state_dir = native_runtime
    payloads = [
        (b'{"key":1,"key":2}', "native_request_invalid_json"),
        (b'{} {"private":"synthetic-canary"}', "native_request_trailing_json"),
    ]
    frames = b"".join(len(payload).to_bytes(4, "big") + payload for payload, _expected_error in payloads)
    result = subprocess.run(
        (str(runtime), "resident-client-stream", "--stdin", str(state_dir)),
        input=frames,
        check=False,
        capture_output=True,
        timeout=3,
    )
    assert result.returncode == 0
    remaining = result.stdout
    for _payload, expected_error in payloads:
        assert len(remaining) >= 4
        length = int.from_bytes(remaining[:4], "big")
        assert 0 < length <= 1024
        assert len(remaining) >= 4 + length
        assert json.loads(remaining[4 : 4 + length]) == {
            "error": expected_error,
            "retryable": False,
        }
        remaining = remaining[4 + length :]
    assert remaining == result.stderr == b""
    assert _state_files(state_dir) == []
    assert not (state_dir / "startup.lock").exists()


def test_native_resident_rejects_duplicate_keys_over_authenticated_transport(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    _invoke(runtime, state_dir, _request(runtime, tmp_path))
    state_files = _state_files(state_dir)
    assert len(state_files) == 1
    state = json.loads(state_files[0].read_text(encoding="utf-8"))
    malformed = b'{"schema":"guard-hook-envelope.v2","schema":"other"}'
    request_id = secrets.token_bytes(32)
    with _connect_state(state) as client:
        client.settimeout(1)
        _authenticate_state(client, state)
        client.sendall(
            b"HGR2" + request_id + hashlib.sha256(malformed).digest() + len(malformed).to_bytes(4, "big") + malformed
        )
        header = _read_exact(client, 72)
        assert len(header) == 72
        assert header[:4] == b"HGS2"
        assert header[4:36] == request_id
        length = int.from_bytes(header[-4:], "big")
        assert 0 < length <= 1024
        response = _read_exact(client, length)
        assert len(response) == length
        assert hmac.compare_digest(header[36:68], hashlib.sha256(response).digest())
        assert json.loads(response) == {"error": "native_request_invalid_json", "retryable": False}
    assert _state_files(state_dir) == state_files
