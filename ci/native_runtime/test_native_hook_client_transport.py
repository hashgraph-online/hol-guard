from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
import subprocess
import time
from pathlib import Path

from native_hook_client_support import (
    _authenticate_state,
    _connect_state,
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
    scope = _initialize_protected_scope(runtime, state_dir)
    lock = scope / "startup.lock"
    lock.write_text("stale", encoding="utf-8")
    old = time.time() - 15
    os.utime(lock, (old, old))
    response = _invoke(runtime, state_dir, _request(runtime, tmp_path))
    assert response["authority"] == "rust"
    assert not lock.exists()


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
