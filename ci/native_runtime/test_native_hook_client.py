from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import signal
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

_NATIVE_BINARY = os.environ.get("HOL_GUARD_NATIVE_BINARY")


@pytest.fixture
def native_runtime(tmp_path: Path) -> Iterator[tuple[Path, Path]]:
    if not _NATIVE_BINARY:
        pytest.skip("compiled native runtime is required")
    assert _NATIVE_BINARY is not None
    runtime = Path(_NATIVE_BINARY).resolve(strict=True)
    state_dir = tmp_path / "native-runtime"
    state_dir.mkdir(mode=0o700)
    yield runtime, state_dir
    subprocess.run(
        (str(runtime), "resident-stop", "--state-dir", str(state_dir)),
        check=False,
        capture_output=True,
        timeout=2,
    )


def _rule_digest(runtime: Path) -> str:
    result = subprocess.run(
        (str(runtime), "rule-contract", "--json"),
        check=True,
        capture_output=True,
        text=True,
        timeout=2,
    )
    digest = json.loads(result.stdout)["rule_digest"]
    assert isinstance(digest, str) and len(digest) == 64
    return digest


def _request(runtime: Path, root: Path, *, command: str = "pwd") -> bytes:
    generation_state = root / "native-policy-generation.json"
    generation_state.write_text(
        json.dumps(
            {
                "schema": "hol-guard-native-policy-generation.v1",
                "generation": 1,
                "policy_digest": "a" * 64,
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    generation_state.chmod(0o600)
    return json.dumps(
        {
            "schema": "guard-hook-envelope.v2",
            "request_id": "native-client-e2e",
            "harness": "claude",
            "event": "PreToolUse",
            "raw_payload": {
                "hook_event_name": "PreToolUse",
                "tool_input": {"command": command},
            },
            "deadline_budget_ms": 1_000,
            "policy_generation": 1,
            "policy_snapshot": {
                "schema": "hol-guard-native-policy.v1",
                "generation": 1,
                "policy_digest": "a" * 64,
                "config_digest": "b" * 64,
                "rule_digest": _rule_digest(runtime),
                "mode": "enforce",
            },
            "source": {
                "cwd": str(root),
                "home_dir": str(root),
                "guard_home": str(root),
            },
        },
        separators=(",", ":"),
    ).encode()


def _invoke(runtime: Path, state_dir: Path, request: bytes) -> dict[str, object]:
    result = subprocess.run(
        (str(runtime), "hook-client", "--stdin", str(state_dir)),
        input=request,
        check=True,
        capture_output=True,
        timeout=3,
    )
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    return payload


def _state_files(state_dir: Path) -> list[Path]:
    return sorted(state_dir.glob("resident-v3-*/generation-*.json"))


def _write_forged_state(runtime: Path, state_dir: Path) -> None:
    runtime_digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
    scope = state_dir / f"resident-v3-{runtime_digest[:16]}"
    scope.mkdir(mode=0o700)
    token = secrets.token_bytes(32)
    state: dict[str, object] = {
        "schema": "hol-guard-resident-state.v3",
        "generation": 18_000_000_000_000_000_000,
        "process_id": os.getpid(),
        "owner_process_id": os.getpid(),
        "runtime_sha256": runtime_digest,
        "transport": "loopback",
        "endpoint": "127.0.0.1:9",
        "token_hex": token.hex(),
        "created_ms": 1,
    }
    message = "\0".join(
        str(state[key])
        for key in (
            "schema",
            "generation",
            "process_id",
            "owner_process_id",
            "runtime_sha256",
            "transport",
            "endpoint",
            "token_hex",
            "created_ms",
        )
    ).encode()
    state["state_mac"] = hmac.new(token, b"hol-guard-resident-state-v3\x00" + message, hashlib.sha256).hexdigest()
    path = scope / "generation-18000000000000000000.json"
    path.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
    path.chmod(0o600)


def _result(response: dict[str, object]) -> dict[str, object]:
    result = response["result"]
    assert isinstance(result, dict)
    return result


def _terminate_state_process(state_file: Path) -> None:
    state = json.loads(state_file.read_text(encoding="utf-8"))
    process_id = state["process_id"]
    assert isinstance(process_id, int) and process_id > 0
    _terminate_process(process_id)


def _terminate_process(process_id: int) -> None:
    os.kill(process_id, signal.SIGTERM)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(process_id, 0)
        except OSError:
            return
        time.sleep(0.01)


def _read_exact(client: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = client.recv(length - len(output))
        if not chunk:
            break
        output.extend(chunk)
    return bytes(output)


def _connect_state(state: dict[str, object]) -> socket.socket:
    endpoint = state["endpoint"]
    assert isinstance(endpoint, str)
    if state["transport"] == "unix":
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(endpoint)
        return client
    host, separator, raw_port = endpoint.partition(":")
    assert separator and host == "127.0.0.1"
    return socket.create_connection((host, int(raw_port)), timeout=1)


def _authenticate_state(client: socket.socket, state: dict[str, object]) -> None:
    token_hex = state["token_hex"]
    assert isinstance(token_hex, str)
    token = bytes.fromhex(token_hex)
    nonce = secrets.token_bytes(32)
    client.sendall(nonce)
    server_proof = _read_exact(client, 32)
    assert hmac.compare_digest(
        server_proof,
        hmac.new(token, b"hol-guard-resident-server-v1\x00" + nonce, hashlib.sha256).digest(),
    )
    client.sendall(hmac.new(token, b"hol-guard-resident-client-v1\x00" + nonce, hashlib.sha256).digest())


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
    runtime_digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
    scope = state_dir / f"resident-v3-{runtime_digest[:16]}"
    scope.mkdir(mode=0o700)
    lock = scope / "startup.lock"
    lock.write_text("stale", encoding="utf-8")
    old = time.time() - 15
    os.utime(lock, (old, old))
    response = _invoke(runtime, state_dir, _request(runtime, tmp_path))
    assert response["authority"] == "rust"
    assert not lock.exists()


def test_native_hook_client_rejects_duplicate_edge_keys_without_fallback(
    native_runtime: tuple[Path, Path],
) -> None:
    runtime, state_dir = native_runtime
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
