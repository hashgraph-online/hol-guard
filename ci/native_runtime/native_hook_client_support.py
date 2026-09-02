from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.live_process_identity import process_start_token
from codex_plugin_scanner.guard.native_policy_snapshot import (
    _policy_snapshot_push_bytes_v3,
    build_policy_snapshot_v3,
    derive_native_policy_verifier_key,
    provision_native_policy_verifier_key,
)

_NATIVE_BINARY = os.environ.get("HOL_GUARD_NATIVE_BINARY")
_NATIVE_DIAGNOSTIC_RE = re.compile(rb"\bnative_[a-z0-9_]+\b")


@pytest.fixture(name="native_runtime")
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


def _request(
    runtime: Path,
    root: Path,
    *,
    command: str = "pwd",
    default_action: str = "allow",
    deadline_budget_ms: int = 1_000,
) -> bytes:
    runtime_identity = hashlib.sha256(runtime.read_bytes()).hexdigest()
    rule_digest = _rule_digest(runtime)
    policy_master = b"\x07" * 32
    provision_native_policy_verifier_key(root, policy_master)
    policy_snapshot = build_policy_snapshot_v3(
        config={
            "mode": "enforce",
            "protection_posture": "protected",
            "security_level": "balanced",
            "default_action": default_action,
            "unknown_publisher_action": "review",
            "changed_hash_action": "require-reapproval",
            "new_network_domain_action": "warn",
            "subprocess_action": "allow",
            "risk_actions": {},
            "harness_risk_actions": {},
            "harness_actions": {},
            "publisher_actions": {},
            "artifact_actions": {},
            "sandbox_analysis": "off",
            "receipt_redaction_level": "full",
        },
        guard_home=root,
        runtime_identity=runtime_identity,
        rule_digest=rule_digest,
        verifier_key=derive_native_policy_verifier_key(policy_master),
        generation=1,
    )
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
            "deadline_budget_ms": deadline_budget_ms,
            "policy_generation": 1,
            "policy_snapshot": policy_snapshot,
            "source": {
                "cwd": str(root),
                "home_dir": str(root),
                "guard_home": str(root),
                "source_ref_external_allowed": False,
            },
        },
        separators=(",", ":"),
    ).encode()


def _push_snapshot(runtime: Path, state_dir: Path, request: bytes) -> None:
    value = json.loads(request)
    assert isinstance(value, dict)
    snapshot = value["policy_snapshot"]
    assert isinstance(snapshot, dict)
    result = subprocess.run(
        (str(runtime), "resident-client", "--stdin", str(state_dir)),
        input=_policy_snapshot_push_bytes_v3(snapshot),
        check=False,
        capture_output=True,
        timeout=8,
    )
    if result.returncode != 0:
        raise AssertionError(f"native policy push failed: {_native_diagnostic(result.stderr)}")
    try:
        acknowledgement = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        raise AssertionError("native policy push failed: native_policy_snapshot_ack_invalid") from None
    assert isinstance(acknowledgement, dict)
    assert acknowledgement["status"] == "accepted"


def _invoke(runtime: Path, state_dir: Path, request: bytes) -> dict[str, object]:
    _push_snapshot(runtime, state_dir, request)
    try:
        result = subprocess.run(
            (str(runtime), "hook-client", "--stdin", str(state_dir)),
            input=request,
            check=False,
            capture_output=True,
            timeout=3,
        )
    except subprocess.TimeoutExpired:
        raise AssertionError("native runtime invocation failed: native_client_timed_out") from None
    if result.returncode != 0:
        raise AssertionError(f"native runtime invocation failed: {_native_diagnostic(result.stderr)}")
    try:
        payload = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        raise AssertionError("native runtime invocation failed: native_client_output_invalid") from None
    assert isinstance(payload, dict)
    return payload


@contextmanager
def _hold_native_client_lease(runtime: Path, state_dir: Path) -> Iterator[None]:
    process = subprocess.Popen(
        (str(runtime), "resident-client-stream", "--stdin", str(state_dir)),
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    lease_directory = state_dir / "resident-client-leases.v1"
    lease_pattern = f"client-{process.pid}-*.lease"
    try:
        deadline = time.monotonic() + 3
        while not any(lease_directory.glob(lease_pattern)):
            if process.poll() is not None:
                raise AssertionError("native lease holder exited before acquiring its lease")
            if time.monotonic() >= deadline:
                raise AssertionError("native lease holder did not acquire its lease")
            time.sleep(0.01)
        yield
    finally:
        if process.stdin is not None:
            with suppress(OSError, ValueError):
                process.stdin.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            with suppress(OSError):
                process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                with suppress(OSError):
                    process.kill()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired as error:
                    raise AssertionError(
                        f"native lease holder did not exit after bounded cleanup (pid={process.pid})"
                    ) from error
        if process.poll() is None:
            raise AssertionError(f"native lease holder remains alive after cleanup (pid={process.pid})")
        if process.returncode != 0:
            raise AssertionError(
                f"native lease holder exited unexpectedly (pid={process.pid}, returncode={process.returncode})"
            )


def _state_files(state_dir: Path) -> list[Path]:
    return sorted(state_dir.glob("resident-v3-*/generation-*.json"))


def _native_diagnostic(stderr: bytes) -> str:
    match = _NATIVE_DIAGNOSTIC_RE.search(stderr[:8192])
    if match is None:
        return "native_client_process_failed"
    return match.group().decode("ascii")


def _initialize_protected_scope(runtime: Path, state_dir: Path) -> Path:
    try:
        result = subprocess.run(
            (str(runtime), "resident-stop", "--state-dir", str(state_dir)),
            check=False,
            capture_output=True,
            timeout=3,
        )
    except subprocess.TimeoutExpired:
        raise AssertionError("native scope initialization failed: native_resident_stop_timeout") from None
    if result.returncode == 0:
        raise AssertionError(
            "native scope initialization unexpectedly succeeded: "
            "native_resident_scope_initialization_unexpected_success"
        )
    token = _native_diagnostic(result.stderr)
    assert token == "native_resident_stop_unavailable", f"native scope initialization failed: {token}"
    runtime_digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
    scope = state_dir / f"resident-v3-{runtime_digest[:16]}"
    assert scope.is_dir()
    return scope


def _write_forged_state(runtime: Path, state_dir: Path) -> None:
    runtime_digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
    scope = _initialize_protected_scope(runtime, state_dir)
    token = secrets.token_bytes(32)
    start_marker = process_start_token(os.getpid())
    assert start_marker is not None
    state: dict[str, object] = {
        "schema": "hol-guard-resident-state.v3",
        "generation": 18_000_000_000_000_000_000,
        "process_id": os.getpid(),
        "process_start_marker": start_marker,
        "owner_process_id": os.getpid(),
        "owner_process_start_marker": start_marker,
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
            "process_start_marker",
            "owner_process_id",
            "owner_process_start_marker",
            "runtime_sha256",
            "transport",
            "endpoint",
            "token_hex",
            "created_ms",
        )
    ).encode()
    state["state_mac"] = hmac.new(
        token,
        b"hol-guard-resident-state-v3\x00" + message,
        hashlib.sha256,
    ).hexdigest()
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
