#!/usr/bin/env python3
"""End-to-end integration proof for the real HOL Guard Rust runtime.

This is intentionally not a unit test. It starts the compiled runtime, sends
one-shot and authenticated resident requests, verifies safe and secret-bearing
PostToolUse decisions, exercises digest and JSON transport failures, and emits
only aggregate privacy-safe evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

REQUEST_MAGIC = b"HGR2"
RESPONSE_MAGIC = b"HGS2"
REQUEST_ID_BYTES = 32
DIGEST_BYTES = 32
HEADER_BYTES = 4 + REQUEST_ID_BYTES + DIGEST_BYTES + 4
SERVER_LABEL = b"hol-guard-resident-server-v1\x00"
CLIENT_LABEL = b"hol-guard-resident-client-v1\x00"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def _request(
    text: str,
    root: Path,
    request_id: str,
    *,
    policy_snapshot_digest: str | None = None,
    observe_mode: bool = False,
) -> bytes:
    payload = {
        "protocol_version": 1,
        "request_id": request_id,
        "harness": "claude-code",
        "event_name": "PostToolUse",
        "payload": {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/example.ts"},
            "tool_response": [{"type": "text", "text": text}],
        },
        "cwd": str(root),
        "home_dir": str(root),
        "guard_home": str(root / "guard-home"),
        "source_ref_external_allowed": False,
        "observe_mode": observe_mode,
        "policy_snapshot_digest": policy_snapshot_digest,
        "deadline_budget_ms": 5_000,
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _json_process(runtime: Path, args: list[str], payload: bytes | None = None) -> dict[str, Any]:
    completed = subprocess.run(
        [str(runtime), *args],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"runtime failed for {args!r}: returncode={completed.returncode}")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"runtime returned invalid JSON for {args!r}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("runtime response must be a JSON object")
    return value


def _read_exact(client: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = client.recv(length - len(output))
        if not chunk:
            raise RuntimeError("resident connection closed before the frame completed")
        output.extend(chunk)
    return bytes(output)


def _authenticate(client: socket.socket, token: bytes) -> None:
    nonce = secrets.token_bytes(32)
    client.sendall(nonce)
    server_proof = _read_exact(client, 32)
    expected_server = hmac.new(token, SERVER_LABEL + nonce, hashlib.sha256).digest()
    if not hmac.compare_digest(server_proof, expected_server):
        raise RuntimeError("resident server authentication proof was invalid")
    client.sendall(hmac.new(token, CLIENT_LABEL + nonce, hashlib.sha256).digest())


def _resident_request(
    socket_path: Path,
    token: bytes,
    payload: bytes,
    *,
    digest_override: bytes | None = None,
) -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5.0)
        client.connect(str(socket_path))
        _authenticate(client, token)

        request_id = secrets.token_bytes(REQUEST_ID_BYTES)
        digest = hashlib.sha256(payload).digest() if digest_override is None else digest_override
        if len(digest) != DIGEST_BYTES:
            raise ValueError("resident request digest must be 32 bytes")
        client.sendall(REQUEST_MAGIC + request_id + digest + len(payload).to_bytes(4, "big") + payload)
        header = _read_exact(client, HEADER_BYTES)
        if header[:4] != RESPONSE_MAGIC:
            raise RuntimeError("resident response magic was invalid")
        if not hmac.compare_digest(header[4 : 4 + REQUEST_ID_BYTES], request_id):
            raise RuntimeError("resident response request id was invalid")
        digest_start = 4 + REQUEST_ID_BYTES
        response_digest = header[digest_start : digest_start + DIGEST_BYTES]
        length = int.from_bytes(header[-4:], "big")
        if length <= 0 or length > MAX_RESPONSE_BYTES:
            raise RuntimeError("resident response length was invalid")
        response = _read_exact(client, length)
        if not hmac.compare_digest(hashlib.sha256(response).digest(), response_digest):
            raise RuntimeError("resident response digest was invalid")
    try:
        value = json.loads(response)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("resident response was invalid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError("resident response must be an object")
    return value




def _policy_snapshot(*, rule_digest: str, scope_byte: str, generation: int, mode: str) -> dict[str, Any]:
    scope_digest = scope_byte * 64
    return {
        "schema": "hol-guard-native-policy.v2",
        "generation": generation,
        "scope_digest": scope_digest,
        "policy_digest": hashlib.sha256(f"policy:{scope_byte}:{mode}".encode()).hexdigest(),
        "config_digest": hashlib.sha256(f"config:{scope_byte}:{mode}".encode()).hexdigest(),
        "rule_digest": rule_digest,
        "mode": mode,
        "security_level": "balanced",
        "global_lockdown": False,
        "managed_restrictions": [],
        "extension_controls": [],
    }


def _install_policy(
    socket_path: Path,
    token: bytes,
    snapshot: dict[str, Any],
) -> str:
    response = _resident_request(
        socket_path,
        token,
        json.dumps(
            {"operation": "install_policy", "request": snapshot},
            separators=(",", ":"),
        ).encode("utf-8"),
    )
    digest = response.get("snapshot_digest")
    if response.get("status") != "installed" or not isinstance(digest, str) or len(digest) != 64:
        raise RuntimeError("resident runtime did not install a native policy snapshot")
    return digest


def _assert_workspace_policy_isolation(
    socket_path: Path,
    token: bytes,
    *,
    root: Path,
    rule_digest: str,
) -> None:
    observe_digest = _install_policy(
        socket_path,
        token,
        _policy_snapshot(rule_digest=rule_digest, scope_byte="a", generation=10, mode="observe"),
    )
    # The second scope intentionally uses a lower generation. A global generation
    # floor would reject this even though it is a distinct workspace authority.
    enforce_digest = _install_policy(
        socket_path,
        token,
        _policy_snapshot(rule_digest=rule_digest, scope_byte="b", generation=3, mode="enforce"),
    )
    secret = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n"
    observed = _resident_request(
        socket_path,
        token,
        _request(
            secret,
            root,
            "workspace-observe",
            policy_snapshot_digest=observe_digest,
            observe_mode=False,
        ),
    )
    enforced = _resident_request(
        socket_path,
        token,
        _request(
            secret,
            root,
            "workspace-enforce",
            policy_snapshot_digest=enforce_digest,
            observe_mode=True,
        ),
    )
    if observed.get("decision") != "allow" or observed.get("observed_policy_action") != "block":
        raise RuntimeError("resident runtime did not select the observe workspace snapshot exactly")
    if enforced.get("decision") != "deny" or enforced.get("model_output_action") != "block":
        raise RuntimeError("resident runtime did not select the enforce workspace snapshot exactly")
    unknown = _resident_request(
        socket_path,
        token,
        _request(secret, root, "workspace-unknown", policy_snapshot_digest="f" * 64),
    )
    if unknown != {"error": "native_policy_snapshot_not_installed", "retryable": False}:
        raise RuntimeError("resident runtime did not fail closed on an unknown policy snapshot")


def _wait_for_socket(process: subprocess.Popen[bytes], socket_path: Path) -> None:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("resident runtime exited before becoming ready")
        if socket_path.exists():
            return
        time.sleep(0.01)
    raise RuntimeError("resident runtime did not create its socket")


def _assert_decisions(safe: dict[str, Any], secret: dict[str, Any]) -> None:
    if safe.get("decision") != "allow" or safe.get("model_output_action") != "allow_original":
        raise RuntimeError("safe content was not allowed by Rust")
    if secret.get("decision") != "deny" or secret.get("model_output_action") != "block":
        raise RuntimeError("secret-bearing content was not blocked by Rust")
    if "reviewed_excerpt" in secret:
        raise RuntimeError("blocked secret-bearing content leaked an excerpt")


def _assert_transport_faults(socket_path: Path, token: bytes) -> None:
    digest_mismatch = _resident_request(
        socket_path,
        token,
        b'{"operation":"health","request":{}}',
        digest_override=b"\x00" * DIGEST_BYTES,
    )
    if digest_mismatch != {"error": "native_request_digest_mismatch", "retryable": False}:
        raise RuntimeError("resident runtime did not reject a digest-mismatched frame deterministically")

    invalid_json = _resident_request(socket_path, token, b'{"operation":')
    if invalid_json != {"error": "native_request_invalid_json", "retryable": False}:
        raise RuntimeError("resident runtime did not reject malformed JSON deterministically")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--faults", action="store_true")
    args = parser.parse_args()
    runtime = args.runtime.resolve(strict=True)
    if not runtime.is_file() or runtime.is_symlink():
        raise SystemExit("runtime must be a regular non-symlink file")

    started = time.perf_counter()
    capabilities = _json_process(runtime, ["capabilities", "--json"])
    features = capabilities.get("features")
    if not isinstance(features, list) or "resident-protocol-v2" not in features:
        raise RuntimeError("runtime does not advertise resident protocol v2")

    transport_faults_passed = False
    with tempfile.TemporaryDirectory(prefix="hol-guard-rust-authority-") as temporary:
        root = Path(temporary)
        (root / "guard-home").mkdir(mode=0o700)
        safe_payload = _request("export const value = 1;\n" * 32, root, "oneshot-safe")
        secret_payload = _request("-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n", root, "oneshot-secret")
        oneshot_safe = _json_process(runtime, ["hook", "--stdin"], safe_payload)
        oneshot_secret = _json_process(runtime, ["hook", "--stdin"], secret_payload)
        _assert_decisions(oneshot_safe, oneshot_secret)

        private_runtime = root / "resident"
        private_runtime.mkdir(mode=0o700)
        socket_path = private_runtime / "hook.sock"
        token = secrets.token_bytes(32)
        process = subprocess.Popen(
            [str(runtime), "serve", "--socket", str(socket_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdin is not None
        process.stdin.write(token.hex().encode("ascii") + b"\n")
        process.stdin.close()
        try:
            _wait_for_socket(process, socket_path)
            resident_safe = _resident_request(socket_path, token, safe_payload)
            resident_secret = _resident_request(socket_path, token, secret_payload)
            _assert_decisions(resident_safe, resident_secret)
            rule_digest = capabilities.get("rule_digest")
            if not isinstance(rule_digest, str) or len(rule_digest) != 64:
                raise RuntimeError("runtime did not report a valid rule digest")
            _assert_workspace_policy_isolation(
                socket_path,
                token,
                root=root,
                rule_digest=rule_digest,
            )
            if args.faults:
                _assert_transport_faults(socket_path, token)
                transport_faults_passed = True
        finally:
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)

    evidence = {
        "schema": "hol-guard-rust-authority-integration.v1",
        "runtime_protocol": capabilities.get("protocol_version"),
        "runtime_rule_digest_present": isinstance(capabilities.get("rule_digest"), str)
        and len(str(capabilities.get("rule_digest"))) == 64,
        "oneshot_safe": True,
        "oneshot_secret_blocked": True,
        "resident_safe": True,
        "resident_secret_blocked": True,
        "workspace_policy_isolation": True,
        "transport_faults_requested": args.faults,
        "transport_faults_passed": transport_faults_passed,
        "python_decision_fallbacks": 0,
        "elapsed_ms": round((time.perf_counter() - started) * 1_000, 3),
    }
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.json is not None:
        args.json.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
