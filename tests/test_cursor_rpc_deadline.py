"""Cursor daemon discovery must not outlive its original operation budget."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import threading
import time
from pathlib import Path

import pytest

from .test_cursor_hook_deadline import _hook_namespace
from .test_hook_http_deadline import open_descriptor_identities


@pytest.mark.parametrize(
    "target,slow_stage",
    [(target, stage) for target in ("health", "verify", "hook") for stage in ("headers", "body")]
    + [("complete", ""), ("oversize", ""), ("error", "body")],
)
def test_cursor_rpc_obeys_original_deadline(tmp_path, target, slow_stage):
    namespace = _hook_namespace(tmp_path)
    baseline_fds = open_descriptor_identities()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.5)
    home = Path(namespace["GUARD_HOME"])
    home.chmod(0o700)
    (home / "daemon-state.json").write_text(json.dumps({"port": listener.getsockname()[1], "pid": os.getpid()}))
    (home / "daemon-auth-token").write_text("fixture-token")
    for name in ("daemon-state.json", "daemon-auth-token"):
        (home / name).chmod(0o600)
    stopped = threading.Event()
    port = listener.getsockname()[1]

    def serve():
        try:
            while not stopped.is_set():
                try:
                    peer, _ = listener.accept()
                except TimeoutError:
                    continue
                with peer:
                    peer.settimeout(1)
                    request = b""
                    while b"\r\n\r\n" not in request and len(request) < 10_000:
                        chunk = peer.recv(10_000 - len(request))
                        if not chunk:
                            return
                        request += chunk
                    headers, payload = request.split(b"\r\n\r\n", 1)
                    length = next(
                        (
                            int(line.split(b":", 1)[1])
                            for line in headers.lower().split(b"\r\n")
                            if line.startswith(b"content-length:")
                        ),
                        0,
                    )
                    if length > 10_000:
                        return
                    while len(payload) < length:
                        chunk = peer.recv(length - len(payload))
                        if not chunk:
                            return
                        payload += chunk
                    path = headers.split(b" ", 2)[1]
                    if path == b"/healthz":
                        phase = "health"
                        assert b"x-guard-token:" not in headers.lower()
                        body = b'{"ok":true,"compatibility_version":"fixture"}'
                        if target == "oversize":
                            body = b'{"ok":true,"padding":"' + b"x" * 1_000_000 + b'"}'
                    elif path == b"/v1/healthz/verify":
                        phase = "verify"
                        assert b"x-guard-token:" not in headers.lower()
                        nonce = json.loads(payload)["nonce"]
                        proof = hmac.new(b"fixture-token", f"{port}:{nonce}".encode(), hashlib.sha256).hexdigest()
                        body = json.dumps({"proof": proof}).encode()
                    else:
                        phase = "hook"
                        assert b"x-guard-token: fixture-token" in headers.lower()
                        body = b'{"policy_action":"allow"}'
                    status = "503 Unavailable" if target == "error" and phase == "hook" else "200 OK"
                    header = f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n\r\n".encode()
                    if target == phase or (target == "error" and phase == "hook"):
                        if slow_stage == "body":
                            peer.sendall(header)
                        for value in header if slow_stage == "headers" else body:
                            if stopped.is_set():
                                return
                            peer.sendall(bytes([value]))
                            if stopped.wait(0.03):
                                return
                        if slow_stage == "headers":
                            peer.sendall(body)
                    else:
                        peer.sendall(header + body)
        except OSError:
            return

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        started = time.monotonic()
        result = namespace["_daemon_hook_result"]("{}", deadline_monotonic=started + 0.2, workspace=None)
        elapsed = time.monotonic() - started
        assert elapsed < 0.5, f"Cursor discovery extended to {elapsed:.3f}s"
        if target == "complete":
            assert result[1] is None
            assert result[0] is not None
            assert json.loads(result[0][1])["policy_action"] == "allow"
        elif target == "oversize":
            assert result == (None, "authenticated-control-plane-failure")
        elif target == "error":
            assert result == (None, "overload")
        else:
            assert result == (None, "timeout")
    finally:
        stopped.set()
        listener.close()
        thread.join(timeout=3)
        assert not thread.is_alive()
        ending_fds = open_descriptor_identities()
        if baseline_fds is not None and ending_fds is not None:
            leaked = ending_fds - baseline_fds
            assert not leaked, f"Cursor RPC left file descriptors open: {sorted(leaked)}"


def test_cursor_expired_discovery_cannot_start_token_read(tmp_path, monkeypatch):
    namespace = _hook_namespace(tmp_path)
    reads = []

    def read(path, **kwargs):
        reads.append(path.name)
        if path.name == "daemon-state.json":
            time.sleep(0.03)
            return json.dumps({"port": 4781, "pid": os.getpid()})
        pytest.fail("Expired discovery must not start a token read")

    monkeypatch.setattr(Path, "read_text", read)
    result = namespace["_daemon_hook_result"]("{}", deadline_monotonic=time.monotonic() + 0.01, workspace=None)
    assert result == (None, "timeout")
    assert reads == ["daemon-state.json"]
