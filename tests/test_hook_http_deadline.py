"""Real loopback headers and bodies cannot renew a hook RPC deadline."""

from __future__ import annotations

import json
import os
import socket
import threading
import time

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_daemon as daemon
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import _render_bounded_hook_script


def identities_from_targets(targets: list[str | None]) -> set[str] | None:
    """Keep stable descriptor targets. A missing target is not a number to compare."""

    stable = {target for target in targets if target}
    if not stable:
        return None
    return stable


def _identity_of(fd: int) -> str | None:
    root = "/proc/self/fd"
    if not os.path.isdir(root):
        return None
    try:
        return os.readlink(f"{root}/{fd}")
    except OSError:
        return None


def open_descriptor_identities() -> set[str] | None:
    """Return stable targets for descriptors the hook could leave open."""

    root = "/proc/self/fd"
    if not os.path.isdir(root):
        return None
    targets = [_identity_of(int(name)) for name in os.listdir(root) if name.isdigit()]
    return identities_from_targets(targets)


@pytest.mark.parametrize("generated", [False, True])
@pytest.mark.parametrize("slow_stage", ["headers", "body", "complete"])
def test_trickling_response_obeys_absolute_rpc_budget(tmp_path, monkeypatch, generated, slow_stage):
    baseline_fds = open_descriptor_identities()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    port = listener.getsockname()[1]
    stopped = threading.Event()
    body = b'{"policy_action":"allow"}'
    header = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode()

    def serve():
        try:
            peer, _ = listener.accept()
            with peer:
                peer.settimeout(1)
                request = b""
                while b"\r\n\r\n" not in request and len(request) < 4096:
                    chunk = peer.recv(4096 - len(request))
                    if not chunk:
                        return
                    request += chunk
                if b"x-guard-token: fixture-token\r\n" not in request.lower():
                    peer.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                    return
                if slow_stage == "complete":
                    peer.sendall(header + body)
                    return
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
        except (OSError, TimeoutError):
            return

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{port}/v1/hooks/grok"
        if generated:
            namespace = {"__name__": "http_deadline_fixture"}
            exec(_render_bounded_hook_script(guard_home=tmp_path, harness="grok", timeout_seconds=2), namespace)
            started = time.monotonic()
            result = namespace["_http_json"](endpoint, "fixture-token", data=b"{}", timeout=0.2)
        else:
            monkeypatch.setattr(daemon, "_daemon_hook_endpoint", lambda *args: endpoint)
            monkeypatch.setattr(daemon, "_read_daemon_auth_token", lambda *args: "fixture-token")
            started = time.monotonic()
            result = daemon.try_daemon_hook(guard_home=tmp_path, harness="grok", input_text="{}", timeout_seconds=0.4)
        elapsed = time.monotonic() - started
        if slow_stage == "complete":
            assert result is not None
            response = result if generated else json.loads(result[0])
            assert response["policy_action"] == "allow"
        else:
            assert result is None, f"Late allow after {elapsed:.3f}s: {result!r}"
        assert elapsed < 0.5, f"RPC budget extended to {elapsed:.3f}s"
    finally:
        stopped.set()
        listener.close()
        thread.join(timeout=3)
        assert not thread.is_alive()
        ending_fds = open_descriptor_identities()
        if baseline_fds is not None and ending_fds is not None:
            leaked = ending_fds - baseline_fds
            assert not leaked, f"hook RPC left file descriptors open: {sorted(leaked)}"


def test_reused_descriptor_number_is_not_a_stable_identity() -> None:
    assert identities_from_targets([None, None]) is None
    before = identities_from_targets(["socket:[10]", "pipe:[2]"])
    after = identities_from_targets(["socket:[99]", "pipe:[2]"])
    assert before is not None and after is not None
    assert after - before == {"socket:[99]"}


def test_open_descriptor_identities_notice_a_new_socket() -> None:
    before = open_descriptor_identities()
    if before is None:
        pytest.skip("descriptor census unavailable")
    leaked: set[str] = set()
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        ident = _identity_of(sock.fileno())
        if ident is None:
            pytest.skip("descriptor target unavailable")
        during = open_descriptor_identities()
        if during is None:
            pytest.skip("descriptor census unavailable")
        leaked = {ident}
        assert ident in during and ident not in before
    finally:
        sock.close()
        after = open_descriptor_identities()
        if after is not None:
            assert leaked.isdisjoint(after)


@pytest.mark.parametrize("generated", [False, True])
def test_expired_discovery_cannot_start_token_read(tmp_path, monkeypatch, generated):
    reads = []

    if generated:
        namespace = {"__name__": "discovery_deadline_fixture"}
        exec(_render_bounded_hook_script(guard_home=tmp_path, harness="grok", timeout_seconds=1), namespace)
        namespace["_HOOK_DEADLINE_MONOTONIC"] = time.monotonic() + 0.01

        def read(path, **kwargs):
            reads.append(path.name)
            if path.name == "daemon-state.json":
                time.sleep(0.03)
                return '{"host":"127.0.0.1","port":4781}'
            return "fixture-token"

        namespace["_read_private_text"] = read
        assert namespace["_daemon_auth"]() is None
        assert reads == ["daemon-state.json"]
    else:

        def endpoint(*args):
            time.sleep(0.03)
            return "http://127.0.0.1:4781/v1/hooks/grok"

        def token(*args):
            reads.append("token")
            return "fixture-token"

        monkeypatch.setattr(daemon, "_daemon_hook_endpoint", endpoint)
        monkeypatch.setattr(daemon, "_read_daemon_auth_token", token)
        result = daemon.try_daemon_hook(guard_home=tmp_path, harness="grok", input_text="{}", timeout_seconds=0.01)
        assert result is None
        assert reads == []
