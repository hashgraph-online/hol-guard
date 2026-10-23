"""Root custody and real CLI binding checks; mocks never claim Guard efficacy."""
from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import anyio
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ci.gauntlet.benchmark import native_mcp_supervisor as module
from ci.gauntlet.benchmark.catalog import load_fixture
from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.service_supervisor import ServiceSupervisor
from ci.gauntlet.benchmark.world import World

SOURCE = "a" * 40


@pytest.fixture
def planned(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "src"))
    with tempfile.TemporaryDirectory(prefix="native-front-", dir="/tmp") as directory:
        root = Path(directory).resolve()
        world = World.create(root / "world.db", load_fixture("business-support-ticket-resolution"),
                             signing_key=Ed25519PrivateKey.generate())
        upstream = ServiceSupervisor(world, root / "upstream", allowed_uid=0, families=("tickets",))
        upstream.start()
        # Planning fixture simulates root custody. Actual Linux checks remain
        # mandatory in production; live VM evidence is separate from these mocks.
        monkeypatch.setattr(module.sys, "platform", "linux")
        monkeypatch.setattr(module.os, "geteuid", lambda: 0)
        monkeypatch.setattr(module, "require_root_private", lambda *args, **kwargs: None)
        monkeypatch.setattr(module, "inspect_installed_guard", lambda *args, **kwargs: {
            "manifest": {"source_sha": SOURCE}, "capabilities": {"build_sha": SOURCE}, "installed": True})
        monkeypatch.setattr(module.NativeMcpSupervisor, "_daemon", lambda *args: subprocess.CompletedProcess([], 0))
        front = module.NativeMcpSupervisor(root / "public", upstream=upstream, python=Path("/usr/bin/python"),
            expected_source_sha=SOURCE, private_root=root / "private", allowed_uid=os.getuid(), socket_gid=None)
        try:
            yield root, world, upstream, front
        finally:
            front.close()
            upstream.close()


def test_public_endpoint_contains_only_relay_and_public_socket(planned):
    root, world, upstream, front = planned
    front.start()
    endpoint = front.endpoint("tickets")
    assert endpoint.command[-1] == str(root / "public" / "tickets.sock")
    assert str(world.path) not in endpoint.command
    assert str(front.guard_home) not in str(endpoint)
    assert str(upstream.directory) not in str(endpoint)
    assert endpoint.environment == ()
    route = front._routes["tickets"].command
    assert route[:5] == ("/usr/bin/python", "-m", "codex_plugin_scanner.cli", "guard", "omp-mcp-proxy")
    assert str(front.guard_home) in route and str(front.config_path) in route
    assert "--arg=" + str(upstream.sockets["tickets"]) in route
    assert "--signing-key-fd" not in str(route) and str(world.path) not in str(route)
    assert front.private_root.stat().st_mode & 0o777 == 0o700
    assert (front.guard_home / "config.toml").stat().st_mode & 0o777 == 0o600


def test_native_child_receives_actual_cli_and_scrubbed_root_environment(planned, monkeypatch):
    _, world, _, front = planned
    front.start()
    captured = {}
    pipes = []

    class Child:
        pid = 1234

        def __init__(self):
            read_fd, write_fd = os.pipe()
            self.stdin = os.fdopen(write_fd, "wb")
            self.stdout = os.fdopen(read_fd, "rb")
            pipes.extend([self.stdin, self.stdout])

    def spawn(command, **kwargs):
        captured.update(command=command, **kwargs)
        return Child()

    monkeypatch.setattr(module.subprocess, "Popen", spawn)
    monkeypatch.setattr(module, "_custody_identity", lambda pid: {
        "effective_uid": 0, "mount_namespace": "controller-mount", "pid_namespace": "controller-pid",
        "network_namespace": "controller-network"})
    process = front._spawn("tickets", "trusted-session")
    try:
        assert captured["command"] == list(front._routes["tickets"].command)
        assert captured["close_fds"] is True and "pass_fds" not in captured
        assert captured["env"] == {"PATH": "/usr/bin:/usr/bin:/bin", "HOME": str(front.home), "LANG": "C.UTF-8"}
        assert captured["cwd"] == front.workspace
        assert world.key.private_bytes_raw().hex() not in canonical_json(front.events)
        assert front._children["trusted-session"] is process
    finally:
        front._children.clear()
        for pipe in pipes:
            pipe.close()
    front.close()
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs:
        subprocess.CompletedProcess([], 0, b"[]", b""))
    anchor = Ed25519PrivateKey.generate()
    audit = front.collect_audit(controller_key=anchor)
    anchor.public_key().verify(base64.b64decode(audit["signature"]), canonical_json(audit["record"]).encode())
    process_evidence = next(event for event in audit["record"]["transport_observations"]
                            if event["kind"] == "child-started")
    assert process_evidence["product_identity"] == process_evidence["controller_identity"]
    assert process_evidence["product_identity"]["effective_uid"] == 0


@pytest.mark.parametrize("bad_scope", ["public-upstream", "public-private-root", "not-root-upstream"])
def test_private_upstream_and_custody_cannot_be_public_mount(planned, bad_scope):
    root, _, upstream, _ = planned
    directory, private = root / "other-public", root / "other-private"
    if bad_scope == "public-upstream":
        directory = upstream.directory
    elif bad_scope == "public-private-root":
        private = directory / "private"
    else:
        upstream.allowed_uid = 10001
    with pytest.raises(ValueError):
        module.NativeMcpSupervisor(directory, upstream=upstream, python=Path("/usr/bin/python"),
            expected_source_sha=SOURCE, private_root=private)


def test_nonlinux_or_nonroot_never_creates_private_state(tmp_path, monkeypatch):
    monkeypatch.setattr(module.sys, "platform", "darwin")
    with pytest.raises(ValueError, match="Linux root"):
        module.NativeMcpSupervisor(tmp_path / "public", upstream=None, python=Path("/usr/bin/python"),
            expected_source_sha=SOURCE, private_root=tmp_path / "private")
    assert not (tmp_path / "private").exists()


def test_audit_attests_actual_collector_output_and_rejects_nonfinite_duplicate(planned, monkeypatch):
    _, _, _, front = planned
    front.start()
    front.close()
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs:
        subprocess.CompletedProcess([], 0, b'[{"decision":"allow","source":"native"}]', b""))
    evidence = front.collect_audit(controller_key=key)
    key.public_key().verify(base64.b64decode(evidence["signature"]), canonical_json(evidence["record"]).encode())
    assert evidence["record"]["product_events"] == [{"decision": "allow", "source": "native"}]
    assert evidence["record"]["qualification_eligible"] is False
    assert "list_events(limit=1001)" in module._EVENTS
    with pytest.raises(InvalidSignature):
        Ed25519PrivateKey.generate().public_key().verify(base64.b64decode(evidence["signature"]),
            canonical_json(evidence["record"]).encode())
    for payload in (b'[{"value":NaN}]', b'[{"value":1,"value":2}]', b'{"model":"claim"}',
                    json.dumps([{"event_id": index} for index in range(1001)]).encode()):
        monkeypatch.setattr(module.subprocess, "run", lambda *args, captured=payload, **kwargs:
            subprocess.CompletedProcess([], 0, captured, b""))
        with pytest.raises(ValueError):
            front.collect_audit(controller_key=key)


def test_failed_daemon_cleanup_blocks_audit(planned, monkeypatch):
    _, _, _, front = planned
    front.start()
    monkeypatch.setattr(front, "_daemon", lambda op: subprocess.CompletedProcess([], 1))
    front.close()
    with pytest.raises(ValueError, match="closed and reaped"):
        front.collect_audit(controller_key=Ed25519PrivateKey.generate())


@pytest.mark.parametrize("boundary", ["uid", "namespace"])
def test_untrusted_product_process_identity_is_killed_before_forwarding(planned, monkeypatch, boundary):
    _, _, _, front = planned
    front.start()
    original_spawn = subprocess.Popen
    spawned = []

    def controlled_process(*args, **kwargs):
        process = original_spawn([sys.executable, "-c", "import time; time.sleep(60)"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        spawned.append(process)
        return process

    def identity(pid):
        observed = {"effective_uid": 0, "mount_namespace": "controller", "pid_namespace": "controller",
                    "network_namespace": "controller"}
        if pid != os.getpid():
            field = "effective_uid" if boundary == "uid" else "pid_namespace"
            observed[field] = 10001 if boundary == "uid" else "agent"
        return observed

    monkeypatch.setattr(module.subprocess, "Popen", controlled_process)
    monkeypatch.setattr(module, "_custody_identity", identity)
    with pytest.raises(ValueError, match="escaped"):
        front._spawn("tickets", "rejected-native-process")
    assert spawned[0].poll() is not None
    assert front.active_children == 0 and front.active_sessions == 0
    assert not any(event["kind"] == "forwarded" for event in front.events)


def test_official_client_protocol_relay_is_real_and_wrong_uid_never_spawns(planned, monkeypatch):
    _, world, _upstream, front = planned
    # This tests only the inherited bounded transport with a real provider
    # backend, explicitly replacing Guard for this test; no protection credit.
    monkeypatch.setattr(module, "peer_uid", lambda connection: os.getuid())
    monkeypatch.setattr("ci.gauntlet.benchmark.service_supervisor.peer_uid", lambda connection: os.getuid())
    front.world = world  # Explicit provider-only test double; production frontdoor world is None.
    monkeypatch.setattr(front, "_spawn", lambda family, session_id: ServiceSupervisor._spawn(front, family, session_id))
    front.start()
    endpoint = front.endpoint("tickets")

    async def call():
        params = StdioServerParameters(command=endpoint.command[0], args=list(endpoint.command[1:]))
        async with stdio_client(params) as streams, ClientSession(*streams) as client:
            with anyio.fail_after(10):
                await client.initialize()
                result = await client.call_tool("tickets.read", {"record_id": "ticket-a"})
                assert result.structuredContent["id"] == "ticket-a"

    anyio.run(call)
    assert len(world.receipts()) == 1
    assert any(event["kind"] == "peer-authenticated" for event in front.events)
    front.allowed_uid = os.getuid() + 1
    count = len(world.receipts())
    with socket.socket(socket.AF_UNIX) as denied:
        denied.settimeout(2)
        denied.connect(str(front.sockets["tickets"]))
        assert denied.recv(1) == b""
    assert len(world.receipts()) == count
    assert any(event["kind"] == "peer-observed-rejected" for event in front.events)
    deadline = time.monotonic() + 5
    while front.active_children and time.monotonic() < deadline:
        time.sleep(0.02)
    assert front.active_children == 0
