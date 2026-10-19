"""Actual key-free client/relay/server custody and owned lifecycle cleanup."""
from __future__ import annotations

import os
import socket
import tempfile
import time
from pathlib import Path

import anyio
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ci.gauntlet.benchmark.catalog import load_fixture
from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.service_relay import validate_frame
from ci.gauntlet.benchmark.service_supervisor import ServiceSupervisor
from ci.gauntlet.benchmark.world import World


@pytest.fixture
def custody():
    with tempfile.TemporaryDirectory(prefix="bm-mcp-", dir="/tmp") as directory:
        root = Path(directory).resolve()
        world = World.create(root / "world.db", load_fixture("business-sales-lead-qualification"),
                            signing_key=Ed25519PrivateKey.generate())
        yield world, root / "sockets"


def wait_until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("owned service did not reach expected lifecycle state")
        time.sleep(0.02)


def test_real_relay_route_has_no_key_or_db_and_proves_forwarding_effect(custody):
    world, directory = custody
    observed = []
    with ServiceSupervisor(world, directory, families=("mail",), observer=observed.append) as supervisor:
        endpoint = supervisor.endpoint("mail")
        assert "--signing-key-fd" not in endpoint.command
        assert str(world.path) not in endpoint.command
        assert endpoint.environment == ()
        assert directory.stat().st_mode & 0o777 == 0o700
        assert supervisor.sockets["mail"].stat().st_mode & 0o777 == 0o600

        async def episode():
            params = StdioServerParameters(command=endpoint.command[0], args=list(endpoint.command[1:]))
            async with stdio_client(params) as (inbound, outbound), ClientSession(inbound, outbound) as client:
                with anyio.fail_after(10):
                    initialized = await client.initialize()
                    assert initialized.protocolVersion == "2025-11-25"
                    names = {tool.name for tool in (await client.list_tools()).tools}
                    assert "mail.create_draft" in names
                    created = await client.call_tool("mail.create_draft", {
                        "record_id": "draft-relayed", "data": {"body": "persisted through relay",
                        "recipients": ["local@example.test"]}})
                    assert created.structuredContent["id"] == "draft-relayed"
            wait_until(lambda: supervisor.active_children == 0)

        anyio.run(episode)
        assert world.inspect("draft-relayed")["data"]["body"] == "persisted through relay"
        frames = [item for item in observed if item["kind"] == "frame"]
        forwarded = [item for item in frames if item["direction"] == "client-to-service"
                     and item["message"].get("method") == "tools/call"]
        responses = [item for item in frames if item["direction"] == "service-to-client"
                     and item["message"].get("id") == forwarded[0]["message"]["id"]]
        assert len(forwarded) == 1 and len(responses) == 1
        assert forwarded[0]["session_id"] == responses[0]["session_id"]
        complete = [item for item in observed if item["kind"] == "forwarded"
                    and item["message"].get("method") == "tools/call"]
        assert complete[0]["message"] == forwarded[0]["message"]
        delivered = [item for item in observed if item["kind"] == "delivered"
                     and item["message"].get("id") == forwarded[0]["message"]["id"]]
        assert delivered[0]["message"] == responses[0]["message"]
        assert str(world.receipts()[0]["event"]["request_id"]) == str(forwarded[0]["message"]["id"])
        assert world.key.private_bytes_raw().hex() not in canonical_json(observed)
        starts = [item for item in observed if item["kind"] == "child-started"]
        reaped = [item for item in observed if item["kind"] == "child-reaped"]
        assert starts[0]["pid"] == reaped[0]["pid"]
        assert starts[0]["environment_keys"] == ["PATH", "PYTHONPATH"]
        assert reaped[0]["returncode"] == 0
    assert not directory.exists()
    assert observed[-1]["kind"] == "closed" and observed[-1]["active_children"] == 0


def test_wrong_peer_uid_never_spawns_service(custody):
    world, directory = custody
    with ServiceSupervisor(world, directory, allowed_uid=os.getuid() + 1, families=("mail",)) as supervisor:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(str(supervisor.sockets["mail"]))
            assert connection.recv(1) == b""
        wait_until(lambda: any(item["kind"] == "session-rejected" for item in supervisor.events))
        assert not any(item["kind"] == "child-started" for item in supervisor.events)
        assert supervisor.active_children == 0
    assert world.receipts() == []


def test_cancellation_reaps_idle_owned_child_and_removes_only_owned_socket(custody):
    world, directory = custody
    supervisor = ServiceSupervisor(world, directory, families=("mail",)).start()
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(str(supervisor.sockets["mail"]))
    wait_until(lambda: supervisor.active_children == 1)
    supervisor.close()
    connection.close()
    assert supervisor.active_children == 0
    assert not directory.exists()
    assert any(item["kind"] == "child-reaped" for item in supervisor.events)
    assert world.path.exists()
    assert world.receipts() == []


def test_frame_budget_disconnect_cannot_reach_fixture_effect(custody):
    world, directory = custody
    with ServiceSupervisor(world, directory, families=("mail",), max_frame_bytes=128) as supervisor:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(supervisor.sockets["mail"]))
            connection.sendall(b"x" * 129)
            wait_until(lambda: any(item["kind"] == "session-error" for item in supervisor.events))
        wait_until(lambda: supervisor.active_children == 0)
    assert world.receipts() == []


def test_observer_failure_stops_route_without_exposing_key(custody):
    world, directory = custody

    def unavailable(_event):
        raise RuntimeError("collector unavailable")

    with ServiceSupervisor(world, directory, families=("mail",), observer=unavailable) as supervisor:
        with pytest.raises(ValueError, match="active"):
            supervisor.endpoint("mail")
        assert any(item["kind"] == "observer-error" for item in supervisor.events)
    assert supervisor.active_children == 0


@pytest.mark.parametrize("line", [b'{"jsonrpc":"2.0","id":1,"id":2}',
                                  b'{"jsonrpc":"2.0","id":NaN}', b'[]', b'{"jsonrpc":"1.0"}'])
def test_ambiguous_or_invalid_frames_fail_closed(line):
    with pytest.raises(ValueError):
        validate_frame(line)


def test_supervisor_never_overwrites_an_existing_directory(custody):
    world, directory = custody
    directory.mkdir()
    unrelated = directory / "keep.txt"
    unrelated.write_text("unrelated")
    with pytest.raises(FileExistsError):
        ServiceSupervisor(world, directory).start()
    assert unrelated.read_text() == "unrelated"
