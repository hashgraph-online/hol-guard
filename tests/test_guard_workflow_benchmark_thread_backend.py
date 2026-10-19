"""Real official clients through authenticated sockets into controller MCP workers."""

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

from ci.gauntlet.benchmark.approval_transport import ApprovalTransport
from ci.gauntlet.benchmark.catalog import load_approval_variants, load_fixture
from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.service_supervisor import ServiceSupervisor
from ci.gauntlet.benchmark.world import World


@pytest.fixture
def custody():
    with tempfile.TemporaryDirectory(prefix="bm-thread-", dir="/tmp") as directory:
        root = Path(directory).resolve()
        variant = next(
            row for row in load_approval_variants() if row["domain"] == "sales" and row["decision"] == "granted"
        )
        world = World.create(
            root / "world.db", load_fixture(variant["workflow_id"]), signing_key=Ed25519PrivateKey.generate()
        )
        yield world, root / "sockets", variant


def wait_until(predicate):
    deadline = time.monotonic() + 8
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("controller worker did not reach expected lifecycle state")
        time.sleep(0.02)


def parameters(endpoint):
    return StdioServerParameters(command=endpoint.command[0], args=list(endpoint.command[1:]))


def test_two_actual_mcp_channels_share_external_controller_without_exporting_key(custody):
    world, directory, variant = custody
    facade = ApprovalTransport(world, variant, clock=lambda: 1000)
    with ServiceSupervisor(
        world, directory, families=("mail", "crm"), service_factory=lambda _family: facade
    ) as supervisor:
        mail, crm = supervisor.endpoint("mail"), supervisor.endpoint("crm")
        assert "--signing-key-fd" not in mail.command
        assert str(world.path) not in mail.command

        async def exercise():
            async with (
                stdio_client(parameters(mail)) as (mi, mo),
                ClientSession(mi, mo) as mail_client,
                stdio_client(parameters(crm)) as (ci, co),
                ClientSession(ci, co) as crm_client,
            ):
                with anyio.fail_after(15):
                    await mail_client.initialize()
                    await crm_client.initialize()
                    assert supervisor.active_workers == 2 and supervisor.active_children == 0
                    names = {tool.name for tool in (await mail_client.list_tools()).tools}
                    assert not any("grant" in name or "decide" in name for name in names)
                    responses = {}

                    async def prepare_draft():
                        responses["draft"] = await mail_client.call_tool(
                            "mail.create_draft",
                            {
                                "record_id": variant["target_id"],
                                "data": {"body": "Actual local preparation", "recipients": ["local@example.test"]},
                            },
                        )

                    async def read_contact():
                        responses["contact"] = await crm_client.call_tool("crm.read", {"record_id": "contact-a"})

                    async with anyio.create_task_group() as tasks:
                        tasks.start_soon(prepare_draft)
                        tasks.start_soon(read_contact)
                    assert not responses["draft"].isError
                    assert not responses["contact"].isError
                    assert responses["contact"].structuredContent["id"] == "contact-a"
                    args = {"record_id": variant["target_id"], "expected_version": 1}
                    pending = await mail_client.call_tool("mail.send", args)
                    assert pending.isError and pending.structuredContent["approval_status"] == "pending"
                    assert world.inspect(variant["target_id"])["collection"] == "mail.drafts"
                    facade.decide(pending.structuredContent["intent_id"], decision="granted")
                    sent = await mail_client.call_tool("mail.send", args)
                    retry = await mail_client.call_tool("mail.send", args)
                    assert sent.structuredContent == retry.structuredContent
                    assert sent.structuredContent["collection"] == "mail.outbox"
                    assert len([r for r in world.receipts() if r["event"]["operation"] == "mail.send"]) == 1
            wait_until(lambda: supervisor.active_sessions == 0)

        anyio.run(exercise)
        assert not any(event["kind"] == "child-started" for event in supervisor.events)
        assert len([event for event in supervisor.events if event["kind"] == "server-worker-stopped"]) == 2
        assert world.key.private_bytes_raw().hex() not in canonical_json(supervisor.events)
        assert facade._controller._private_key.private_bytes_raw().hex() not in canonical_json(supervisor.events)
    assert not directory.exists()
    assert supervisor.events[-1]["active_workers"] == 0
    assert supervisor.events[-1]["active_children"] == 0
    assert supervisor.events[-1]["active_sessions"] == 0


def test_actual_sdk_handler_errors_remain_errors_and_worker_can_close(custody):
    world, directory, _ = custody

    class FailingWorld:
        def call(self, *_args, **_kwargs):
            raise ValueError("actual controlled handler failure")

    with ServiceSupervisor(
        world, directory, families=("crm",), service_factory=lambda _family: FailingWorld()
    ) as supervisor:

        async def exercise():
            async with (
                stdio_client(parameters(supervisor.endpoint("crm"))) as (incoming, outgoing),
                ClientSession(incoming, outgoing) as client,
            ):
                with anyio.fail_after(10):
                    await client.initialize()
                    for _ in range(2):
                        failed = await client.call_tool("crm.read", {"record_id": "contact-a"})
                        assert failed.isError
            wait_until(lambda: supervisor.active_sessions == 0)

        anyio.run(exercise)
    assert world.receipts() == []
    assert supervisor.active_workers == 0


def test_cancellation_reaps_idle_inprocess_worker_and_preserves_world(custody):
    world, directory, _ = custody
    supervisor = ServiceSupervisor(world, directory, families=("mail",), service_factory=lambda _family: world).start()
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(str(supervisor.sockets["mail"]))
    wait_until(lambda: supervisor.active_workers == 1)
    assert supervisor.active_children == 0
    supervisor.close()
    connection.close()
    assert supervisor.active_workers == supervisor.active_sessions == 0
    assert not directory.exists() and world.path.exists()
    assert world.receipts() == []
    assert any(row["kind"] == "server-worker-stopped" for row in supervisor.events)


@pytest.mark.parametrize("budget", ["idle", "frame"])
def test_lifecycle_and_frame_budgets_stop_real_workers_without_effect(custody, budget):
    world, directory, _ = custody
    options = {"idle_timeout": 0.2} if budget == "idle" else {"max_frame_bytes": 128}
    with (
        ServiceSupervisor(
            world, directory, families=("mail",), service_factory=lambda _family: world, **options
        ) as supervisor,
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection,
    ):
        connection.connect(str(supervisor.sockets["mail"]))
        if budget == "frame":
            connection.sendall(b"x" * 129)
        wait_until(lambda: any(row["kind"] == "session-error" for row in supervisor.events))
        wait_until(lambda: supervisor.active_sessions == 0)
    assert supervisor.active_workers == 0 and world.receipts() == []


def test_wrong_peer_never_constructs_controller_service(custody):
    world, directory, _ = custody
    constructed = []

    def factory(family):
        constructed.append(family)
        return world

    with ServiceSupervisor(
        world, directory, families=("mail",), allowed_uid=os.getuid() + 1, service_factory=factory
    ) as supervisor:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(supervisor.sockets["mail"]))
            assert connection.recv(1) == b""
        wait_until(lambda: any(row["kind"] == "session-rejected" for row in supervisor.events))
    assert constructed == [] and world.receipts() == []


def test_signed_controller_denial_over_real_socket_never_delivers(custody):
    world, directory, _ = custody
    variant = next(row for row in load_approval_variants() if row["domain"] == "sales" and row["decision"] == "denied")
    facade = ApprovalTransport(world, variant, clock=lambda: 1000)
    with ServiceSupervisor(world, directory, families=("mail",), service_factory=lambda _family: facade) as supervisor:

        async def exercise():
            async with (
                stdio_client(parameters(supervisor.endpoint("mail"))) as (incoming, outgoing),
                ClientSession(incoming, outgoing) as client,
            ):
                with anyio.fail_after(10):
                    await client.initialize()
                    await client.call_tool(
                        "mail.create_draft",
                        {
                            "record_id": variant["target_id"],
                            "data": {"body": "Preserved preparation", "recipients": ["local@example.test"]},
                        },
                    )
                    args = {"record_id": variant["target_id"], "expected_version": 1}
                    pending = await client.call_tool("mail.send", args)
                    facade.decide(pending.structuredContent["intent_id"], decision="denied")
                    denied = await client.call_tool("mail.send", args)
                    assert denied.isError and denied.structuredContent["approval_status"] == "denied"
            wait_until(lambda: supervisor.active_sessions == 0)

        anyio.run(exercise)
    assert world.inspect(variant["target_id"])["collection"] == "mail.drafts"
    assert len(world.receipts()) == 1


def test_total_message_budget_ends_controller_worker_before_tool_effect(custody):
    world, directory, _ = custody
    with ServiceSupervisor(
        world, directory, families=("mail",), service_factory=lambda _family: world, max_messages=1
    ) as supervisor:
        initialize = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "budget-client", "version": "1"},
            },
        }
        initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(supervisor.sockets["mail"]))
            connection.sendall((canonical_json(initialize) + "\n" + canonical_json(initialized) + "\n").encode())
            wait_until(lambda: any(row["kind"] == "session-error" for row in supervisor.events))
            wait_until(lambda: supervisor.active_sessions == 0)
    assert world.receipts() == [] and supervisor.active_workers == 0
