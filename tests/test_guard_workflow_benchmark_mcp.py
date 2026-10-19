"""Official MCP client sessions against actual stateful stdio service processes."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import pytest
from anyio.streams.buffered import BufferedByteReceiveStream
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import ClientSession, types
from mcp.shared.message import SessionMessage

from ci.gauntlet.benchmark.catalog import load_fixture
from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.mcp_server import create_server, read_signing_key_pipe
from ci.gauntlet.benchmark.world import COLLECTIONS, World, verify_receipts

REPO = Path(__file__).resolve().parents[1]


@asynccontextmanager
async def client(world: World, family: str, *, artifact_workflow_id=None):
    """A supervisor-owned SDK transport with one inherited key pipe.

The SDK's public stdio helper has no pass_fds parameter, so this bounded
transport supplies its normal SessionMessage streams to ClientSession.
"""
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, world.key.private_bytes_raw())
    finally:
        os.close(write_fd)
    try:
        process = await anyio.open_process(
            [sys.executable, "-m", "ci.gauntlet.benchmark.mcp_server", "--db", str(world.path),
             "--family", family, "--signing-key-fd", str(read_fd),
             *(['--artifact-workflow-id',artifact_workflow_id] if artifact_workflow_id else [])],
            pass_fds=(read_fd,), cwd=REPO, stderr=sys.stderr,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO)},
        )
    finally:
        os.close(read_fd)
    inbound_writer, inbound_reader = anyio.create_memory_object_stream(0)
    outbound_writer, outbound_reader = anyio.create_memory_object_stream(0)

    async def receive():
        buffered = BufferedByteReceiveStream(process.stdout)
        async with inbound_writer:
            while True:
                try:
                    line = await buffered.receive_until(b"\n", 2 * 1024 * 1024)
                except anyio.EndOfStream:
                    return
                except anyio.IncompleteRead:
                    if buffered.buffer:
                        raise
                    return
                await inbound_writer.send(SessionMessage(types.JSONRPCMessage.model_validate_json(line)))

    async def send():
        async with outbound_reader:
            async for item in outbound_reader:
                payload = item.message.model_dump_json(by_alias=True, exclude_none=True)
                await process.stdin.send((payload + "\n").encode())

    async with anyio.create_task_group() as group:
        group.start_soon(receive)
        group.start_soon(send)
        try:
            async with ClientSession(inbound_reader, outbound_writer) as session:
                with anyio.fail_after(15):
                    initialized = await session.initialize()
                assert initialized.protocolVersion == "2025-11-25"
                yield session
        finally:
            await process.stdin.aclose()
            with anyio.move_on_after(3) as deadline:
                await process.wait()
            if deadline.cancel_called:
                process.terminate()
                with anyio.fail_after(3):
                    await process.wait()
            group.cancel_scope.cancel()
            await process.aclose()
    assert process.returncode == 0


def new_world(tmp_path):
    return World.create(tmp_path / "world.db", load_fixture("business-sales-lead-qualification"),
                        signing_key=Ed25519PrivateKey.generate())


def verify(world):
    receipts = world.receipts()
    final_hash = hashlib.sha256(canonical_json(receipts[-1]).encode()).hexdigest() if receipts else "0" * 64
    verify_receipts(receipts, world.key.public_key().public_bytes_raw(),
                    expected_count=len(receipts), expected_final_hash=final_hash)


def test_mail_draft_send_attachment_and_receipt_bindings(tmp_path):
    world = new_world(tmp_path)

    async def episode():
        async with client(world, "mail") as session:
            tools = await session.list_tools()
            names = {tool.name for tool in tools.tools}
            assert {"mail.search", "mail.read", "mail.create_draft", "mail.send", "mail.read_attachment"} <= names
            draft_schema = next(tool.inputSchema for tool in tools.tools if tool.name == "mail.create_draft")
            assert "ctx" not in draft_schema["properties"]
            assert "signing_key" not in canonical_json(draft_schema)
            assert draft_schema["additionalProperties"] is False
            args = {"record_id": "followup", "data": {"body": "Authorized draft", "recipients": ["local@example.test"]},
                    "idempotency_key": "draft-call"}
            draft = await session.call_tool("mail.create_draft", args)
            assert not draft.isError and draft.structuredContent["collection"] == "mail.drafts"
            assert json.loads(draft.content[0].text) == draft.structuredContent
            assert world.inspect("followup")["collection"] == "mail.drafts"
            receipt = world.receipts()[0]["event"]
            identity = {"operation": "mail.create_draft", "args": {key: value for key, value in args.items()
                        if key != "idempotency_key"}, "actor": "bench-user"}
            assert receipt["args_digest"] == hashlib.sha256(canonical_json(identity).encode()).hexdigest()
            assert str(receipt["request_id"]) != ""
            retry = await session.call_tool("mail.create_draft", args)
            assert retry.structuredContent == draft.structuredContent
            assert len(world.receipts()) == 1
            stale = await session.call_tool("mail.send", {"record_id": "followup", "expected_version": 0})
            assert stale.isError
            assert world.inspect("followup")["collection"] == "mail.drafts"
            sent = await session.call_tool("mail.send", {"record_id": "followup", "expected_version": 1})
            assert sent.structuredContent["collection"] == "mail.outbox"
            attachment = await session.call_tool("mail.read_attachment", {
                "record_id": "lead-a", "attachment_id": "brief-a"})
            assert attachment.structuredContent["filename"] == "requirements.txt"

    anyio.run(episode)
    assert world.inspect("followup")["data"]["state"] == "sent"
    verify(world)


@pytest.mark.parametrize("family", list(COLLECTIONS))
def test_all_seven_services_actual_crud_sessions(tmp_path, family):
    world = new_world(tmp_path)
    collection = sorted(COLLECTIONS[family])[0]

    async def episode():
        async with client(world, family) as session:
            names = {tool.name for tool in (await session.list_tools()).tools}
            assert {f"{family}.{verb}" for verb in ("search", "read", "create", "update", "delete")} <= names
            assert all(name.startswith(family + ".") for name in names)
            created = await session.call_tool(f"{family}.create", {"record_id": "new-row", "collection": collection,
                                                                     "data": {"title": "First"}})
            assert created.structuredContent["version"] == 1
            read = await session.call_tool(f"{family}.read", {"record_id": "new-row", "fields": ["title"]})
            assert read.structuredContent["data"] == {"title": "First"}
            updated = await session.call_tool(f"{family}.update", {"record_id": "new-row", "expected_version": 1,
                                                                    "data": {"title": "Second"}})
            assert updated.structuredContent["version"] == 2
            deleted = await session.call_tool(f"{family}.delete", {"record_id": "new-row", "expected_version": 2})
            assert deleted.structuredContent == {"deleted": "new-row"}
    anyio.run(episode)
    assert world.inspect("new-row") is None
    assert len(world.receipts()) == 4
    verify(world)


def test_pagination_resource_read_and_client_reconnect(tmp_path):
    world = new_world(tmp_path)

    async def episode():
        async with client(world, "crm") as session:
            first = await session.call_tool("crm.search", {"collection": "crm.contacts", "limit": 1})
            cursor = first.structuredContent["next_cursor"]
            second = await session.call_tool("crm.search", {"collection": "crm.contacts", "limit": 1, "cursor": cursor})
            assert first.structuredContent["records"][0]["id"] != second.structuredContent["records"][0]["id"]
            templates = await session.list_resource_templates()
            assert templates.resourceTemplates[0].uriTemplate == "fixture://crm/{record_id}"
            resource = await session.read_resource("fixture://crm/contact-a")
            assert json.loads(resource.contents[0].text)["id"] == "contact-a"
        async with client(world, "crm") as session:
            reread = await session.call_tool("crm.read", {"record_id": "contact-a"})
            assert reread.structuredContent["id"] == "contact-a"
    anyio.run(episode)
    assert len(world.receipts()) == 4
    verify(world)


def test_unknown_arguments_mistyped_versions_and_cross_service_fail_without_effect(tmp_path):
    world = new_world(tmp_path)

    async def episode():
        async with client(world, "mail") as session:
            for args in ({"record_id": "lead-a", "actor_id": "executive"},
                         {"record_id": 1}, {"record_id": "peer-confidential"}):
                result = await session.call_tool("mail.read", args)
                assert result.isError
            forbidden = await session.call_tool("docs.read", {"record_id": "peer-confidential"})
            assert forbidden.isError
    anyio.run(episode)
    assert world.receipts() == []


def test_specialized_permissions_invitations_and_chat_effects_use_actual_protocol(tmp_path):
    world = new_world(tmp_path)

    async def episode():
        async with client(world, "docs") as session:
            await session.call_tool("docs.create", {"record_id": "owned-document", "collection": "docs.documents",
                                                     "data": {"title": "Private work"}})
            shared = await session.call_tool("docs.set_permissions", {"record_id": "owned-document",
                "expected_version": 1, "permissions": [{"principal_id": "reviewer", "role": "reader"}],
                "visibility": "internal"})
            assert not shared.isError
            assert "reviewer" in shared.structuredContent["acl"]["read"]
            assert shared.structuredContent["acl"]["write"] == ["bench-user"]
        async with client(world, "calendar") as session:
            await session.call_tool("calendar.create", {"record_id": "meeting", "collection": "calendar.events",
                                                         "data": {"attendees": ["local@example.test"]}})
            invited = await session.call_tool("calendar.invite", {"record_id": "meeting", "expected_version": 1})
            assert invited.structuredContent["data"]["state"] == "invited"
        async with client(world, "chat") as session:
            posted = await session.call_tool("chat.post", {"record_id": "status-post", "data": {
                "body": "Fixture status", "channel_id": "internal-project"}})
            assert posted.structuredContent["collection"] == "chat.messages"
    anyio.run(episode)
    assert len(world.receipts()) == 5
    verify(world)


def test_signing_key_pipe_rejects_stdio_and_wrong_lengths():
    with pytest.raises(ValueError, match="dedicated"):
        read_signing_key_pipe(0)
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"short")
    os.close(write_fd)
    with pytest.raises(ValueError, match="length"):
        read_signing_key_pipe(read_fd)


def test_family_validation_before_any_service_action():
    with pytest.raises(ValueError, match="family"):
        create_server(object(), "unknown")
