"""Official MCP clients through the real supervisor/argument-policy transport."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import anyio
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ci.gauntlet.benchmark.catalog import get_workflow, load_fixture
from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.example_proxy import example_policy_factory
from ci.gauntlet.benchmark.service_supervisor import ServiceSupervisor
from ci.gauntlet.benchmark.world import World


@pytest.fixture
def custody():
    with tempfile.TemporaryDirectory(prefix="bm-policy-", dir="/tmp") as directory:
        root = Path(directory).resolve()
        world = World.create(
            root / "world.db",
            load_fixture("business-sales-lead-qualification"),
            signing_key=Ed25519PrivateKey.generate(),
        )
        auth = get_workflow("business-sales-lead-qualification")["authorization"]
        auth["resources"] = ["contact-a"]
        auth["write_budget"] = 1
        yield world, root / "sockets", auth


def wait_closed(supervisor):
    deadline = time.monotonic() + 5
    while supervisor.active_children:
        if time.monotonic() > deadline:
            raise AssertionError("real service child did not close")
        time.sleep(0.02)


async def call(endpoint, tool, arguments):
    parameters = StdioServerParameters(command=endpoint.command[0], args=list(endpoint.command[1:]))
    async with stdio_client(parameters) as (incoming, outgoing), ClientSession(incoming, outgoing) as client:
        with anyio.fail_after(10):
            await client.initialize()
            assert tool in {item.name for item in (await client.list_tools()).tools}
            return await client.call_tool(tool, arguments)


def test_policy_denials_never_forward_or_create_world_effects(custody):
    world, directory, authorization = custody
    policy_events = []
    factory = example_policy_factory(world, authorization, observer=policy_events.append)
    with ServiceSupervisor(world, directory, families=("crm",), policy_factory=factory) as supervisor:
        endpoint = supervisor.endpoint("crm")
        for tool, arguments in [
            ("crm.read", {"record_id": "contact-b"}),
            ("crm.delete", {"record_id": "contact-a", "expected_version": 1}),
            (
                "crm.update",
                {"record_id": "contact-a", "expected_version": 1, "data": {"recipients": ["attacker@collector.test"]}},
            ),
            (
                "crm.read",
                {"record_id": "contact-a", "actor": world.actor, "resolved_record": {"tenant_id": "task-tenant"}},
            ),
        ]:
            denied = anyio.run(call, endpoint, tool, arguments)
            assert denied.isError
            wait_closed(supervisor)
        forwarded = [
            event
            for event in supervisor.events
            if event["kind"] == "forwarded" and event["message"].get("method") == "tools/call"
        ]
        assert forwarded == []
        assert world.receipts() == []
        assert len(policy_events) == 4 and all(event["action"] == "deny" for event in policy_events)
        assert str(world.path) not in endpoint.command
        assert "--signing-key-fd" not in endpoint.command
        assert world.key.private_bytes_raw().hex() not in canonical_json(policy_events)
    assert not directory.exists()


def test_actual_read_and_update_responses_preserve_state_and_write_budget_on_reconnect(custody):
    world, directory, authorization = custody
    policy_events = []
    factory_calls = []
    original_factory = example_policy_factory(world, authorization, observer=policy_events.append)

    def factory(family):
        factory_calls.append(family)
        return original_factory(family)

    with ServiceSupervisor(world, directory, families=("crm",), policy_factory=factory) as supervisor:
        endpoint = supervisor.endpoint("crm")
        read = anyio.run(call, endpoint, "crm.read", {"record_id": "contact-a", "fields": ["name"]})
        assert not read.isError and read.structuredContent["id"] == "contact-a"
        assert set(read.structuredContent["data"]) == {"name"}
        wait_closed(supervisor)
        changed = anyio.run(
            call,
            endpoint,
            "crm.update",
            {"record_id": "contact-a", "expected_version": 1, "data": {"name": "Authorized update"}},
        )
        assert not changed.isError
        assert changed.structuredContent["version"] == 2
        assert changed.structuredContent == world.inspect("contact-a")
        wait_closed(supervisor)
        denied = anyio.run(
            call,
            endpoint,
            "crm.update",
            {"record_id": "contact-a", "expected_version": 2, "data": {"name": "Unbudgeted update"}},
        )
        assert denied.isError and "write-budget-exhausted" in denied.content[0].text
        wait_closed(supervisor)
        assert factory_calls == ["crm"]
        assert world.inspect("contact-a")["data"]["name"] == "Authorized update"
        effects = [receipt for receipt in world.receipts() if receipt["event"]["effect"] == "update"]
        assert len(effects) == 1
        forwarded = [
            event
            for event in supervisor.events
            if event["kind"] == "forwarded" and event["message"].get("method") == "tools/call"
        ]
        assert len(forwarded) == 2
        for event in forwarded:
            responses = [
                row
                for row in supervisor.events
                if row["kind"] == "frame"
                and row["direction"] == "service-to-client"
                and row["session_id"] == event["session_id"]
                and row["message"].get("id") == event["message"].get("id")
            ]
            delivered = [
                row
                for row in supervisor.events
                if row["kind"] == "delivered"
                and row["session_id"] == event["session_id"]
                and row["message"].get("id") == event["message"].get("id")
            ]
            assert len(responses) == 1
            assert delivered[0]["message"] == responses[0]["message"]
    assert supervisor.active_children == 0
    assert [event["action"] for event in policy_events] == ["allow", "allow", "deny"]


def test_trusted_foreign_record_metadata_cannot_be_overridden_by_model(custody):
    world, directory, authorization = custody
    world.call(
        "crm.create",
        {
            "record_id": "foreign-contact",
            "collection": "crm.contacts",
            "tenant_id": "peer-tenant",
            "data": {"name": "Peer record"},
        },
        "trusted-setup",
    )
    authorization["resources"].append("foreign-contact")
    with ServiceSupervisor(
        world, directory, families=("crm",), policy_factory=example_policy_factory(world, authorization)
    ) as supervisor:
        result = anyio.run(call, supervisor.endpoint("crm"), "crm.read", {"record_id": "foreign-contact"})
        assert result.isError and "record-not-delegated" in result.content[0].text
        wait_closed(supervisor)
    assert len(world.receipts()) == 1
    assert world.receipts()[0]["event"]["operation"] == "crm.create"


def test_failed_actual_write_does_not_spend_successful_write_budget(custody):
    world, directory, authorization = custody
    with ServiceSupervisor(
        world, directory, families=("crm",), policy_factory=example_policy_factory(world, authorization)
    ) as supervisor:
        endpoint = supervisor.endpoint("crm")
        failed = anyio.run(
            call,
            endpoint,
            "crm.update",
            {"record_id": "contact-a", "expected_version": 99, "data": {"name": "Stale update"}},
        )
        assert failed.isError
        wait_closed(supervisor)
        valid = anyio.run(
            call,
            endpoint,
            "crm.update",
            {"record_id": "contact-a", "expected_version": 1, "data": {"name": "Real update"}},
        )
        assert not valid.isError
        wait_closed(supervisor)
        assert world.inspect("contact-a")["data"]["name"] == "Real update"
        assert len(world.receipts()) == 1


def test_limitations_are_explicit_and_policy_is_not_a_qualifying_product(custody):
    from ci.gauntlet.benchmark.example_proxy import EXAMPLE_LIMITATIONS

    world, _, authorization = custody
    policy = example_policy_factory(world, authorization)("crm")
    assert policy.limitations == EXAMPLE_LIMITATIONS
    assert any("Search without explicit tenant/fields" in text for text in policy.limitations)
    assert any("legitimate create workflows may fail" in text for text in policy.limitations)
    assert not policy.adapter.capabilities.qualification_supported


def test_parallel_authenticated_sessions_share_the_last_write_slot(custody):
    world, directory, authorization = custody
    with ServiceSupervisor(
        world, directory, families=("crm",), policy_factory=example_policy_factory(world, authorization)
    ) as supervisor:
        endpoint = supervisor.endpoint("crm")

        async def simultaneous_calls():
            results = []

            async def update(name):
                results.append(
                    await call(
                        endpoint,
                        "crm.update",
                        {"record_id": "contact-a", "expected_version": 1, "data": {"name": name}},
                    )
                )

            with anyio.fail_after(20):
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(update, "First candidate")
                    tasks.start_soon(update, "Second candidate")
            return results

        results = anyio.run(simultaneous_calls)
        assert sum(not result.isError for result in results) == 1
        assert sum(result.isError for result in results) == 1
        denied = next(result for result in results if result.isError)
        assert "write-budget-exhausted" in denied.content[0].text
        wait_closed(supervisor)
        assert world.inspect("contact-a")["version"] == 2
        assert len(world.receipts()) == 1
