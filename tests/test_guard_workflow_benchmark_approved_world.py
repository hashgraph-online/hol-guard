"""Authoritative approval derivation, transaction races and real provider effects."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.approval import ApprovalController, ApprovalError, ApprovalLedger
from ci.gauntlet.benchmark.approved_world import ApprovedWorld
from ci.gauntlet.benchmark.catalog import load_fixture
from ci.gauntlet.benchmark.world import World


@pytest.fixture
def approved(tmp_path):
    world = World.create(
        tmp_path / "world.db",
        load_fixture("business-sales-lead-qualification"),
        signing_key=Ed25519PrivateKey.generate(),
    )
    controller = ApprovalController()
    ledger = ApprovalLedger(world.path, controller.public_key_bytes())
    adapter = ApprovedWorld(world, ledger, policy_version="policy-v1")
    world.call(
        "mail.create_draft",
        {"record_id": "draft-1", "data": {"body": "Approved message", "recipients": ["contact@example.test"]}},
        "create-1",
    )
    return world, controller, adapter


def send_args():
    return {"record_id": "draft-1", "expected_version": 1}


def grant_for(controller, adapter, operation="mail.send", args=None, decision="granted"):
    return controller.issue(adapter.request_for(operation, args or send_args()), decision=decision, now=100)


def test_send_derives_persisted_scope_and_commits_once(approved):
    world, controller, adapter = approved
    request = adapter.request_for("mail.send", send_args())
    assert request["actor"] == world.actor
    assert request["recipients"] == ["contact@example.test"]
    assert request["state_versions"] == {"draft-1": "1"}
    grant = grant_for(controller, adapter)
    first = adapter.call("mail.send", send_args(), operation_id="send-1", grant=grant, now=101)
    second = adapter.call("mail.send", send_args(), operation_id="send-1", grant=grant, now=102)
    assert first.status == "claimed" and second.status == "cached"
    assert first.receipt == second.receipt
    assert first.receipt["result"]["collection"] == "mail.outbox"
    assert first.receipt["world_receipt"]["event"]["actor"] == world.actor
    assert len(world.receipts()) == 2
    with sqlite3.connect(world.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM approval_claims").fetchone()[0] == 1


@pytest.mark.parametrize("decision", ["denied", "no-response", "expired"])
def test_denied_controller_preserves_draft_and_no_claim(approved, decision):
    world, controller, adapter = approved
    grant = grant_for(controller, adapter, decision=decision)
    with pytest.raises(ApprovalError):
        adapter.call("mail.send", send_args(), operation_id="send-1", grant=grant, now=101)
    assert world.inspect("draft-1")["collection"] == "mail.drafts"
    assert len(world.receipts()) == 1


def test_expiry_spoofed_signer_and_model_scope_are_rejected(approved):
    world, controller, adapter = approved
    grant = grant_for(controller, adapter)
    for candidate, now in [(grant, 160), (grant_for(ApprovalController(), adapter), 101)]:
        with pytest.raises(ApprovalError):
            adapter.call("mail.send", send_args(), operation_id="send-1", grant=candidate, now=now)
    for field in ("actor", "state_versions", "recipients", "idempotency_key"):
        args = {**send_args(), field: "model-assertion"}
        with pytest.raises(ApprovalError, match="unknown"):
            adapter.call("mail.send", args, operation_id="send-1", grant=grant, now=101)
    assert len(world.receipts()) == 1


def test_stale_persisted_payload_and_versions_fail_before_send(approved):
    world, controller, adapter = approved
    grant = grant_for(controller, adapter)
    world.call("mail.update", {**send_args(), "data": {"recipients": ["attacker@collector.test"]}}, "update-1")
    with pytest.raises(ApprovalError, match="stale"):
        adapter.call("mail.send", send_args(), operation_id="send-1", grant=grant, now=101)
    with pytest.raises(ApprovalError, match="scope"):
        adapter.call(
            "mail.send", {"record_id": "draft-1", "expected_version": 2}, operation_id="send-1", grant=grant, now=101
        )
    assert world.inspect("draft-1")["collection"] == "mail.drafts"
    assert len(world.receipts()) == 2


def test_changed_payload_without_version_increment_still_fails(approved):
    world, controller, adapter = approved
    grant = grant_for(controller, adapter)
    changed = world.inspect("draft-1")
    changed["data"]["body"] = "Different persisted payload"
    with sqlite3.connect(world.path) as connection:
        connection.execute("UPDATE records SET value=? WHERE id=?", (json.dumps(changed), "draft-1"))
    with pytest.raises(ApprovalError, match="scope"):
        adapter.call("mail.send", send_args(), operation_id="send-1", grant=grant, now=101)
    assert len(world.receipts()) == 1


def test_world_effect_journal_and_claim_roll_back_together(approved, monkeypatch):
    world, controller, adapter = approved
    grant = grant_for(controller, adapter)
    original = world.execute_on_connection

    def interrupted(*args):
        original(*args)
        raise RuntimeError("crash before approval claim commit")

    monkeypatch.setattr(world, "execute_on_connection", interrupted)
    with pytest.raises(RuntimeError, match="crash"):
        adapter.call("mail.send", send_args(), operation_id="send-1", grant=grant, now=101)
    assert world.inspect("draft-1")["collection"] == "mail.drafts"
    assert len(world.receipts()) == 1
    with sqlite3.connect(world.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM approval_claims").fetchone()[0] == 0
    monkeypatch.setattr(world, "execute_on_connection", original)
    assert adapter.call("mail.send", send_args(), operation_id="send-1", grant=grant, now=102).status == "claimed"


def test_concurrent_duplicate_calls_deliver_once(approved):
    world, controller, adapter = approved
    grant = grant_for(controller, adapter)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda _: adapter.call("mail.send", send_args(), operation_id="send-1", grant=grant, now=101), range(8)
            )
        )
    assert sum(result.status == "claimed" for result in results) == 1
    assert all(result.receipt == results[0].receipt for result in results)
    assert world.inspect("draft-1")["version"] == 2
    assert len(world.receipts()) == 2


def test_distinct_operations_cannot_race_one_grant(approved):
    world, controller, adapter = approved
    grant = grant_for(controller, adapter)

    def attempt(index):
        try:
            return adapter.call("mail.send", send_args(), operation_id=f"send-{index}", grant=grant, now=101).status
        except ApprovalError:
            return "denied"

    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(attempt, range(8)))
    assert statuses.count("claimed") == 1
    assert statuses.count("denied") == 7
    assert len(world.receipts()) == 2


def test_permission_effect_changes_actual_acl_and_preserves_owner(approved):
    world, controller, adapter = approved
    record_id = "approved-doc"
    world.call(
        "docs.create",
        {"record_id": record_id, "collection": "docs.documents", "data": {"body": "Private"}},
        "doc-create",
    )
    args = {
        "record_id": record_id,
        "expected_version": 1,
        "permissions": [{"principal_id": "reviewer", "role": "writer"}],
        "visibility": "link",
    }
    grant = grant_for(controller, adapter, "docs.set_permissions", args)
    result = adapter.call("docs.set_permissions", args, operation_id="share-1", grant=grant, now=101).receipt["result"]
    assert result["owner_id"] == world.actor
    assert result["acl"]["read"] == ["*", world.actor, "reviewer"]
    assert result["acl"]["write"] == [world.actor, "reviewer"]
    with pytest.raises(ValueError, match="owner"):
        world.call(
            "docs.set_permissions",
            {**args, "expected_version": 2, "permissions": [{"principal_id": "attacker", "role": "owner"}]},
            "owner-rewrite",
        )
    assert world.inspect(record_id) == result


def test_invite_post_and_update_bind_persisted_records(approved):
    world, controller, adapter = approved
    world.call(
        "calendar.create",
        {
            "record_id": "event-1",
            "collection": "calendar.events",
            "data": {"attendees": ["candidate@example.test"], "state": "draft"},
        },
        "event-create",
    )
    args = {"record_id": "event-1", "expected_version": 1}
    grant = grant_for(controller, adapter, "calendar.invite", args)
    assert adapter.request_for("calendar.invite", args)["recipients"] == ["candidate@example.test"]
    assert (
        adapter.call("calendar.invite", args, operation_id="invite-1", grant=grant, now=101).receipt["result"]["data"][
            "state"
        ]
        == "invited"
    )
    world.call(
        "chat.create",
        {
            "record_id": "chat-draft",
            "collection": "chat.drafts",
            "data": {"body": "Internal summary", "channel_id": "internal-project"},
        },
        "chat-create",
    )
    args = {"record_id": "post-1", "draft_id": "chat-draft", "expected_version": 1}
    grant = grant_for(controller, adapter, "chat.post", args)
    result = adapter.call("chat.post", args, operation_id="post-1", grant=grant, now=101).receipt["result"]
    assert result["collection"] == "chat.messages"
    assert result["data"]["channel_id"] == "internal-project"
    args = {"record_id": "draft-1", "expected_version": 1, "data": {"body": "Approved edit"}}
    grant = grant_for(controller, adapter, "mail.update", args)
    result = adapter.call("mail.update", args, operation_id="edit-1", grant=grant, now=101).receipt["result"]
    assert result["owner_id"] == world.actor and result["data"]["body"] == "Approved edit"


def test_provider_permissions_are_real_and_generic_updates_cannot_replace_identity(approved):
    world, _, _ = approved
    world.call(
        "docs.create",
        {"record_id": "doc-1", "collection": "docs.documents", "data": {"body": "Synthetic private document"}},
        "doc-create",
    )
    changed = world.call(
        "docs.set_permissions",
        {"record_id": "doc-1", "expected_version": 1, "permissions": ["reviewer"], "visibility": "public"},
        "share",
    )
    assert changed["acl"] == {"read": ["*", world.actor, "reviewer"], "write": [world.actor]}
    updated = world.call(
        "docs.update",
        {
            "record_id": "doc-1",
            "expected_version": 2,
            "data": {"owner_id": "attacker", "tenant_id": "foreign", "acl": {"write": ["attacker"]}},
        },
        "update",
    )
    assert updated["owner_id"] == world.actor
    assert updated["tenant_id"] == changed["tenant_id"]
    assert updated["acl"] == changed["acl"]
    assert world.receipts()[-2]["event"]["after"]["acl"] == changed["acl"]


def test_attachment_journal_binds_exact_parent_and_attachment(approved):
    world, _, _ = approved
    attachment = {"id": "attached-1", "body": "Synthetic attachment body"}
    world.call(
        "mail.create",
        {
            "record_id": "message-1",
            "collection": "mail.messages",
            "data": {"body": "Message", "attachments": [attachment]},
        },
        "message-create",
    )
    assert (
        world.call("mail.read_attachment", {"record_id": "message-1", "attachment_id": "attached-1"}, "attachment-read")
        == attachment
    )
    observed = world.receipts()[-1]["event"]["after"]
    assert observed["id"] == "message-1"
    assert observed["collection"] == "mail.messages"
    assert observed["version"] == 1
    assert observed["parent_record"]["id"] == "message-1"
    assert observed["attachment"] == attachment


def test_synthetic_calendar_principal_is_allowed_but_real_email_is_not(approved):
    world, _, _ = approved
    event = world.call(
        "calendar.create",
        {"record_id": "event-principal", "collection": "calendar.events", "data": {"attendees": [world.actor]}},
        "calendar-create",
    )
    assert event["data"]["attendees"] == [world.actor]
    with pytest.raises(ValueError, match="synthetic"):
        world.call(
            "calendar.update",
            {"record_id": "event-principal", "expected_version": 1, "data": {"attendees": ["real-person@gmail.com"]}},
            "calendar-update",
        )
