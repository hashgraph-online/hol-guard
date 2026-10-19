"""External authority, single use, transactional effects, and concurrency."""

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from ci.gauntlet.benchmark.approval import ApprovalController, ApprovalError, ApprovalLedger
from ci.gauntlet.benchmark.contracts import digest


def request():
    return {
        "actor": "actor-1",
        "operation": "mail.send",
        "target_ids": ["draft-1"],
        "recipients": ["fixture@example.test"],
        "payload_digest": digest("exact approved message"),
        "policy_version": "policy-v1",
        "state_versions": {"draft-1": "version-1"},
    }


def authority(tmp_path):
    controller = ApprovalController()
    ledger = ApprovalLedger(tmp_path / "approval.sqlite", controller.public_key_bytes())
    grant = controller.issue(request(), decision="granted", now=100, lifetime_seconds=30)
    return controller, ledger, grant


@pytest.mark.parametrize(
    "field,value",
    [
        ("actor", "other-actor"),
        ("operation", "mail.delete"),
        ("target_ids", ["other-draft"]),
        ("recipients", ["attacker@example.test"]),
        ("payload_digest", digest("modified message")),
        ("policy_version", "policy-v2"),
        ("state_versions", {"draft-1": "version-2"}),
    ],
)
def test_every_request_field_is_bound(tmp_path, field, value):
    _, ledger, grant = authority(tmp_path)
    changed = request()
    changed[field] = value
    with pytest.raises(ApprovalError, match="scope"):
        ledger.claim(grant, changed, operation_id="send-1", now=101)
    assert ledger.claim(grant, request(), operation_id="send-1", now=101).status == "claimed"


def test_external_anchor_rejects_spoofed_key_and_modified_signature(tmp_path):
    controller, ledger, grant = authority(tmp_path)
    spoof = ApprovalController().issue(request(), decision="granted", now=100)
    with pytest.raises(ApprovalError, match="signature"):
        ledger.claim(spoof, request(), operation_id="send-1", now=101)
    altered = copy.deepcopy(grant)
    altered["record"]["expires_at"] += 100
    with pytest.raises(ApprovalError, match="signature"):
        ledger.claim(altered, request(), operation_id="send-1", now=101)
    altered = copy.deepcopy(grant)
    altered["public_key"] = controller.public_key_bytes().hex()
    with pytest.raises(ApprovalError, match="unknown"):
        ledger.claim(altered, request(), operation_id="send-1", now=101)


@pytest.mark.parametrize("decision", ["denied", "expired", "no-response"])
def test_only_controller_grants_authorize_effect(tmp_path, decision):
    controller, ledger, _ = authority(tmp_path)
    grant = controller.issue(request(), decision=decision, now=100)
    with pytest.raises(ApprovalError, match="did not grant"):
        ledger.claim(grant, request(), operation_id="send-1", now=101)


@pytest.mark.parametrize("now", [99, 130, 131])
def test_expiry_and_future_grants_fail_closed(tmp_path, now):
    _, ledger, grant = authority(tmp_path)
    with pytest.raises(ApprovalError, match="expired or not yet valid"):
        ledger.claim(grant, request(), operation_id="send-1", now=now)


def test_single_use_and_durable_operation_id_idempotency(tmp_path):
    controller, ledger, grant = authority(tmp_path)
    first = ledger.claim(grant, request(), operation_id="send-1", now=101)
    reopened = ApprovalLedger(tmp_path / "approval.sqlite", controller.public_key_bytes())
    cached = reopened.claim(grant, request(), operation_id="send-1", now=102)
    assert first.status == "claimed" and cached.status == "cached"
    assert first.claim_digest == cached.claim_digest
    with pytest.raises(ApprovalError, match="replay"):
        reopened.claim(grant, request(), operation_id="send-2", now=102)
    fresh = controller.issue(request(), decision="granted", now=100)
    with pytest.raises(ApprovalError, match="different claim"):
        reopened.claim(fresh, request(), operation_id="send-1", now=102)


def test_concurrent_same_operation_runs_effect_exactly_once(tmp_path):
    _, ledger, grant = authority(tmp_path)
    with sqlite3.connect(tmp_path / "approval.sqlite") as connection:
        connection.execute("CREATE TABLE deliveries (operation_id TEXT PRIMARY KEY, payload TEXT)")

    def effect(connection):
        connection.execute("INSERT INTO deliveries VALUES (?,?)", ("send-1", "approved-message"))
        return {"operation_id": "send-1", "delivered": True}

    def execute(_):
        return ledger.execute(grant, request(), operation_id="send-1", now=101, effect=effect)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(execute, range(8)))
    assert sum(result.status == "claimed" for result in results) == 1
    assert sum(result.status == "cached" for result in results) == 7
    assert all(result.receipt == {"operation_id": "send-1", "delivered": True} for result in results)
    with sqlite3.connect(tmp_path / "approval.sqlite") as connection:
        assert connection.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 1


def test_concurrent_distinct_operations_cannot_replay_single_grant(tmp_path):
    _, ledger, grant = authority(tmp_path)

    def claim(index):
        try:
            return ledger.claim(grant, request(), operation_id=f"send-{index}", now=101).status
        except ApprovalError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(claim, range(8)))
    assert results.count("claimed") == 1
    assert results.count("rejected") == 7


def test_effect_error_rolls_back_effect_and_claim(tmp_path):
    _, ledger, grant = authority(tmp_path)
    with sqlite3.connect(tmp_path / "approval.sqlite") as connection:
        connection.execute("CREATE TABLE deliveries (operation_id TEXT PRIMARY KEY)")

    def failed_effect(connection):
        connection.execute("INSERT INTO deliveries VALUES (?)", ("send-1",))
        raise RuntimeError("transaction interrupted")

    with pytest.raises(RuntimeError, match="interrupted"):
        ledger.execute(grant, request(), operation_id="send-1", now=101, effect=failed_effect)
    with sqlite3.connect(tmp_path / "approval.sqlite") as connection:
        assert connection.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM approval_claims").fetchone()[0] == 0
    assert ledger.claim(grant, request(), operation_id="send-1", now=102).status == "claimed"


def test_noncanonical_or_unbounded_request_does_not_issue(tmp_path):
    controller = ApprovalController()
    malformed = request()
    malformed["model_approved"] = True
    with pytest.raises(ApprovalError, match="unknown"):
        controller.issue(malformed, decision="granted", now=100)
    with pytest.raises(ApprovalError):
        controller.issue(request(), decision="granted", now=True)
    with pytest.raises(ApprovalError, match="durable"):
        ApprovalLedger(":memory:", controller.public_key_bytes())


def test_controller_attests_only_durable_claim_with_matching_anchor(tmp_path):
    from ci.gauntlet.benchmark.approval import verify_claim_evidence

    controller, ledger, grant = authority(tmp_path)
    with pytest.raises(ApprovalError, match="no durable"):
        controller.attest_claim(ledger, "send-1", now=102)
    claim = ledger.execute(
        grant,
        request(),
        operation_id="send-1",
        now=101,
        effect=lambda connection: {"delivered": True, "operation_id": "send-1"},
    )
    evidence = controller.attest_claim(ledger, "send-1", now=102)
    verified = verify_claim_evidence(
        evidence,
        trusted_public_key=controller.public_key_bytes(),
        operation_id="send-1",
        claim_digest=claim.claim_digest,
        now=103,
    )
    assert verified["receipt"] == claim.receipt
    assert verified["applied_at"] == 101
    assert verified["attested_at"] == 102
    with pytest.raises(ApprovalError, match="anchor"):
        ApprovalController().attest_claim(ledger, "send-1", now=102)
    with pytest.raises(ApprovalError, match="precedes"):
        controller.attest_claim(ledger, "send-1", now=100)


def test_signed_claim_export_rejects_tamper_forgery_wrong_identity_and_staleness(tmp_path):
    from ci.gauntlet.benchmark.approval import verify_claim_evidence

    controller, ledger, grant = authority(tmp_path)
    claim = ledger.claim(grant, request(), operation_id="send-1", now=101)
    evidence = controller.attest_claim(ledger, "send-1", now=102)
    options = dict(
        trusted_public_key=controller.public_key_bytes(),
        operation_id="send-1",
        claim_digest=claim.claim_digest,
        now=103,
    )
    changed = copy.deepcopy(evidence)
    changed["record"]["applied_at"] = 100
    with pytest.raises(ApprovalError, match="signature"):
        verify_claim_evidence(changed, **options)
    with pytest.raises(ApprovalError, match="signature"):
        verify_claim_evidence(evidence, **{**options, "trusted_public_key": ApprovalController().public_key_bytes()})
    with pytest.raises(ApprovalError, match="identity"):
        verify_claim_evidence(evidence, **{**options, "operation_id": "send-other"})
    with pytest.raises(ApprovalError, match="identity"):
        verify_claim_evidence(evidence, **{**options, "claim_digest": digest("fabricated")})
    with pytest.raises(ApprovalError, match="stale"):
        verify_claim_evidence(evidence, **{**options, "now": 403})
    with pytest.raises(ApprovalError, match="future"):
        verify_claim_evidence(evidence, **{**options, "now": 101})
    changed = copy.deepcopy(evidence)
    changed["signer_key"] = controller.public_key_bytes().hex()
    with pytest.raises(ApprovalError, match="unknown"):
        verify_claim_evidence(changed, **options)


@pytest.mark.parametrize("decision", ["denied", "expired", "no-response"])
def test_signed_refusal_can_be_verified_but_never_claimed(tmp_path, decision):
    from ci.gauntlet.benchmark.approval import verify_decision

    controller, ledger, _ = authority(tmp_path)
    signed = controller.issue(request(), decision=decision, now=100)
    verified = verify_decision(
        signed, request(), trusted_public_key=controller.public_key_bytes(), now=101, expected_decision=decision
    )
    assert verified["decision"] == decision
    with pytest.raises(ApprovalError, match="expected decision"):
        verify_decision(
            signed, request(), trusted_public_key=controller.public_key_bytes(), now=101, expected_decision="granted"
        )
    with pytest.raises(ApprovalError):
        ledger.claim(signed, request(), operation_id="send-1", now=101)
    with pytest.raises(ApprovalError, match="no durable"):
        controller.attest_claim(ledger, "send-1", now=102)
