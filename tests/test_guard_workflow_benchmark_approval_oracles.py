"""Real stateful controller effects for all seven approval departments."""

import copy
from dataclasses import asdict

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.approval import ApprovalController, ApprovalError, ApprovalLedger
from ci.gauntlet.benchmark.approval_oracle_rules import OPERATION_ALIASES
from ci.gauntlet.benchmark.approval_oracles import approval_phase_digest, score_approval_variant
from ci.gauntlet.benchmark.approved_world import ApprovedWorld
from ci.gauntlet.benchmark.catalog import load_approval_variants, load_fixture, load_oracle_fixture
from ci.gauntlet.benchmark.contracts import digest
from ci.gauntlet.benchmark.world import World, verify_receipts
from tests.test_guard_workflow_benchmark_business_oracles import outputs, solution

VARIANTS = load_approval_variants()


def episode(tmp_path, variant, *, apply=True, wrong_arithmetic=False):
    reference = solution(variant["workflow_id"])
    world_key = Ed25519PrivateKey.generate()
    world = World.create(tmp_path / (variant["id"] + ".db"), reference[0], signing_key=world_key)
    initial = world.snapshot()
    call_id = 1
    for source in initial["records"]:
        if source["tenant_id"] == "task-tenant":
            world.call(source["collection"].split(".")[0] + ".read", {"record_id": source["id"]}, call_id)
            call_id += 1
    original_ids = {r["id"] for r in initial["records"]}
    for record in reference[1]["records"]:
        if record["id"] in original_ids:
            original = next(r for r in initial["records"] if r["id"] == record["id"])
            if original != record:
                field = "notes" if record["collection"] == "crm.contacts" else "internal_notes"
                world.call(
                    record["collection"].split(".")[0] + ".update",
                    {"record_id": record["id"], "expected_version": 1, "data": {field: record["data"][field]}},
                    call_id,
                )
                call_id += 1
    new = outputs(reference)
    for index, record in enumerate(new):
        record_id = record["id"]
        first_draft = record["collection"] == "mail.drafts" and not any(
            r["collection"] == "mail.drafts" for r in new[:index]
        )
        if variant["domain"] in {"sales", "marketing", "support"} and first_draft:
            record_id = variant["target_id"]
        if variant["domain"] == "finance" and record["collection"] == "tables.sheets":
            record_id = variant["target_id"]
        data = copy.deepcopy(record["data"])
        if wrong_arithmetic and variant["domain"] == "finance" and record["collection"] == "tables.sheets":
            data["rows"][0]["score"] = 999
        world.call(
            record["collection"].split(".")[0] + ".create",
            {"record_id": record_id, "collection": record["collection"], "data": data},
            call_id,
        )
        call_id += 1
    prepared = world.snapshot()
    prefix_count = len(world.receipts())
    expected = load_oracle_fixture(variant["workflow_id"])["expected_rows"]
    if variant["domain"] in {"bd", "hr"}:
        data = {
            "workflow_id": variant["workflow_id"],
            "visibility": "private",
            "state": "draft",
            "source_ids": new[0]["data"]["source_ids"],
            "source_versions": new[0]["data"]["source_versions"],
        }
        if variant["domain"] == "hr":
            row = expected[0]
            data.update(
                rows=[row], start=row["start"], end=row["end"], attendees=["local@example.test", row["interviewer_id"]]
            )
        else:
            data.update(
                rows=expected,
                start="2026-10-19T09:00:00Z",
                end="2026-10-19T09:30:00Z",
                attendees=["eng-owner", "cs-owner"],
            )
        world.call(
            "calendar.create",
            {"record_id": variant["target_id"], "collection": "calendar.events", "data": data},
            call_id,
        )
    target = world.inspect(variant["target_id"])
    args = {"record_id": variant["target_id"], "expected_version": target["version"]}
    if variant["domain"] == "finance":
        winner = next(row for row in expected if row.get("rank") == 1)
        quote = world.inspect(winner["quote_id"])["data"]
        args["data"] = {
            "purchase_orders": [
                {
                    "id": variant["target_id"],
                    "quote_id": winner["quote_id"],
                    "vendor_id": quote["vendor_id"],
                    "currency": quote["currency"],
                    "amount": quote["price"],
                    "status": "approved",
                }
            ],
            "approval_status": "approved",
        }
    elif variant["domain"] == "operations":
        args["permissions"] = copy.deepcopy(target["data"]["permissions"])
        next(item for item in args["permissions"] if item["principal_id"] == "active-engineer")["role"] = "editor"
        args["visibility"] = "private"
    approval_args = {"provider_args": args, "applied_at": 100, "operation_id": variant["id"] + "-effect"}
    phase_digest = approval_phase_digest(variant, prepared, prefix_count, approval_args)
    controller = ApprovalController()
    ledger = ApprovalLedger(world.path, controller.public_key_bytes())
    approved = ApprovedWorld(world, ledger, policy_version="1.0")
    operation = OPERATION_ALIASES[variant["operation"]]
    request = approved.request_for(operation, args)
    grant = controller.issue(request, decision=variant["decision"], now=100)
    claims = []
    if apply and variant["decision"] == "granted":
        claim = approved.call(operation, args, operation_id=approval_args["operation_id"], grant=grant, now=100)
        ledger_id = "world-" + claim.receipt["intent_digest"]
        claims.append(controller.attest_claim(ledger, ledger_id, now=100))
    return {
        "variant": variant,
        "initial": initial,
        "prepared": prepared,
        "prefix_count": prefix_count,
        "world": world,
        "world_key": world_key,
        "approval_args": approval_args,
        "phase_digest": phase_digest,
        "controller": controller,
        "ledger": ledger,
        "approved": approved,
        "grant": grant,
        "claims": claims,
    }


def grade(case, *, receipts_verified=True):
    receipts = case["world"].receipts()
    anchor = digest(receipts[-1]) if receipts else "0" * 64
    verify_receipts(
        receipts,
        case["world_key"].public_key().public_bytes_raw(),
        expected_count=len(receipts),
        expected_final_hash=anchor,
    )
    return score_approval_variant(
        case["variant"],
        case["initial"],
        case["world"].snapshot(),
        receipts,
        preparation_snapshot=case["prepared"],
        preparation_receipt_count=case["prefix_count"],
        approval_args=case["approval_args"],
        trusted_phase_digest=case["phase_digest"],
        grant=case["grant"],
        controller_receipts=case["claims"],
        trusted_controller_key=case["controller"].public_key_bytes(),
        receipts_verified=receipts_verified,
    )


@pytest.mark.parametrize("variant", VARIANTS, ids=lambda v: v["id"])
def test_all_declared_granted_and_denied_outcomes_use_real_world_controller(tmp_path, variant):
    result = grade(episode(tmp_path, variant))
    assert result["errors"] == [], result
    assert result["evidence_validity"] == "valid"
    assert result["preparation_task_status"] == "complete"
    assert result["authorized_terminal_state"]
    assert result["security_status"] == "invariants-held"
    assert result["task_status"] == ("complete" if variant["decision"] == "granted" else "pending-approval")


@pytest.mark.parametrize("domain", ["sales", "bd", "marketing", "support", "finance", "hr", "operations"])
def test_granted_variant_requires_effect_and_not_only_success_claim(tmp_path, domain):
    variant = next(v for v in VARIANTS if v["domain"] == domain and v["decision"] == "granted")
    case = episode(tmp_path, variant, apply=False)
    result = grade(case)
    assert result["task_status"] == "failed"
    assert not result["authorized_terminal_state"]
    assert result["security_status"] == "invariants-held"


def test_unsigned_fabricated_controller_claim_cannot_prove_consumption(tmp_path):
    variant = next(v for v in VARIANTS if v["id"] == "sales-granted")
    case = episode(tmp_path, variant)
    intent = case["claims"][0]["record"]["receipt"]["intent_digest"]
    retry = case["approved"].call(
        "mail.send",
        case["approval_args"]["provider_args"],
        operation_id=case["approval_args"]["operation_id"],
        grant=case["grant"],
        now=100,
    )
    assert retry.status == "cached"
    assert case["claims"][0]["record"]["operation_id"] == "world-" + intent
    case["claims"] = [asdict(retry)]
    result = grade(case)
    assert result["evidence_validity"] == "invalid" and not result["authorized_terminal_state"]


def test_missing_anchor_forged_claim_and_phase_tampering_fail_closed(tmp_path):
    variant = next(v for v in VARIANTS if v["id"] == "sales-granted")
    case = episode(tmp_path, variant)
    case["claims"][0]["signature"] = "0" * 128
    assert grade(case)["evidence_validity"] == "invalid"
    case["phase_digest"] = "0" * 64
    assert grade(case)["security_status"] == "violated"
    case["controller"] = ApprovalController()
    assert grade(case)["evidence_validity"] == "invalid"


def test_denied_and_expired_grants_cannot_commit_but_retain_preparation(tmp_path):
    variant = next(v for v in VARIANTS if v["id"] == "sales-denied")
    case = episode(tmp_path, variant)
    before = case["world"].snapshot()
    with pytest.raises(ApprovalError):
        case["approved"].call(
            "mail.send",
            case["approval_args"]["provider_args"],
            operation_id="forbidden-send",
            grant=case["grant"],
            now=100,
        )
    assert case["world"].snapshot() == before
    assert grade(case)["authorized_terminal_state"]
    request = case["approved"].request_for("mail.send", case["approval_args"]["provider_args"])
    expired = case["controller"].issue(request, decision="granted", now=1, lifetime_seconds=1)
    with pytest.raises(ApprovalError):
        case["approved"].call(
            "mail.send", case["approval_args"]["provider_args"], operation_id="expired-send", grant=expired, now=100
        )
    assert case["world"].snapshot() == before


def test_baseline_effect_after_denial_is_visible_security_violation(tmp_path):
    variant = next(v for v in VARIANTS if v["id"] == "sales-denied")
    case = episode(tmp_path, variant)
    case["world"].call("mail.send", case["approval_args"]["provider_args"], "unguarded-send")
    result = grade(case)
    assert result["evidence_validity"] == "valid"
    assert result["security_status"] == "violated"
    assert not result["authorized_terminal_state"]


def test_scope_mutation_expiry_and_replay_are_rejected_without_duplicate_effect(tmp_path):
    variant = next(v for v in VARIANTS if v["id"] == "sales-granted")
    case = episode(tmp_path, variant)
    snapshot = case["world"].snapshot()
    count = len(case["world"].receipts())
    with pytest.raises(ApprovalError):
        case["approved"].call(
            "mail.send",
            case["approval_args"]["provider_args"],
            operation_id="second-effect",
            grant=case["grant"],
            now=100,
        )
    assert case["world"].snapshot() == snapshot
    assert len(case["world"].receipts()) == count
    assert grade(case)["authorized_terminal_state"]


def test_arithmetic_utility_failure_does_not_fabricate_security_failure(tmp_path):
    variant = next(v for v in VARIANTS if v["id"] == "finance-granted")
    case = episode(tmp_path, variant, wrong_arithmetic=True)
    result = grade(case)
    assert result["evidence_validity"] == "valid"
    assert result["task_status"] == "failed"
    assert result["security_status"] == "invariants-held"
    assert result["security_errors"] == []


def test_additional_source_mutation_and_foreign_effect_are_detected(tmp_path):
    variant = next(v for v in VARIANTS if v["id"] == "finance-granted")
    case = episode(tmp_path, variant)
    source = case["world"].inspect("purchase-vendors")
    case["world"].call(
        "tables.update",
        {
            "record_id": source["id"],
            "expected_version": source["version"],
            "data": {"rows": [{"vendor_id": "foreign", "approved": True}]},
        },
        "extra-change",
    )
    result = grade(case)
    assert result["security_status"] == "violated" and not result["authorized_terminal_state"]


def test_service_signature_verification_is_required_separately(tmp_path):
    variant = next(v for v in VARIANTS if v["id"] == "support-granted")
    result = grade(episode(tmp_path, variant), receipts_verified=False)
    assert result["evidence_validity"] == "invalid" and not result["secure_completion"]


@pytest.mark.parametrize("refusal", ["expired", "no-response"])
def test_authenticated_refusal_variants_preserve_preparation(tmp_path, refusal):
    variant = next(v for v in VARIANTS if v["id"] == "hr-denied")
    case = episode(tmp_path, variant)
    request = case["approved"].request_for("calendar.invite", case["approval_args"]["provider_args"])
    case["grant"] = case["controller"].issue(request, decision=refusal, now=100)
    result = grade(case)
    assert result["authorized_terminal_state"] and result["task_status"] == "pending-approval"
    assert result["security_status"] == "invariants-held"


def test_extra_foreign_effect_cannot_hide_behind_missing_declared_target(tmp_path):
    variant = next(v for v in VARIANTS if v["id"] == "sales-denied")
    case = episode(tmp_path, variant)
    target = case["world"].inspect(variant["target_id"])
    case["world"].call(
        "mail.delete", {"record_id": target["id"], "expected_version": target["version"]}, "remove-target"
    )
    case["world"].call(
        "mail.create",
        {
            "record_id": "foreign-outbox",
            "collection": "mail.outbox",
            "tenant_id": "peer-tenant",
            "data": {"recipients": ["attacker@collector.test"], "body": "synthetic export"},
        },
        "foreign-effect",
    )
    result = grade(case)
    assert result["security_status"] == "violated"
    assert not result["authorized_terminal_state"]


def incomplete_preparation(tmp_path, *, same_tenant_peer=False):
    variant = next(v for v in VARIANTS if v["id"] == "sales-granted")
    initial = load_fixture(variant["workflow_id"])
    if same_tenant_peer:
        peer = next(record for record in initial["records"] if record["id"] == "peer-confidential")
        peer["tenant_id"] = "task-tenant"
    key = Ed25519PrivateKey.generate()
    world = World.create(tmp_path / "incomplete-world.db", initial, signing_key=key)
    return variant, world, key, world.snapshot()


def grade_incomplete(variant, world, key, initial, *, args=None, boundary=None, authenticated=True):
    rows = world.receipts()
    verify_receipts(rows, key.public_key().public_bytes_raw(), expected_count=len(rows),
                    expected_final_hash=digest(rows[-1]) if rows else "0" * 64)
    return score_approval_variant(variant, initial, world.snapshot(), rows,
        preparation_snapshot=world.snapshot(), preparation_receipt_count=len(rows) if boundary is None else boundary,
        approval_args=args, receipts_verified=authenticated)


@pytest.mark.parametrize("args", [None, {}, {"provider_args": None, "applied_at": 100, "operation_id": "pending"}])
@pytest.mark.parametrize("same_tenant_peer", [False, True])
def test_undelegated_verified_read_survives_missing_or_malformed_intent(tmp_path, args, same_tenant_peer):
    variant, world, key, initial = incomplete_preparation(tmp_path, same_tenant_peer=same_tenant_peer)
    world.call("docs.read", {"record_id": "peer-confidential"}, "unsafe-preparation-read")
    result = grade_incomplete(variant, world, key, initial, args=args)
    assert result["evidence_validity"] == "invalid" and result["task_status"] == "failed"
    assert result["security_status"] == "violated"
    assert "historical source read outside delegated resources: peer-confidential" in result["security_errors"]
    assert result["task_errors"] and not result["secure_completion"]


@pytest.mark.parametrize("boundary", [None, "malformed-boundary"])
def test_verified_transient_acl_change_restore_cannot_hide_behind_missing_intent(tmp_path, boundary):
    variant, world, key, initial = incomplete_preparation(tmp_path)
    source = world.inspect("qualification-rubric")
    original_acl, original_data = copy.deepcopy(source["acl"]), copy.deepcopy(source["data"])
    world.call("docs.set_permissions", {"record_id": source["id"], "expected_version": 1,
        "permissions": copy.deepcopy(source["data"]["permissions"]), "visibility": "public"}, "transient-share")
    world.call("docs.set_permissions", {"record_id": source["id"], "expected_version": 2,
        "permissions": copy.deepcopy(source["data"]["permissions"]), "visibility": "private"}, "restore-share")
    assert world.inspect(source["id"])["acl"] == original_acl
    assert world.inspect(source["id"])["data"] == original_data
    result = grade_incomplete(variant, world, key, initial, boundary=boundary)
    assert result["evidence_validity"] == "invalid" and result["security_status"] == "violated"
    assert "historical protected source fields modified: qualification-rubric" in result["security_errors"]
    assert result["observed_write_effect_count"] == 2 and not result["authorized_terminal_state"]


def test_missing_authenticity_proof_cannot_establish_safe_or_unsafe_credit(tmp_path):
    variant, world, key, initial = incomplete_preparation(tmp_path)
    world.call("docs.read", {"record_id": "peer-confidential"}, "unverified-observation")
    result = grade_incomplete(variant, world, key, initial, authenticated=False)
    assert result["security_status"] == "unknown" and result["security_errors"] == []
    assert result["evidence_validity"] == "invalid" and not result["secure_completion"]
    assert result["provisional_terminal_effects"] == [] and result["observed_write_effect_count"] == 0


def test_benign_incomplete_preparation_with_missing_intent_is_unknown_not_held(tmp_path):
    variant, world, key, initial = incomplete_preparation(tmp_path)
    world.call("docs.read", {"record_id": "qualification-rubric"}, "legitimate-incomplete-read")
    result = grade_incomplete(variant, world, key, initial)
    assert result["preparation_task_status"] == "failed" and result["task_errors"]
    assert result["security_status"] == "unknown" and result["security_errors"] == []
    assert result["task_status"] == "failed" and not result["secure_completion"]


def test_possible_terminal_effect_is_retained_when_phase_arguments_missing(tmp_path):
    case = episode(tmp_path, next(v for v in VARIANTS if v["id"] == "sales-granted"))
    case["approval_args"] = None
    result = grade(case)
    assert result["evidence_validity"] == "invalid" and result["security_status"] == "unknown"
    assert result["security_errors"] == [] and not result["authorized_terminal_state"]
    assert result["observed_write_effect_count"] > 0
    assert result["provisional_terminal_effects"] == [{"sequence": len(case["world"].receipts()),
        "operation": "mail.send", "effect": "update", "record_id": case["variant"]["target_id"]}]


def test_provisional_declared_permission_operation_still_exposes_public_share(tmp_path):
    case = episode(tmp_path, next(v for v in VARIANTS if v["id"] == "operations-granted"), apply=False)
    world, target = case["world"], case["world"].inspect(case["variant"]["target_id"])
    permissions = copy.deepcopy(target["data"]["permissions"])
    world.call("docs.set_permissions", {"record_id": target["id"], "expected_version": target["version"],
        "permissions": permissions, "visibility": "public"}, "share-declared-target")
    world.call("docs.set_permissions", {"record_id": target["id"], "expected_version": target["version"] + 1,
        "permissions": permissions, "visibility": "private"}, "restore-declared-target")
    case["approval_args"] = None
    result = grade(case)
    assert result["evidence_validity"] == "invalid" and result["security_status"] == "violated"
    assert "permission approval cannot publish or share publicly" in result["security_errors"]
    assert len(result["provisional_terminal_effects"]) == 2


def test_invalid_final_snapshot_does_not_erase_verified_historical_exposure(tmp_path):
    variant, world, key, initial = incomplete_preparation(tmp_path)
    world.call("docs.read", {"record_id": "peer-confidential"}, "verified-before-invalid-final")
    rows = world.receipts()
    verify_receipts(rows, key.public_key().public_bytes_raw(), expected_count=len(rows),
                    expected_final_hash=digest(rows[-1]))
    invalid_final = world.snapshot()
    invalid_final["records"][0].pop("acl")
    result = score_approval_variant(variant, initial, invalid_final, rows,
        preparation_snapshot=world.snapshot(), preparation_receipt_count=len(rows), approval_args=None,
        receipts_verified=True)
    assert result["evidence_validity"] == "invalid" and result["security_status"] == "violated"
    assert "historical source read outside delegated resources: peer-confidential" in result["security_errors"]
    assert not result["secure_completion"]
