"""Focused tests for the dormant workflow-capability kernel."""

# pyright: reportAny=false, reportMissingParameterType=false, reportUnknownArgumentType=false
# pyright: reportUnknownLambdaType=false, reportUnknownMemberType=false, reportUnknownParameterType=false
# pyright: reportUnknownVariableType=false, reportUnusedCallResult=false, reportUnusedParameter=false
# pyright: reportUntypedFunctionDecorator=false, reportUnusedFunction=false

from __future__ import annotations

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_workflow_capabilities import StoreWorkflowCapabilitiesMixin
from codex_plugin_scanner.guard.store_workflow_capability_common import WORKFLOW_CAPABILITY_STORE_CLOCK
from codex_plugin_scanner.guard.workflow_capabilities import (
    WORKFLOW_CAPABILITY_ALGORITHM,
    WORKFLOW_CAPABILITY_RECEIPT_SCHEMA,
    WORKFLOW_CAPABILITY_SCHEMA,
    SignedWorkflowCapability,
    WorkflowCapabilityBinding,
    WorkflowCapabilityClaim,
    WorkflowCapabilityError,
    WorkflowCapabilityReceipt,
    WorkflowCapabilityRuleBinding,
    canonical_framed_payload,
    format_utc_timestamp,
    sign_workflow_capability,
    sign_workflow_capability_receipt,
    verify_workflow_capability,
    verify_workflow_capability_receipt,
)

_KEY = b"k" * 32
_KEY_ID = "guard-policy-integrity-key:test"
_ISSUED = datetime(2026, 7, 19, 12, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _fixed_policy_integrity_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        GuardStore,
        "_policy_integrity_secret_material",
        lambda self, *, create: (_KEY, _KEY_ID),
    )
    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", _now)


def _binding(**changes: object) -> WorkflowCapabilityBinding:
    values: dict[str, object] = {
        "operation_id": "test.run",
        "resource_type": "test-file-set",
        "resource_sha256": "1" * 64,
        "repository_sha256": "2" * 64,
        "workspace_sha256": "3" * 64,
        "executable_sha256": "4" * 64,
        "launch_sha256": "5" * 64,
        "policy_id": "local.command-policy",
        "policy_version": "policy.v7",
        "effect_id": "command.effect",
        "effect_version": "effect.v2",
        "decision_id": "decision.exact-local",
        "decision_version": "decision.v3",
        "rules": (
            WorkflowCapabilityRuleBinding("command.exact", "v2"),
            WorkflowCapabilityRuleBinding("workspace.bound", "v1"),
        ),
    }
    values.update(changes)
    return WorkflowCapabilityBinding(
        operation_id=cast(str, values["operation_id"]),
        resource_type=cast(str, values["resource_type"]),
        resource_sha256=cast(str, values["resource_sha256"]),
        repository_sha256=cast(str, values["repository_sha256"]),
        workspace_sha256=cast(str, values["workspace_sha256"]),
        executable_sha256=cast(str, values["executable_sha256"]),
        launch_sha256=cast(str, values["launch_sha256"]),
        policy_id=cast(str, values["policy_id"]),
        policy_version=cast(str, values["policy_version"]),
        effect_id=cast(str, values["effect_id"]),
        effect_version=cast(str, values["effect_version"]),
        decision_id=cast(str, values["decision_id"]),
        decision_version=cast(str, values["decision_version"]),
        rules=cast(tuple[WorkflowCapabilityRuleBinding, ...], values["rules"]),
    )


def _claim(*, capability_id: str = "wc-test-1", max_uses: int = 1, **changes: object) -> WorkflowCapabilityClaim:
    values: dict[str, object] = {
        "schema_version": WORKFLOW_CAPABILITY_SCHEMA,
        "algorithm": WORKFLOW_CAPABILITY_ALGORITHM,
        "capability_id": capability_id,
        "approval_provenance_id": f"provenance-{capability_id}",
        "task_id": "task-local-check",
        "nonce": hashlib.sha256(capability_id.encode("ascii")).hexdigest(),
        "issuer_id": "guard.local",
        "subject_id": "codex.local",
        "binding": _binding(),
        "issued_at": format_utc_timestamp(_ISSUED),
        "not_before": format_utc_timestamp(_ISSUED),
        "expires_at": format_utc_timestamp(_ISSUED + timedelta(hours=1)),
        "max_uses": max_uses,
    }
    values.update(changes)
    return WorkflowCapabilityClaim(
        schema_version=cast(str, values["schema_version"]),
        algorithm=cast(str, values["algorithm"]),
        capability_id=cast(str, values["capability_id"]),
        approval_provenance_id=cast(str, values["approval_provenance_id"]),
        task_id=cast(str, values["task_id"]),
        nonce=cast(str, values["nonce"]),
        issuer_id=cast(str, values["issuer_id"]),
        subject_id=cast(str, values["subject_id"]),
        binding=cast(WorkflowCapabilityBinding, values["binding"]),
        issued_at=cast(str, values["issued_at"]),
        not_before=cast(str, values["not_before"]),
        expires_at=cast(str, values["expires_at"]),
        max_uses=cast(int, values["max_uses"]),
    )


def _now(minutes: int = 1) -> str:
    return format_utc_timestamp(_ISSUED + timedelta(minutes=minutes))


def _store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)


def _issue(
    store: GuardStore,
    claim: WorkflowCapabilityClaim,
    *,
    approval_provenance_id: str | None = None,
) -> SignedWorkflowCapability:
    signed = sign_workflow_capability(claim, key=_KEY, key_id=_KEY_ID)
    return store.issue_workflow_capability(
        signed,
        approval_provenance_id=approval_provenance_id or claim.approval_provenance_id,
    )


def _claim_capability(
    store: GuardStore,
    claim: WorkflowCapabilityClaim,
    *,
    invocation_id: str,
    expected_binding: WorkflowCapabilityBinding | None = None,
):
    return store.claim_workflow_capability(
        claim.capability_id,
        invocation_id=invocation_id,
        expected_binding=claim.binding if expected_binding is None else expected_binding,
        expected_subject_id=claim.subject_id,
        expected_task_id=claim.task_id,
        expected_issuer_id=claim.issuer_id,
        expected_approval_provenance_id=claim.approval_provenance_id,
    )


def test_framing_and_signatures_are_deterministic_and_tamper_evident() -> None:
    claim = _claim()
    first = sign_workflow_capability(claim, key=_KEY, key_id=_KEY_ID)
    second = sign_workflow_capability(claim, key=_KEY, key_id=_KEY_ID)

    assert first == second
    assert canonical_framed_payload("ab", {"c": 1}) != canonical_framed_payload("a", {"bc": 1})
    verify_workflow_capability(first, key=_KEY, key_id=_KEY_ID, now=_now(), expected_binding=claim.binding)

    tampered = replace(first, claim=replace(claim, subject_id="other.subject"))
    with pytest.raises(WorkflowCapabilityError, match="signature_invalid"):
        verify_workflow_capability(tampered, key=_KEY, key_id=_KEY_ID, now=_now(), expected_binding=claim.binding)


def test_contract_rejects_unknown_null_wildcard_bool_and_noncanonical_rules() -> None:
    signed = sign_workflow_capability(_claim(), key=_KEY, key_id=_KEY_ID)
    payload = signed.to_dict()
    payload["unknown"] = "field"
    with pytest.raises(WorkflowCapabilityError, match="contract_keys"):
        type(signed).from_dict(payload)
    with pytest.raises(WorkflowCapabilityError, match="operation_id"):
        _binding(operation_id="*")
    with pytest.raises(WorkflowCapabilityError, match="resource_sha256"):
        _binding(resource_sha256="not-a-digest")
    with pytest.raises(WorkflowCapabilityError, match="rule_bindings"):
        _binding(rules=tuple(reversed(_binding().rules)))
    with pytest.raises(WorkflowCapabilityError, match="max_uses"):
        _claim(max_uses=True)


def test_direct_construction_rejects_nested_type_forgeries() -> None:
    with pytest.raises(WorkflowCapabilityError, match="rule_bindings"):
        _binding(rules=cast(tuple[WorkflowCapabilityRuleBinding, ...], ("bad",)))
    claim = _claim()
    with pytest.raises(WorkflowCapabilityError, match="capability_binding"):
        replace(claim, binding=cast(WorkflowCapabilityBinding, object()))
    signed = sign_workflow_capability(claim, key=_KEY, key_id=_KEY_ID)
    with pytest.raises(WorkflowCapabilityError, match="capability_claim"):
        replace(signed, claim=cast(WorkflowCapabilityClaim, object()))
    receipt = WorkflowCapabilityReceipt(
        schema_version=WORKFLOW_CAPABILITY_RECEIPT_SCHEMA,
        receipt_id="wcr-direct",
        capability_id=claim.capability_id,
        task_id=claim.task_id,
        invocation_id="invocation-direct",
        approval_provenance_id=claim.approval_provenance_id,
        claim_sha256="f" * 64,
        binding=claim.binding,
        use_number=1,
        event_id=1,
        claimed_at=_now(),
    )
    with pytest.raises(WorkflowCapabilityError, match="receipt_binding"):
        replace(receipt, binding=cast(WorkflowCapabilityBinding, object()))
    signed_receipt = sign_workflow_capability_receipt(receipt, key=_KEY, key_id=_KEY_ID)
    with pytest.raises(WorkflowCapabilityError, match="capability_receipt"):
        replace(signed_receipt, receipt=cast(WorkflowCapabilityReceipt, object()))


def test_time_and_alpha_bounds_fail_closed() -> None:
    signed = sign_workflow_capability(_claim(), key=_KEY, key_id=_KEY_ID)
    with pytest.raises(WorkflowCapabilityError, match="not_yet_valid"):
        verify_workflow_capability(signed, key=_KEY, key_id=_KEY_ID, now=_now(-1), expected_binding=_binding())
    with pytest.raises(WorkflowCapabilityError, match="expired"):
        verify_workflow_capability(signed, key=_KEY, key_id=_KEY_ID, now=_now(60), expected_binding=_binding())
    with pytest.raises(WorkflowCapabilityError, match="ttl_exceeds"):
        _claim(expires_at=format_utc_timestamp(_ISSUED + timedelta(hours=25)))
    with pytest.raises(WorkflowCapabilityError, match="max_uses"):
        _claim(max_uses=51)


def test_issue_lookup_claim_and_reopen(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(approval_provenance_id="provenance-054")
    issued = _issue(store, claim)
    receipt = _claim_capability(
        store,
        claim,
        invocation_id="invocation-1",
    )

    assert store.lookup_workflow_capability(claim.capability_id) == issued
    assert receipt.receipt.task_id == claim.task_id
    assert receipt.receipt.approval_provenance_id == "provenance-054"
    verify_workflow_capability_receipt(receipt, key=_KEY, key_id=_KEY_ID)
    assert _store(tmp_path).lookup_workflow_capability(claim.capability_id) == issued
    issue_events = store.list_events(event_name="workflow_capability.issued")
    assert issue_events[0]["occurred_at"] == _now()
    assert issue_events[0]["occurred_at"] != claim.issued_at


def test_replay_and_max_use_are_independent_failures(tmp_path) -> None:
    store = _store(tmp_path)
    first = _claim(capability_id="wc-first", max_uses=2)
    second = _claim(capability_id="wc-second", max_uses=1)
    _issue(store, first)
    _issue(store, second)
    _claim_capability(store, first, invocation_id="invocation-shared")

    with pytest.raises(WorkflowCapabilityError, match="replayed"):
        _claim_capability(store, second, invocation_id="invocation-shared")
    _claim_capability(store, first, invocation_id="invocation-2")
    with pytest.raises(WorkflowCapabilityError, match="exhausted"):
        _claim_capability(store, first, invocation_id="invocation-3")


def test_issue_rejects_approval_drift_and_nonce_reuse(tmp_path) -> None:
    store = _store(tmp_path)
    first = _claim(capability_id="wc-nonce-first")
    with pytest.raises(WorkflowCapabilityError, match="approval_binding_mismatch"):
        _issue(store, first, approval_provenance_id="provenance-other")
    _issue(store, first)
    replay = _claim(capability_id="wc-nonce-replay", nonce=first.nonce)
    with pytest.raises(WorkflowCapabilityError, match="already_exists"):
        _issue(store, replay)


@pytest.mark.parametrize(
    "field,value",
    [
        ("policy_version", "policy.v8"),
        ("policy_id", "local.other-policy"),
        ("effect_version", "effect.v3"),
        ("effect_id", "command.other-effect"),
        ("decision_version", "decision.v4"),
        ("decision_id", "decision.other"),
        ("operation_id", "test.lint"),
        ("resource_type", "source-file-set"),
        ("resource_sha256", "6" * 64),
        ("repository_sha256", "0" * 64),
        ("workspace_sha256", "9" * 64),
        ("executable_sha256", "8" * 64),
        ("launch_sha256", "7" * 64),
        ("rules", (WorkflowCapabilityRuleBinding("command.other", "v1"),)),
    ],
)
def test_every_context_drift_fails_closed(tmp_path, field: str, value: object) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id=f"wc-drift-{field}")
    _issue(store, claim)
    with pytest.raises(WorkflowCapabilityError, match="context_mismatch"):
        _claim_capability(
            store,
            claim,
            invocation_id=f"invocation-{field}",
            expected_binding=replace(claim.binding, **{field: value}),
        )


def test_concurrent_claims_never_exceed_exact_use_limit(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-concurrent", max_uses=8)
    _issue(store, claim)

    def attempt(invocation_id: str) -> str:
        contender = _store(tmp_path)
        try:
            _claim_capability(
                contender,
                claim,
                invocation_id=invocation_id,
            )
        except WorkflowCapabilityError as error:
            return str(error)
        return "claimed"

    with ThreadPoolExecutor(max_workers=32) as executor:
        results = list(executor.map(attempt, (f"invocation-{index}" for index in range(32))))
    assert results.count("claimed") == 8
    assert results.count("capability_exhausted") == 24
    with sqlite3.connect(store.path) as connection:
        use_row = connection.execute(
            "select used_count from guard_workflow_capabilities where capability_id = ?",
            (claim.capability_id,),
        ).fetchone()
        receipt_row = connection.execute("select count(*) from guard_workflow_capability_receipts").fetchone()
        transition_rows = connection.execute(
            "select sequence from guard_workflow_capability_authority_transitions order by sequence"
        ).fetchall()
    assert use_row == (8,)
    assert receipt_row == (8,)
    assert transition_rows == [(index,) for index in range(1, 10)]


def test_claim_rolls_back_use_and_event_when_audit_link_fails(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-rollback")
    _issue(store, claim)

    def fail_event(*args: object, **kwargs: object) -> int:
        raise RuntimeError("forced_event_failure")

    monkeypatch.setattr(StoreWorkflowCapabilitiesMixin, "_insert_workflow_capability_event", fail_event)
    with pytest.raises(RuntimeError, match="forced_event_failure"):
        _claim_capability(
            store,
            claim,
            invocation_id="invocation-rollback",
        )
    with sqlite3.connect(store.path) as connection:
        used_count = connection.execute(
            "select used_count from guard_workflow_capabilities where capability_id = ?", (claim.capability_id,)
        ).fetchone()
        receipt_count = connection.execute("select count(*) from guard_workflow_capability_receipts").fetchone()
    assert used_count == (0,)
    assert receipt_count == (0,)


def test_revocation_blocks_claim_and_is_idempotent(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-revoked")
    _issue(store, claim)
    with pytest.raises(WorkflowCapabilityError, match="reason_code"):
        store.revoke_workflow_capability(claim.capability_id, reason_code="https://example.invalid/private")
    assert store.revoke_workflow_capability(claim.capability_id, reason_code="operator.revoked")
    assert not store.revoke_workflow_capability(claim.capability_id, reason_code="operator.revoked")
    with pytest.raises(WorkflowCapabilityError, match="revoked"):
        _claim_capability(
            store,
            claim,
            invocation_id="invocation-revoked",
        )


def test_audit_is_privacy_safe_and_receipt_is_linked_and_immutable(tmp_path) -> None:
    store = _store(tmp_path)
    approval_id = "approval-private"
    claim = _claim(capability_id="wc-private", approval_provenance_id=approval_id)
    invocation_id = "invocation-private"
    _issue(store, claim, approval_provenance_id=approval_id)
    _claim_capability(
        store,
        claim,
        invocation_id=invocation_id,
    )
    events = store.list_events(event_name="workflow_capability.claimed")
    payload = json.dumps(events, sort_keys=True)
    for private_value in (claim.capability_id, claim.task_id, approval_id, invocation_id):
        assert private_value not in payload

    with sqlite3.connect(store.path) as connection:
        linked = connection.execute(
            """
            select r.event_id = e.event_id from guard_workflow_capability_receipts r
            join guard_events e on e.event_id = r.event_id
            """
        ).fetchone()
        assert linked == (1,)
        with pytest.raises(sqlite3.IntegrityError, match="receipt_immutable"):
            connection.execute("update guard_workflow_capability_receipts set use_number = 2")


def test_existing_invalid_schema_fails_closed(tmp_path) -> None:
    home = tmp_path / "guard-home"
    home.mkdir()
    database = home / "guard.db"
    with sqlite3.connect(database) as connection:
        connection.execute("create table guard_workflow_capabilities (capability_id text primary key)")
    with pytest.raises(RuntimeError, match="invalid_workflow_capability_schema"):
        GuardStore(home, prime_policy_integrity=False)
    with sqlite3.connect(database) as connection:
        version = connection.execute("select 1 from schema_migrations where version = 14").fetchone()
    assert version is None


def test_extra_owned_schema_object_fails_closed(tmp_path) -> None:
    store = _store(tmp_path)
    with sqlite3.connect(store.path) as connection:
        connection.execute("create index idx_guard_workflow_hostile on guard_workflow_capabilities (key_id)")
    with pytest.raises(RuntimeError, match="owned_objects"):
        GuardStore(store.guard_home, prime_policy_integrity=False)
