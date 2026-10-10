"""Approval proof predicates are answered by the native runtime.

The vectors were recorded from the retired Python predicates before they were
deleted, so a divergence here means the resident changed behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_approval_proof as proof

_VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "approval_proof" / "parity_vectors.json").read_text(encoding="utf-8")
)
_ARTIFACT = SimpleNamespace(harness="codex", artifact_id="codex:workspace:tool")


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_matches_recorded_python_behaviour() -> None:
    mismatches = []
    for vector in _VECTORS:
        outcome = proof.native_approval_proof(vector["query"])
        expected = vector["expected"]
        if (outcome.accepted, outcome.claim_disposition) != (expected["accepted"], expected["claim_disposition"]):
            mismatches.append(vector["name"])
    assert mismatches == []


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_predicate_helpers_present_resident_answers() -> None:
    proof_row = {
        "source": "approval-gate-once",
        "approval_id": "approval-id",
        "action": "allow",
        "scope": "artifact",
        "harness": "codex",
        "artifact_id": "codex:workspace:tool",
        "artifact_hash": "hash",
        "expires_at": "2030-01-01T00:00:00+00:00",
    }
    assert proof.fresh_local_tool_approval_matches(proof_row, artifact=_ARTIFACT, artifact_hash="hash")
    assert not proof.fresh_local_tool_approval_matches(proof_row, artifact=_ARTIFACT, artifact_hash="other")
    assert proof.approval_reuse_claim_disposition(proof_row) == "consumed"
    assert proof.fresh_claim_allows_reapproval(
        claim_disposition="consumed",
        reason_code=None,
        decision=proof_row,
        artifact=_ARTIFACT,
        artifact_hash="hash",
    )
    assert not proof.fresh_claim_allows_reapproval(
        claim_disposition="retained",
        reason_code=None,
        decision=proof_row,
        artifact=_ARTIFACT,
        artifact_hash="hash",
    )
    assert proof.fresh_lookup_preserves_claim(None)
    assert not proof.fresh_lookup_preserves_claim("approval_reuse_integrity_failure")
    assert proof.claimed_approval_authorizes_postclaim_review(
        claim_disposition="consumed", claimed_decision=None, current_decision=None
    )
    assert not proof.claimed_approval_authorizes_postclaim_review(
        claim_disposition="retained", claimed_decision=proof_row, current_decision=None
    )


def _resident_returning(monkeypatch: pytest.MonkeyPatch, reply) -> None:
    monkeypatch.setattr(proof, "_resolve_digest_home", lambda _home: Path("/tmp/approval-proof-home"))

    def fake(*, request, **_kwargs):
        return reply(request)

    monkeypatch.setattr(proof, "_resident_request", fake)


def _good(request: dict[str, object], **overrides: object) -> dict[str, object]:
    reply: dict[str, object] = {
        "schema": "guard-approval-proof-result.v1",
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + proof._canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
        "payload": {"accepted": True, "claim_disposition": "consumed"},
    }
    reply.update(overrides)
    return reply


@pytest.mark.parametrize(
    "overrides",
    [
        {"request_sha256": "sha256:" + "0" * 64},
        {"request_id": "someone-else"},
        {"schema": "wrong"},
        {"status": "error", "code": "native_approval_proof_schema_mismatch", "payload": None},
        {"status": "error", "code": "arbitrary text", "payload": None},
        {"payload": {"accepted": True}},
        {"payload": {"accepted": "yes", "claim_disposition": None}},
        {"payload": {"accepted": True, "claim_disposition": "other"}},
        {"payload": {"accepted": True, "claim_disposition": []}},
        {"payload": {"accepted": True, "claim_disposition": {}}},
        {"payload": None},
    ],
)
def test_unbound_or_malformed_answers_raise_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]
) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request, **overrides))
    with pytest.raises(proof.NativeApprovalProofError):
        proof.native_approval_proof({"kind": "lookup_preserves_claim", "reason_code": None})
    assert proof.fresh_lookup_preserves_claim(None) is False
    assert proof.approval_reuse_claim_disposition({"action": "allow", "decision_id": 1}) is None


def test_bound_answer_is_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request))
    outcome = proof.native_approval_proof({"kind": "lookup_preserves_claim", "reason_code": None})
    assert (outcome.accepted, outcome.claim_disposition) == (True, "consumed")


def test_unavailable_resident_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda _request: None)
    with pytest.raises(proof.NativeApprovalProofError):
        proof.native_approval_proof({"kind": "lookup_preserves_claim", "reason_code": None})
    assert not proof.claimed_approval_authorizes_postclaim_review(
        claim_disposition="consumed", claimed_decision=None, current_decision=None
    )


def test_non_json_rows_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proof, "_resolve_digest_home", lambda _home: Path("/tmp/approval-proof-home"))
    with pytest.raises(proof.NativeApprovalProofError):
        proof.native_approval_proof({"kind": "claim_disposition", "decision": {"action": object()}})


def test_helpers_send_the_callers_guard_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    homes: list[Path] = []

    def fake(*, request, guard_home, **_kwargs):
        homes.append(guard_home)
        return _good(request)

    monkeypatch.setattr(proof, "_resolve_digest_home", lambda home: home if home is not None else Path("/ambient"))
    monkeypatch.setattr(proof, "_resident_request", fake)
    row = {
        "source": "approval-gate-once",
        "approval_id": "approval-id",
        "action": "allow",
        "scope": "artifact",
        "harness": "codex",
        "artifact_id": "codex:workspace:tool",
        "artifact_hash": "hash",
        "expires_at": "2030-01-01T00:00:00+00:00",
    }
    proof.fresh_local_tool_approval_matches(row, artifact=_ARTIFACT, artifact_hash="hash", guard_home=tmp_path)
    proof.fresh_lookup_preserves_claim(None, guard_home=tmp_path)
    proof.claimed_approval_authorizes_postclaim_review(
        claim_disposition="consumed", claimed_decision=None, current_decision=None, guard_home=tmp_path
    )
    proof.fresh_claim_allows_reapproval(
        claim_disposition="consumed",
        reason_code=None,
        decision=row,
        artifact=_ARTIFACT,
        artifact_hash="hash",
        guard_home=tmp_path,
    )
    assert homes == [tmp_path] * 4
