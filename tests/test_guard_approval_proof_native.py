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
