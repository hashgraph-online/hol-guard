"""Fact sets for the approval-reuse step vectors.

``record_artifact_reuse_step_vectors.py`` walks every set below through the
retired Python ladder. The blocks mirror the ladder's stages: the saved
decision and its claim (stage A), the trusted-request override and its claim
(stage B), the claimed pass (stage C), the stages together, and package
requests, whose own resolver claimed before the ladder ran.
"""

from __future__ import annotations

import base64
import itertools
import json
from collections.abc import Iterator
from typing import Any

ACTIONS = ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block")
CHANGED = "approval_reuse_content_changed"
IDENTITY_CHANGED = "approval_reuse_identity_changed"
RUNTIME_HASH = "runtime-context-token"


def _token(seed: str) -> str:
    body = {
        "version": 1,
        **{field: seed * 64 for field in ("identity", "content", "capabilities", "policy", "sandbox")},
    }
    encoded = base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode()).rstrip(b"=")
    return "guard-approval-context:v1:" + encoded.decode()


CTX_TOKEN = _token("a")
LEGACY_HASH = "b" * 64

# --- Enumerated facts ---------------------------------------------------------


def _saved(**fields: Any) -> dict[str, Any]:
    saved: dict[str, Any] = {
        "stored_present": False,
        "stored_action": None,
        "stored_artifact_hash": None,
        "integrity_failure": False,
        "stored_validation_reason": None,
        "cursor_native_present": False,
        "cursor_validation_reason": None,
        "diagnostic_reason": None,
        "diagnostic_stored_hash": None,
    }
    saved.update(fields)
    return saved


def _allow(**fields: Any) -> dict[str, Any]:
    return _saved(**{"stored_present": True, "stored_action": "allow", "stored_artifact_hash": CTX_TOKEN, **fields})


SAVED: dict[str, dict[str, Any]] = {
    "none": _saved(),
    "allow": _allow(),
    "allow_legacy_hash": _allow(stored_artifact_hash=LEGACY_HASH),
    "allow_changed": _allow(stored_validation_reason=CHANGED),
    "allow_identity_changed": _allow(stored_validation_reason=IDENTITY_CHANGED),
    "saved_block": _saved(stored_present=True, stored_action="block", stored_artifact_hash=CTX_TOKEN),
    "saved_review": _saved(stored_present=True, stored_action="review", stored_artifact_hash=CTX_TOKEN),
    "integrity_with_allow": _allow(integrity_failure=True),
    "integrity_alone": _saved(integrity_failure=True),
    "cursor_native": _saved(cursor_native_present=True),
    "cursor_native_changed": _saved(cursor_native_present=True, cursor_validation_reason=CHANGED),
    "expired": _saved(diagnostic_reason="approval_reuse_expired", diagnostic_stored_hash=CTX_TOKEN),
    "changed_hash": _saved(diagnostic_reason=CHANGED, diagnostic_stored_hash=LEGACY_HASH),
}

STORED_SOURCES = (("approval-gate", None), ("approval-gate-once", "request-1"), ("manual", None))


def _stored(action: Any, source: str, request_id: str | None, artifact_hash: Any = CTX_TOKEN) -> dict[str, Any]:
    return {"action": action, "artifact_hash": artifact_hash, "source": source, "request_id": request_id}


def _stored_for(saved: dict[str, Any], sources: tuple[tuple[str, str | None], ...]) -> list[dict[str, Any] | None]:
    if not saved["stored_present"]:
        return [None]
    return [
        _stored(saved["stored_action"], source, request_id, saved["stored_artifact_hash"])
        for source, request_id in sources
    ]


def _facts(
    *,
    current: str,
    saved: dict[str, Any] | None = None,
    stored: dict[str, Any] | None = None,
    claim: bool = True,
    remembered: bool = False,
    preflight: bool = False,
    reasons: list[dict[str, Any]] | None = None,
    evaluation: str = "review",
    override: dict[str, Any] | None = None,
    claimed: dict[str, Any] | None = None,
) -> dict[str, Any]:
    lookup: dict[str, Any] = (
        {"mode": "tool", "saved": saved, "workflow_preflight": preflight}
        if reasons is None
        else {"mode": "package", "reasons": reasons, "evaluation_policy_action": evaluation}
    )
    return {
        "claim_saved_approval": claim,
        "current_action": current,
        "remembered_rule_rejected": remembered,
        "stored": stored,
        "lookup": lookup,
        "trusted_override": override,
        "claimed": claimed,
    }


def _claimed(
    token: str | None = None,
    *,
    refresh_failed: bool = False,
    capability_required: bool = False,
    authorization_claimed: bool = False,
    trusted: bool = False,
    consumed: bool = False,
) -> dict[str, Any]:
    return {
        "claimed_hash": RUNTIME_HASH,
        "token_validation_reason": token,
        "post_claim_refresh_failed": refresh_failed,
        "workflow_capability_required": capability_required,
        "workflow_authorization_claimed": authorization_claimed,
        "claimed_trusted_request_override": trusted,
        "claimed_package_approval_consumed": consumed,
    }


def _override(token: str | None = None, stored_validation: str | None = None) -> dict[str, Any]:
    return {"token_validation_reason": token, "stored_validation_reason": stored_validation}


OVERRIDES = [_override(token, stored) for token, stored in itertools.product((None, CHANGED), (None, CHANGED))]
CLAIMED_ALL = [
    _claimed(
        token,
        refresh_failed=refresh,
        capability_required=cap,
        authorization_claimed=auth,
        trusted=trusted,
        consumed=consumed,
    )
    for token, refresh, cap, auth, trusted, consumed in itertools.product(
        (None, CHANGED), (False, True), (False, True), (False, True), (False, True), (False, True)
    )
]
CLAIMED_FEW = [
    _claimed(),
    _claimed(CHANGED),
    _claimed(refresh_failed=True),
    _claimed(trusted=True, consumed=True),
    _claimed(capability_required=True),
    _claimed(capability_required=True, authorization_claimed=True),
]

PACKAGE_REUSE_ACCEPTED = {
    "action": "allow",
    "status": "accepted",
    "reason_code": "approval_reuse_accepted",
    "current_action": "review",
    "saved_action": "allow",
    "should_claim": True,
    "original_current_type": "str",
}
PACKAGE_REUSE_REJECTED = {
    "action": "require-reapproval",
    "status": "rejected",
    "reason_code": "approval_reuse_reapproval_required",
    "current_action": "review",
    "saved_action": "allow",
    "should_claim": False,
    "original_current_type": "str",
}
PACKAGE_REASONS: dict[str, list[dict[str, Any]]] = {
    "none": [],
    "unrelated": [{"code": "package_risk", "message": "risky"}],
    "allow_consumed": [{"code": "saved_package_approval", "approval_claim_disposition": "consumed"}],
    "allow_retained": [{"code": "saved_package_approval", "approval_claim_disposition": "retained"}],
    "allow_unnamed": [{"code": "saved_package_approval"}],
    "allow_bogus": [{"code": "saved_package_approval", "approval_claim_disposition": "bogus"}],
    "block": [{"code": "saved_package_block"}],
    "allow_with_reuse": [{"code": "saved_package_approval", "approval_reuse": PACKAGE_REUSE_ACCEPTED}],
    "allow_with_rejected": [{"code": "saved_package_approval", "approval_reuse": PACKAGE_REUSE_REJECTED}],
    "block_with_reuse": [{"code": "saved_package_block", "approval_reuse": PACKAGE_REUSE_REJECTED}],
    "reuse_only": [{"code": "x", "approval_reuse": PACKAGE_REUSE_ACCEPTED}],
    "two_reasons": [
        {"code": "package_risk"},
        {"code": "saved_package_approval", "approval_reuse": PACKAGE_REUSE_ACCEPTED},
    ],
}
PACKAGE_STORED: list[dict[str, Any] | None] = [
    None,
    _stored("allow", "approval-gate", None),
    _stored("allow", "approval-gate-once", "request-1"),
    _stored("block", "approval-gate", None),
]


def cases() -> Iterator[dict[str, Any]]:
    """Every fact set recorded; the blocks mirror the ladder's stages."""

    # Stage A: the saved decision, its claim and the claim's failure.
    for current, saved in itertools.product(ACTIONS, SAVED.values()):
        for stored, claim, preflight in itertools.product(
            _stored_for(saved, STORED_SOURCES[:2]), (True, False), (False, True)
        ):
            yield _facts(current=current, saved=saved, stored=stored, claim=claim, preflight=preflight)
    # Stage B: the trusted-request override and its claim.
    names = ("none", "allow", "allow_changed", "saved_block", "integrity_with_allow", "cursor_native")
    for current, name in itertools.product(ACTIONS, names):
        saved = SAVED[name]
        for stored, override, claim, remembered in itertools.product(
            _stored_for(saved, STORED_SOURCES), OVERRIDES, (True, False), (False, True)
        ):
            yield _facts(
                current=current, saved=saved, stored=stored, claim=claim, remembered=remembered, override=override
            )
    # Stage C: the claimed pass.
    for current, name in itertools.product(ACTIONS, ("none", "allow", "allow_changed", "integrity_with_allow")):
        saved = SAVED[name]
        stored = _stored_for(saved, STORED_SOURCES[:2])[0]
        for claimed in CLAIMED_ALL:
            yield _facts(current=current, saved=saved, stored=stored, claim=False, claimed=claimed)
        for claimed, claim, remembered in itertools.product(CLAIMED_FEW, (True, False), (False, True)):
            yield _facts(
                current=current, saved=saved, stored=stored, claim=claim, remembered=remembered, claimed=claimed
            )
    # Override and claimed pass together.
    for current, name in itertools.product(ACTIONS, ("none", "allow", "allow_changed")):
        saved = SAVED[name]
        for stored, override, claimed in itertools.product(
            _stored_for(saved, STORED_SOURCES[:2]), OVERRIDES[:2], CLAIMED_FEW[:4]
        ):
            yield _facts(current=current, saved=saved, stored=stored, claim=False, override=override, claimed=claimed)
    # Package requests: the resolver already claimed; the step settles it.
    for current, evaluation, reasons, stored, claim in itertools.product(
        ("allow", "review", "require-reapproval", "block"),
        ("allow", "review", "block"),
        PACKAGE_REASONS.values(),
        PACKAGE_STORED,
        (True, False),
    ):
        yield _facts(current=current, reasons=reasons, evaluation=evaluation, stored=stored, claim=claim)
    for current, reasons, stored, override, claim, remembered in itertools.product(
        ("review", "require-reapproval", "block"),
        [PACKAGE_REASONS[name] for name in ("none", "allow_retained", "allow_with_reuse", "block")],
        PACKAGE_STORED,
        OVERRIDES,
        (True, False),
        (False, True),
    ):
        yield _facts(
            current=current, reasons=reasons, stored=stored, claim=claim, remembered=remembered, override=override
        )
    for current, reasons, stored, claimed in itertools.product(
        ("review", "require-reapproval"),
        [PACKAGE_REASONS[name] for name in ("none", "allow_retained", "allow_with_reuse", "block", "two_reasons")],
        PACKAGE_STORED,
        CLAIMED_FEW + CLAIMED_ALL[::7],
    ):
        yield _facts(current=current, reasons=reasons, stored=stored, claim=False, claimed=claimed)
