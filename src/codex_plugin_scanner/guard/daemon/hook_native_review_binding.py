"""Bind ordinary local review reuse to its verified native policy domain."""

from __future__ import annotations

import hmac
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeGuard

from ..native_decision_receipt import edge_receipt
from ..store_base import _workspace_policy_key

# v2 drops ``policy_digest``: it is ``H(config_digest, rule_digest)`` over the
# whole compiled snapshot, so it moves whenever the publisher republishes, even
# for observed state that cannot weaken a verdict. The retry's own anchor
# covers the configured policy, ``rule_digest`` and ``runtime_identity``, and
# the receipt is still required to carry a well-formed ``policy_digest``.
_SCHEMA = "guard.native-review-policy-binding.v2"


def native_review_policy_binding(
    *, harness: str, native_result: Mapping[str, object], verified_receipt: object
) -> dict[str, object] | None:
    """Capture only a typed native receipt; request payload metadata is not authority.

    Absence on both native surfaces retains the legacy contract. A partially
    present or inconsistent command domain cannot create an unbound approval.
    Receipt persistence is asynchronous and does not participate in this check.
    """

    receipt_bound = isinstance(verified_receipt, Mapping) and "command_extensions" in verified_receipt
    if "command_extensions" not in native_result and not receipt_bound:
        return None
    receipt = edge_receipt(harness, native_result, verified_receipt)
    if receipt is None:
        raise ValueError("native_review_policy_binding_invalid")
    if any(not isinstance(receipt.get(field), str) for field in ("policy_digest", "rule_digest", "runtime_identity")):
        raise ValueError("native_review_policy_binding_invalid")
    command_binding = receipt.get("command_extensions")
    if not isinstance(command_binding, dict):
        raise ValueError("native_review_policy_binding_invalid")
    uncertainty_count = command_binding.get("uncertainty_count")
    if type(uncertainty_count) is not int or uncertainty_count < 0:
        raise ValueError("native_review_policy_binding_invalid")
    return {
        "schema": _SCHEMA,
        "rule_digest": receipt["rule_digest"],
        "runtime_identity": receipt["runtime_identity"],
        "command_extensions": dict(command_binding),
    }


def native_review_settle(
    store: object,
    *,
    harness: str,
    artifact_id: str,
    tool_name: str,
    launch_target: str,
    workspace: Path | None,
    identity: str | None,
    spend: bool,
) -> str | None:
    """Settle a retry in one resident transaction.

    ``"blocked"`` when the user chose Keep blocked for it, ``"allowed"`` when
    ``spend`` spent an approve-once, else ``None``.
    """

    settle = getattr(store, "settle_native_review_reuse", None)
    if not callable(settle) or identity is None or not launch_target:
        return None
    try:
        settled = settle(
            harness=harness,
            artifact_id=artifact_id,
            artifact_name=tool_name,
            artifact_hash=identity,
            launch_target=launch_target,
            workspace=str(workspace) if workspace is not None else None,
            now=datetime.now(tz=timezone.utc).isoformat(),
            spend=spend,
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return None
    return settled if settled in ("blocked", "allowed") else None


def native_review_claimed_allow(
    store: object,
    *,
    harness: str,
    artifact_id: str,
    workspace: Path | None,
    identity: str | None,
    claimed_saved_allow_hash: str,
    claimed_approval_request_id: str | None,
    claim_saved_approval: bool,
) -> bool:
    """Settle a MAC'd once-approval bound to this exact native request."""

    if identity is None or not hmac.compare_digest(identity, claimed_saved_allow_hash):
        return False
    peek = getattr(store, "peek_local_once_approval", None)
    if not callable(peek):
        return False
    try:
        decision = peek(
            harness=harness,
            artifact_id=artifact_id,
            artifact_hash=identity,
            workspace=str(workspace) if workspace is not None else None,
            publisher=None,
            now=datetime.now(tz=timezone.utc).isoformat(),
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return False
    if not _allows_request(decision, claimed_approval_request_id):
        # A Cloud Review allow is stored apart from local approvals and only
        # answers to the request it was issued for. The live completion that
        # asks with claim_saved_approval=False consumes it afterwards; a
        # retry that would claim it here is left to the ordinary path.
        if claim_saved_approval or claimed_approval_request_id is None:
            return False
        return _exact_cloud_allow(
            store,
            request_id=claimed_approval_request_id,
            harness=harness,
            artifact_id=artifact_id,
            workspace=workspace,
            identity=identity,
        )
    if not claim_saved_approval:
        return True
    approval_id = decision.get("approval_id")
    claim = getattr(store, "claim_approval_reuse_decision", None)
    if not isinstance(approval_id, str) or not callable(claim):
        return False
    try:
        return (
            claim(
                decision,
                now=datetime.now(tz=timezone.utc).isoformat(),
                consume_local_once=True,
            )
            is True
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return False


def _allows_request(decision: object, request_id: str | None) -> TypeGuard[Mapping[str, object]]:
    if not isinstance(decision, Mapping) or decision.get("action") != "allow":
        return False
    return request_id is None or decision.get("request_id") == request_id


def _exact_cloud_allow(
    store: object,
    *,
    request_id: str,
    harness: str,
    artifact_id: str,
    workspace: Path | None,
    identity: str,
) -> bool:
    peek = getattr(store, "peek_exact_cloud_local_once_approval", None)
    if not callable(peek):
        return False
    try:
        decision = peek(request_id=request_id, now=datetime.now(tz=timezone.utc).isoformat())
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return False
    if not _allows_request(decision, request_id):
        return False
    stored_hash = decision.get("artifact_hash")
    return (
        decision.get("harness") == harness
        and decision.get("artifact_id") == artifact_id
        and isinstance(stored_hash, str)
        and hmac.compare_digest(stored_hash, identity)
        and decision.get("workspace") == _workspace_policy_key(str(workspace) if workspace is not None else None)
    )
