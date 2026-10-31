"""Bind ordinary local review reuse to its verified native policy domain."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

from ..native_decision_receipt import edge_receipt

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
    """Settle a MAC'd once-approval bound to this exact native request.

    The resident owns the identity check, the exact peek, the spend and the
    exact Cloud fallback; no answer means no allow.
    """

    settle = getattr(store, "settle_claimed_native_allow", None)
    if identity is None or not callable(settle):
        return False
    try:
        return (
            settle(
                harness=harness,
                artifact_id=artifact_id,
                workspace=str(workspace) if workspace is not None else None,
                identity=identity,
                claimed_saved_allow_hash=claimed_saved_allow_hash,
                claimed_approval_request_id=claimed_approval_request_id,
                claim_saved_approval=claim_saved_approval,
                now=datetime.now(tz=timezone.utc).isoformat(),
            )
            is True
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return False
