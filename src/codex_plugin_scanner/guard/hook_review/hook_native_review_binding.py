"""Bind ordinary local review reuse to its verified native policy domain."""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import overload

from ..native_hook_review_binding import native_hook_review_policy_binding


def native_review_policy_binding(
    *,
    harness: str,
    native_result: Mapping[str, object],
    verified_receipt: object,
    guard_home: Path,
    deadline: float | None = None,
) -> dict[str, object] | None:
    """Capture only a typed native receipt; request payload metadata is not authority.

    Absence on both native surfaces retains the legacy contract. A partially
    present or inconsistent command domain cannot create an unbound approval.
    Receipt persistence is asynchronous and does not participate in this check.
    """

    receipt_bound = isinstance(verified_receipt, Mapping) and "command_extensions" in verified_receipt
    if "command_extensions" not in native_result and not receipt_bound:
        return None
    binding = native_hook_review_policy_binding(
        harness=harness,
        native_result=native_result,
        verified_receipt=verified_receipt if isinstance(verified_receipt, Mapping) else None,
        guard_home=guard_home,
        deadline=deadline,
    )
    if binding is None:
        raise ValueError("native_review_policy_binding_invalid")
    return binding


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
    claimed_saved_allow_hash: str | None = None,
    claimed_approval_request_id: str | None = None,
) -> str | None:
    """Settle a retry in one resident transaction.

    ``"blocked"`` when the user chose Keep blocked for it, ``"allowed"`` when
    ``spend`` spent an approve-once, else ``None``. A retry that names the
    once-approval it was granted (``claimed_saved_allow_hash``) settles that
    MAC'd allow between the two in the same call; the resident owns the
    identity check, the exact peek, the spend and the exact Cloud fallback.
    No answer means no allow.
    """

    claimed = claimed_saved_allow_hash is not None
    method = "settle_claimed_native_review" if claimed else "settle_native_review_reuse"
    settle = getattr(store, method, None)
    if not callable(settle) or identity is None or not (launch_target or claimed):
        return None
    identity_args: dict[str, object] = {
        "harness": harness,
        "artifact_id": artifact_id,
        "artifact_name": tool_name,
        "launch_target": launch_target,
        "workspace": str(workspace) if workspace is not None else None,
        "now": datetime.now(tz=timezone.utc).isoformat(),
    }
    if claimed:
        identity_args.update(
            identity=identity,
            claimed_saved_allow_hash=claimed_saved_allow_hash,
            claimed_approval_request_id=claimed_approval_request_id,
            claim_saved_approval=spend,
        )
    else:
        identity_args.update(artifact_hash=identity, spend=spend)
    try:
        settled = settle(**identity_args)
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return None
    return settled if settled in ("blocked", "allowed") else None


@overload
def admit_accepted_call(
    store: object, *, harness: str, payload: Mapping[str, object], response: dict[str, object]
) -> dict[str, object]: ...


@overload
def admit_accepted_call(
    store: object, *, harness: str, payload: Mapping[str, object], response: dict[str, object] | None
) -> dict[str, object] | None: ...


def admit_accepted_call(
    store: object, *, harness: str, payload: Mapping[str, object], response: dict[str, object] | None
) -> dict[str, object] | None:
    """Record the approval witness for a call let through on the user's answer.

    The call's ``PostToolUse`` reads it back so the policy floor that sent the
    call to review does not withhold the output of what the user approved. The
    resident owns the witness key. A failed write only leaves that floor in
    place, so it never blocks the approved call itself.
    """

    if response is None or response.get("approval_reuse_status") != "accepted":
        return response
    record = getattr(store, "record_native_admitted_call", None)
    if callable(record):
        with contextlib.suppress(OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
            record(harness=harness, payload=dict(payload), now=datetime.now(tz=timezone.utc).isoformat())
    return response
