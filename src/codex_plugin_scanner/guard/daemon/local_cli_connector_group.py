"""Resolve the approval rows held on one connector after it is set up.

This runs only after the local-CLI apply has passed its one-use proof and saved
``allowed``. It never writes a grant. The held rows go through the existing
bulk allow-once path, so the approval gate is checked again and the resident's
bulk eligibility verdict still applies: a row it rejects (a secret read, a
catastrophic hint) stays pending for a normal decision. Rows are resolved, not
deleted, so the group keeps its evidence.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Mapping

from ..approval_gate_types import ApprovalGateError, ApprovalGateInput
from ..runtime.extension_allow_hint import validated_connector_setup_hint
from ..store import GuardStore
from .approval_connector_recommendation import pending_connector_group_rows
from .local_cli_api_contract import LocalCliApiError

_MAX_REQUEST_ID = 128

_LOGGER = logging.getLogger(__name__)


def connector_group_request_id(payload: Mapping[str, object], state: str) -> str | None:
    """The held request a setup was started from; checked before any proof is spent."""

    raw = payload.get("connector_group_request_id")
    if raw is None:
        return None
    text = raw.strip() if isinstance(raw, str) else ""
    if not 0 < len(text) <= _MAX_REQUEST_ID or not text.isprintable():
        raise LocalCliApiError(400, "invalid_connector_group_request_id")
    if state != "allowed":
        raise LocalCliApiError(400, "connector_group_requires_allowed")
    return text


def _connector_row(store: GuardStore, row: Mapping[str, object], *, cli_id: str, identity_hash: str) -> bool:
    """A pending row queued on this connector whose stored hint names the same connector."""

    if row.get("status") not in (None, "pending"):
        return False
    if not str(row.get("queue_group_id") or "").startswith(f"connector:{identity_hash}:"):
        return False
    hint = validated_connector_setup_hint(store.get_approval_extension_allow_hint(str(row.get("request_id") or "")))
    # The group id alone is not enough: the row must name this connector too.
    return hint is not None and hint["identity_hash"] == identity_hash and hint["cli_id"] == cli_id


def connector_group_request_ids(
    store: GuardStore, *, cli_id: str, identity_hash: str, request_id: str | None = None
) -> list[str]:
    """Pending rows queued on this exact connector identity, read across the whole pending queue.

    ``request_id`` (the row the setup started from) is checked directly, so a
    long queue can never hide it.
    """

    rows, _complete = pending_connector_group_rows(store, identity_hash)
    ids = [
        str(row.get("request_id"))
        for row in rows
        if _connector_row(store, row, cli_id=cli_id, identity_hash=identity_hash)
    ]
    if request_id is not None and request_id not in ids:
        origin = store.get_approval_request(request_id) or {}
        if origin.get("status") == "pending" and _connector_row(
            store, origin, cli_id=cli_id, identity_hash=identity_hash
        ):
            ids.append(request_id)
    return ids


def _continuation(store: GuardStore, request_id: str, now: str) -> dict[str, object]:
    """Codex rows reuse the resume binding; every other harness gets the retry-hint text."""

    from ..cli.approval_commands import _build_retry_hint
    from .local_approval_continuation import apply_local_approval_continuation

    row = store.get_approval_request(request_id)
    harness = str(row.get("harness") or "") if isinstance(row, Mapping) else ""
    copy = _build_retry_hint("allow", harness)
    result: dict[str, object] = {"request_id": request_id, "harness": harness}
    try:
        updated, copy = apply_local_approval_continuation(
            store=store,
            updated={},
            request_id=request_id,
            action="allow",
            harness=harness,
            copy=copy,
            now=lambda: now,
        )
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        _LOGGER.warning("Connector continuation unavailable (%s)", type(error).__name__)
        updated = {}
    for key in ("codexResume", "harnessResume"):
        if isinstance(updated.get(key), dict):
            result[key] = updated[key]
    result["copy"] = copy
    result["retry_hint"] = copy["body"]
    return result


def resolve_connector_group(
    store: GuardStore,
    *,
    cli_id: str,
    identity_hash: str,
    request_id: str,
    approval_gate_input: ApprovalGateInput | None,
    now: str,
) -> dict[str, object]:
    """Approve once every eligible row of the connector's group; never raises."""

    from ..approvals import bulk_allow_read_only_once

    try:
        ids = connector_group_request_ids(store, cli_id=cli_id, identity_hash=identity_hash, request_id=request_id)
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        _LOGGER.warning("Connector group unavailable (%s)", type(error).__name__)
        return {"status": "failed", "error": "connector_group_unavailable", "resolved_count": 0, "failed": []}
    if request_id not in ids:
        # Only a setup started from a row of this group may resolve the group.
        return {"status": "not_in_group", "resolved_count": 0, "failed": []}
    try:
        outcome = bulk_allow_read_only_once(
            store=store, request_ids=ids, approval_gate_input=approval_gate_input, now=now
        )
    except ApprovalGateError as error:
        return {"status": "failed", "error": error.code, "resolved_count": 0, "failed": []}
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        return {"status": "failed", "error": str(error) or type(error).__name__, "resolved_count": 0, "failed": []}
    failed = outcome.get("failed")
    failed_ids = (
        {str(item.get("request_id")) for item in failed if isinstance(item, Mapping)}
        if isinstance(failed, list)
        else set()
    )
    resolved_count = outcome.get("resolved_count")
    result: dict[str, object] = {
        "status": "resolved" if not failed_ids and "error" not in outcome else "partial",
        "resolved_count": resolved_count if isinstance(resolved_count, int) else 0,
        "failed": failed if isinstance(failed, list) else [],
    }
    # Every row the bulk path approved continues its own agent; the response
    # carries the continuation of the row the setup started from.
    for resolved_id in [item for item in ids if item not in failed_ids] if result["resolved_count"] else []:
        continuation = _continuation(store, resolved_id, now)
        if resolved_id == request_id:
            result["continuation"] = continuation
    return result


__all__ = [
    "connector_group_request_id",
    "connector_group_request_ids",
    "resolve_connector_group",
]
