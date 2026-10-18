"""Live "set up this connector" recommendation for one pending approval request.

A review held only because Guard does not know the connector it launches
records a connector hint at queue time. This module re-checks that hint on
every read against the stored connector (still ``unset``, same identity), the
extension-control authority and the approval gate, so the Inbox never offers a
setup that no longer applies. It is read-only: setting the connector up still
goes through the local-CLI preview, one-use proof and apply flow.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable, Mapping
from urllib.parse import urlencode

from ..runtime.connector_setup_items import listed_public_items
from ..runtime.extension_allow_hint import validated_connector_setup_hint
from ..runtime.extension_control_authority import AuthorityHealth
from ..runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from .approval_extension_recommendation import CAUTION_RISK_CLASSES

CONNECTOR_RECOMMENDATION_SCHEMA = "guard.approval-connector-recommendation.v1"
# Pending rows read per page, and the most the group scan reads in total. A
# scan that stops early is cautioned: unread rows are never treated as safe.
_GROUP_PAGE_ROWS = 200
_MAX_GROUP_SCAN_ROWS = 2000

_LOGGER = logging.getLogger(__name__)


def _strings(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _stored_connector(store: object, cli_id: str, identity_hash: str) -> Mapping[str, object] | None:
    for item in listed_public_items(store):  # pyright: ignore[reportArgumentType]
        if item.get("cli_id") == cli_id:
            return item if item.get("identity_hash") == identity_hash else None
    return None


def pending_connector_group_rows(store: object, identity_hash: str) -> tuple[list[Mapping[str, object]], bool]:
    """Pending rows queued on this connector identity, paging through the whole queue.

    The queue cannot filter by group, so other groups' rows are skipped page by
    page. Returns the rows and whether every pending row was read; the scan
    stops after ``_MAX_GROUP_SCAN_ROWS`` rows.
    """

    pager = getattr(store, "list_approval_request_page", None)
    if not callable(pager):
        return [], False
    prefix = f"connector:{identity_hash}:"
    rows: list[Mapping[str, object]] = []
    cursor: str | None = None
    scanned = 0
    while scanned < _MAX_GROUP_SCAN_ROWS:
        page = pager(status="pending", limit=_GROUP_PAGE_ROWS, cursor=cursor, include_totals=False)
        if not isinstance(page, Mapping):
            return rows, False
        items = page.get("items")
        if not isinstance(items, list):
            return rows, False
        scanned += len(items)
        for row in items:
            if isinstance(row, Mapping) and str(row.get("queue_group_id") or "").startswith(prefix):
                rows.append(row)
        next_cursor = page.get("next_cursor")
        if not items or not isinstance(next_cursor, str) or not next_cursor:
            return rows, True
        cursor = next_cursor
    return rows, False


def _group_risk_classes(
    store: object,
    identity_hash: str,
    current: list[str],
    read_hint: Callable[[str], object],
) -> tuple[set[str], bool]:
    classes = set(current)
    rows, complete = pending_connector_group_rows(store, identity_hash)
    for row in rows:
        hint = validated_connector_setup_hint(read_hint(str(row.get("request_id", ""))))
        if hint is not None and hint["identity_hash"] == identity_hash:
            classes.update(_strings(hint["risk_classes"]))
    return classes, complete


def _setup_request(
    item: Mapping[str, object], approval: Mapping[str, object], cli_id: str, identity_hash: str
) -> dict[str, object]:
    body: dict[str, object] = {
        "cli_id": cli_id,
        "identity_hash": identity_hash,
        "name": item.get("name"),
        "kind": item.get("kind"),
        "state": "allowed",
        "connector_group_request_id": approval.get("request_id"),
    }
    for key in ("example_label", "interpreter_name"):
        if isinstance(item.get(key), str):
            body[key] = item[key]
    return body


def build_approval_connector_recommendation(
    approval: Mapping[str, object],
    *,
    store: object,
    snapshot: ExtensionControlRuntimeSnapshot,
    approval_gate_configured: bool,
) -> dict[str, object] | None:
    """Return the setup recommendation for a pending request, or None when it no longer applies."""

    if approval.get("status") != "pending":
        return None
    hint = validated_connector_setup_hint(approval.get("extension_allow_hint"))
    if hint is None:
        return None
    identity_hash, cli_id = str(hint["identity_hash"]), str(hint["cli_id"])
    if not str(approval.get("queue_group_id") or "").startswith(f"connector:{identity_hash}:"):
        return None
    if any(layer.global_lockdown for layer in snapshot.layers):
        return None
    item = _stored_connector(store, cli_id, identity_hash)
    # Only a connector this device still has no decision for is a setup.
    if item is None or item.get("state") != "unset":
        return None
    surface = item.get("surface")
    if surface != hint["surface"]:
        return None
    reader = getattr(store, "get_approval_extension_allow_hint", None)
    risk_classes, scanned_all = _group_risk_classes(
        store,
        identity_hash,
        _strings(hint["risk_classes"]),
        reader if callable(reader) else (lambda _request_id: None),
    )
    caution_classes = sorted(risk_classes & CAUTION_RISK_CLASSES)
    if snapshot.health is not AuthorityHealth.PROTECTED:
        status = "authority_unavailable"
    elif not approval_gate_configured:
        status = "approval_gate_required"
    else:
        status = "available"
    setup_query = urlencode({"setup": approval.get("request_id"), "identity": identity_hash})
    return {
        "schema": CONNECTOR_RECOMMENDATION_SCHEMA,
        "status": status,
        "identity_hash": identity_hash,
        "cli_id": cli_id,
        "surface": surface,
        "display_name": hint["display_name"],
        "deep_link": hint["deep_link"],
        # Protect page opened on this request; the page re-checks the identity.
        "setup_href": f"{hint['deep_link']}?{setup_query}",
        # Recomputed from the stored connector, never trusted from the queue time.
        "card_recommendation": {"state": "allowed", "capabilities": []},
        # Pre-filled body for the same local-CLI preview/apply endpoint as
        # Protect; the dashboard adds the revision, credentials and nonce.
        "setup_request": _setup_request(item, approval, cli_id, identity_hash),
        "approval_gate_configured": approval_gate_configured,
        "caution": bool(caution_classes) or not scanned_all,
        "caution_risk_classes": caution_classes,
        "revision": snapshot.revision,
    }


def safe_connector_recommendation(
    approval: Mapping[str, object],
    *,
    store: object,
    snapshot: ExtensionControlRuntimeSnapshot,
    approval_gate_configured: Callable[[], bool],
) -> dict[str, object] | None:
    """The recommendation, or None when any input cannot be read; never fails the approval read."""

    if validated_connector_setup_hint(approval.get("extension_allow_hint")) is None:
        return None
    try:
        return build_approval_connector_recommendation(
            approval, store=store, snapshot=snapshot, approval_gate_configured=approval_gate_configured()
        )
    except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        _LOGGER.warning("Connector recommendation unavailable (%s)", type(error).__name__)
        return None


__all__ = [
    "CONNECTOR_RECOMMENDATION_SCHEMA",
    "build_approval_connector_recommendation",
    "pending_connector_group_rows",
    "safe_connector_recommendation",
]
