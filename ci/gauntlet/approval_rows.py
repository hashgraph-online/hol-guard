"""Summarize approval rows that ordinary work created, with the Always option they offer."""

from __future__ import annotations

from typing import Any

PERSISTENT_SCOPES = frozenset({"workspace", "harness", "global", "publisher", "artifact"})


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def approval_rows(store: Any, known_ids: set[str]) -> list[dict[str, Any]]:
    """Return redacted-by-construction facts for rows added during the run.

    Only the tool, reason and whether an Always option is offered are kept; commands and paths are
    already in the redacted tool evidence, so they are not copied again.
    """
    from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract

    rows = []
    for row in store.list_approval_requests(status=None, limit=200):
        if not isinstance(row, dict) or str(row.get("request_id") or "") in known_ids:
            continue
        contract = request_scope_contract(row)
        scopes = [str(scope) for scope in contract.allow_scopes]
        envelope = _mapping(row.get("action_envelope_json"))
        decision = _mapping(row.get("decision_v2_json"))
        rows.append(
            {
                "tool_name": str(envelope.get("tool_name") or row.get("tool_name") or ""),
                "reason_code": str(
                    _mapping(envelope.get("native_origin_receipt")).get("reason_code")
                    or decision.get("reason_code")
                    or row.get("reason_code")
                    or ""
                ),
                "exact_action_persistence_eligible": contract.exact_action_persistence_eligible is True,
                "allow_scopes": scopes,
                "always_available": contract.exact_action_persistence_eligible is True
                or any(scope in PERSISTENT_SCOPES for scope in scopes),
            }
        )
    return rows


def always_gap(rows: list[dict[str, Any]]) -> list[str]:
    """Name rows that a user could not turn into a lasting allow, a defect for read-only work."""
    return [str(row.get("tool_name") or "unknown") for row in rows if row.get("always_available") is not True]
