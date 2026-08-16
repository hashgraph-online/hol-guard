"""Tool implementations for guard-mcp.v1 local MCP server.

Each tool returns a JSON-serialized response containing the required
contract fields: contractVersion, source, generatedAt, freshness.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .adapters import fetch_inventory, fetch_receipt, get_status, search_inventory, search_receipts
from .sanitizers import sanitize_fetch_result, sanitize_search_result, sanitize_status_result
from .schemas import CONTRACT_VERSION, MAX_FETCH_TEXT_BYTES, MAX_SEARCH_LIMIT, SOURCE_LOCAL

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.store import GuardStore


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _envelope(extra: dict[str, object]) -> str:
    payload: dict[str, object] = {
        "contractVersion": CONTRACT_VERSION,
        "source": SOURCE_LOCAL,
        "generatedAt": _now_iso(),
        "freshness": "real-time",
    }
    payload.update(extra)
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def execute_search(store: GuardStore, query: str) -> str:
    receipt_results = search_receipts(store, query, limit=MAX_SEARCH_LIMIT)
    inventory_results = search_inventory(store, query, limit=MAX_SEARCH_LIMIT)
    all_results = (receipt_results + inventory_results)[:MAX_SEARCH_LIMIT]
    sanitized = [sanitize_search_result(r) for r in all_results]
    return _envelope(
        {
            "results": sanitized,
            "count": len(sanitized),
        }
    )


def execute_fetch(store: GuardStore, item_id: str) -> str:
    result: dict[str, object] | None = None
    if item_id.startswith("receipt:"):
        result = fetch_receipt(store, item_id)
    elif item_id.startswith(("inventory:", "artifact:", "device:")):
        result = fetch_inventory(store, item_id)
    if result is None:
        return _envelope(
            {
                "found": False,
                "id": _sanitize_id_echo(item_id),
                "text": None,
            }
        )
    sanitized = sanitize_fetch_result(result)
    text_bytes = str(sanitized.get("text", "")).encode("utf-8")
    if len(text_bytes) > MAX_FETCH_TEXT_BYTES:
        sanitized["text"] = text_bytes[:MAX_FETCH_TEXT_BYTES].decode("utf-8", errors="ignore")
        sanitized["truncated"] = True
    return _envelope(
        {
            "found": True,
            **sanitized,
        }
    )


def execute_get_guard_status(store: GuardStore) -> str:
    raw = get_status(store)
    sanitized = sanitize_status_result(raw)
    policy_authoring = _policy_authoring_status(store)
    return _envelope(
        {
            **sanitized,
            **policy_authoring,
        }
    )


def _policy_authoring_status(store: GuardStore) -> dict[str, object]:
    """Additive policy authoring availability fields.

    These are purely informational and do not change existing status
    semantics.  They tell MCP clients whether validate_policy /
    create_policy / get_policy_creation are available and whether writes
    are enabled.
    """
    import os

    from .policy_store import MCPolicyRequestRepository

    policy_import_enabled = os.environ.get("HOL_GUARD_POLICY_YAML_IMPORT") == "1"
    mcp_policy_write_enabled = os.environ.get("HOL_GUARD_MCP_POLICY_WRITE") == "1"
    policy_authoring_available = policy_import_enabled
    policy_write_enabled = policy_import_enabled and mcp_policy_write_enabled

    pending_count = 0
    try:
        repo = MCPolicyRequestRepository(store)
        pending = repo.list_pending_requests()
        pending_count = len(pending)
    except Exception:
        pending_count = 0

    return {
        "policyAuthoringAvailable": policy_authoring_available,
        "policyWriteEnabled": policy_write_enabled,
        "policySchemaVersion": "1.0",
        "pendingPolicyRequests": pending_count,
    }


def _sanitize_id_echo(raw_id: str) -> str:
    """Sanitize a caller-supplied ID for safe echo in not-found responses."""
    import re

    return re.sub(r"[^a-zA-Z0-9:_-]", "", raw_id)[:256]
