"""Local Guard state summaries for the approval-center dashboard."""

from __future__ import annotations

from datetime import datetime, timezone

from ..store import GuardStore

_PORTAL_LINKS = {
    "home": "https://hol.org/guard/dashboard",
    "inbox": "https://hol.org/guard/inbox",
    "fleet": "https://hol.org/guard/fleet",
}


def build_guard_local_state_payload(store: GuardStore, *, now: str) -> dict[str, object]:
    pending_approvals = store.count_approval_requests()
    receipt_count = store.count_receipts()
    sync_credentials = store.get_sync_credentials()
    latest_sync = store.get_sync_payload("latest_sync")
    latest_connect_state = store.get_latest_guard_connect_state(now=now)
    active_sessions = store.list_guard_sessions(limit=5)
    active_operations = store.list_guard_operations(limit=5)

    headline_state = _resolve_headline_state(
        pending_approvals=pending_approvals,
        receipt_count=receipt_count,
        sync_configured=sync_credentials is not None,
        latest_sync=latest_sync,
        latest_connect_state=latest_connect_state,
        active_sessions=active_sessions,
    )
    guidance = _build_guidance(
        headline_state=headline_state,
        pending_approvals=pending_approvals,
        latest_connect_state=latest_connect_state,
        sync_configured=sync_credentials is not None,
        latest_sync=latest_sync,
        active_sessions=active_sessions,
    )
    return {
        "headline_state": headline_state,
        "pending_approvals": pending_approvals,
        "receipt_count": receipt_count,
        "sync_configured": sync_credentials is not None,
        "latest_sync": latest_sync if isinstance(latest_sync, dict) else None,
        "latest_connect_state": latest_connect_state,
        "runtime": {
            "sessions": len(active_sessions),
            "operations": len(active_operations),
            "latest_session": active_sessions[0] if active_sessions else None,
            "latest_operation": active_operations[0] if active_operations else None,
        },
        "portal_links": _PORTAL_LINKS if sync_credentials is not None else {},
        "guidance": guidance,
        "updated_at": now,
    }


def _resolve_headline_state(
    *,
    pending_approvals: int,
    receipt_count: int,
    sync_configured: bool,
    latest_sync: object,
    latest_connect_state: dict[str, object] | None,
    active_sessions: list[dict[str, object]],
) -> str:
    if pending_approvals > 0:
        return "blocked"
    if latest_connect_state is not None and str(latest_connect_state.get("status")) == "retry_required":
        return "stale"
    if latest_connect_state is not None and str(latest_connect_state.get("status")) == "waiting":
        return "connected"
    if sync_configured and isinstance(latest_sync, dict):
        return "connected"
    if sync_configured:
        return "stale"
    if receipt_count == 0 and not active_sessions:
        return "setup"
    if receipt_count == 0:
        return "protected"
    return "local_only"


def _build_guidance(
    *,
    headline_state: str,
    pending_approvals: int,
    latest_connect_state: dict[str, object] | None,
    sync_configured: bool,
    latest_sync: object,
    active_sessions: list[dict[str, object]],
) -> dict[str, object]:
    if headline_state == "blocked":
        return {
            "title": "Blocked action needs review",
            "body": (
                f"Guard paused {pending_approvals} request"
                f"{'' if pending_approvals == 1 else 's'} on this machine. "
                "Review the current request, then return to the harness."
            ),
            "command": None,
            "primary_link": "/",
        }
    if headline_state == "connected":
        milestone = None if latest_connect_state is None else str(latest_connect_state.get("milestone") or "")
        if milestone == "first_sync_pending":
            body = (
                "This machine is paired to Guard Cloud. "
                "The first shared proof is still being written, so Fleet will update next."
            )
        elif milestone == "waiting_for_browser":
            body = (
                "Browser pairing is still open. Finish the connect flow in the browser, "
                "then Guard will send the first proof."
            )
        else:
            body = (
                "This machine is connected to Guard Cloud. Open Home, Inbox, or Fleet "
                "to continue from the shared control plane."
            )
        return {
            "title": "Connected to Guard Cloud",
            "body": body,
            "command": "hol-guard sync" if sync_configured and not isinstance(latest_sync, dict) else None,
            "primary_link": _PORTAL_LINKS["home"] if sync_configured else None,
        }
    if headline_state == "stale":
        return {
            "title": "Cloud sync needs attention",
            "body": (
                "Guard has cloud credentials, but the latest proof is stale or the first sync failed. "
                "Re-run sync, then reopen Fleet to verify coverage."
            ),
            "command": "hol-guard sync" if sync_configured else "hol-guard connect",
            "primary_link": _PORTAL_LINKS["fleet"] if sync_configured else None,
        }
    if headline_state == "setup":
        return {
            "title": "Protect the first harness run",
            "body": (
                "Guard is ready on this machine. Start a supported harness or run Guard once "
                "to create the first decision and proof record."
            ),
            "command": "hol-guard start",
            "primary_link": None,
        }
    if headline_state == "protected":
        return {
            "title": "Runtime health is waiting",
            "body": (
                "The approval center is attached and ready. When a harness run starts, "
                "Runtime health will show the live session and operation here."
            ),
            "command": None,
            "primary_link": None,
        }
    updated_at = _sync_timestamp(latest_sync)
    sync_copy = f" The latest shared proof landed at {updated_at}." if updated_at is not None else ""
    session_copy = " Guard is attached to an active harness session." if active_sessions else ""
    return {
        "title": "Local protection is active",
        "body": (
            "Recent decisions are saved on this machine, and Guard is ready to reuse them on the next launch."
            f"{sync_copy}{session_copy}"
        ),
        "command": "hol-guard connect" if not sync_configured else None,
        "primary_link": _PORTAL_LINKS["inbox"] if sync_configured else None,
    }


def _sync_timestamp(payload: object) -> str | None:
    if not isinstance(payload, dict):
        return None
    synced_at = payload.get("synced_at")
    if isinstance(synced_at, str) and synced_at.strip():
        return _humanize_timestamp(synced_at)
    return None


def _humanize_timestamp(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
