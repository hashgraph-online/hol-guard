"""``hol-guard cloud status``: what this machine reports and what Guard Cloud shows."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
from collections.abc import Callable, Mapping
from typing import Any

from ..config import GuardConfig
from ..runtime.fleet_posture import (
    fleet_posture_managed,
    fleet_posture_opted_out,
    full_inventory_requested,
    last_sent_fleet_posture,
)
from ..store import GuardStore

MACHINE_SELF_PATH = "/api/guard/v1/fleet/machines/self"
_SELF_TIMEOUT_SECONDS = 8


def _last_sync_at(store: GuardStore) -> str | None:
    summary = store.get_sync_payload("sync_summary")
    if isinstance(summary, dict) and isinstance(summary.get("synced_at"), str):
        return str(summary["synced_at"])
    cursor = store.get_sync_payload("receipt_sync_cursor")
    if isinstance(cursor, dict) and isinstance(cursor.get("synced_at"), str):
        return str(cursor["synced_at"])
    return None


def _section(parent: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    return value if isinstance(value, dict) else {}


def _last_sent_summary(store: GuardStore) -> dict[str, object] | None:
    last = last_sent_fleet_posture(store)
    if last is None:
        return None
    summary = _section(last, "summary")
    tools = _section(last, "tools")
    client = _section(summary, "client")
    policy = _section(summary, "policy")
    return {
        "sent_at": last.get("sentAt"),
        "inventory_mode": last.get("mode"),
        "inventory_digest": last.get("inventoryDigest"),
        "inventory_items_tracked": last.get("inventoryItemsTracked"),
        "payload_bytes": last.get("payloadBytes"),
        "client_version": client.get("version"),
        "tools": dict(sorted((str(key), str(value)) for key, value in tools.items())),
        "policy_status": policy.get("status"),
        "policy_bundle_version": policy.get("appliedBundleVersion"),
    }


def _machine_self_url(sync_url: str) -> str:
    parts = urllib.parse.urlsplit(sync_url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, MACHINE_SELF_PATH, "", ""))


def fetch_cloud_machine_view(store: GuardStore) -> dict[str, object]:
    """Ask Guard Cloud what it currently shows for this machine.

    Never raises. Offline, signed-out and older Guard Cloud deployments return a
    status the caller prints as a plain message.
    """

    from ..runtime import runner

    try:
        auth_context = runner._resolve_guard_sync_auth_context(store)
        request_url = _machine_self_url(runner._validate_guard_sync_url(runner._auth_context_sync_url(auth_context)))
    except Exception as error:
        return {
            "status": "not_connected",
            "message": "Not signed in to Guard Cloud. Run `hol-guard connect` to pair this machine.",
            "detail": type(error).__name__,
        }
    try:
        request = runner._guard_sync_request(auth_context, request_url=request_url, method="GET")
        machine = runner._urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_SELF_TIMEOUT_SECONDS,
            retry_timeout_seconds=_SELF_TIMEOUT_SECONDS,
        )
    except urllib.error.HTTPError as error:
        if error.code in {404, 405, 501}:
            return {
                "status": "not_supported",
                "message": "Guard Cloud does not show fleet machine status for this workspace yet.",
            }
        return {"status": "unavailable", "message": f"Guard Cloud answered HTTP {error.code}."}
    except (OSError, RuntimeError, ValueError) as error:
        return {
            "status": "offline",
            "message": "Could not reach Guard Cloud. The local summary above is still accurate.",
            "detail": type(error).__name__,
        }
    if not isinstance(machine, dict):
        return {"status": "unavailable", "message": "Guard Cloud returned an unexpected response."}
    return {"status": "ok", "machine": machine}


def build_cloud_status_payload(
    store: GuardStore,
    *,
    guard_config: GuardConfig | None,
    now: str,
    fetch_cloud: bool = True,
    cloud_fetcher: Callable[[GuardStore], dict[str, object]] | None = None,
) -> dict[str, object]:
    managed = fleet_posture_managed(guard_config)
    opted_out = fleet_posture_opted_out(store)
    payload: dict[str, object] = {
        "generated_at": now,
        "last_sync_at": _last_sync_at(store),
        "fleet_posture": {
            "reporting": "minimal" if opted_out and not managed else "full",
            "managed": managed,
            "opt_out_ignored": bool(opted_out and managed),
            "full_inventory_requested": full_inventory_requested(store),
            "last_sent": _last_sent_summary(store),
        },
    }
    if fetch_cloud:
        payload["cloud_sees"] = (cloud_fetcher or fetch_cloud_machine_view)(store)
    return payload


def _machine_lines(machine: Mapping[str, object]) -> list[str]:
    lines: list[str] = []
    for label, key in (
        ("Guard version", "guardVersion"),
        ("OS", "os"),
        ("Last seen", "lastSeenAt"),
        ("Policy", "policyStatus"),
        ("Inventory digest", "inventoryDigest"),
    ):
        value = machine.get(key)
        if value not in (None, ""):
            lines.append(f"  {label}: {value}")
    tools = machine.get("aiTools")
    if isinstance(tools, list):
        for tool in tools:
            if isinstance(tool, Mapping):
                lines.append(f"  {tool.get('harness')}: {tool.get('protectionState')}")
    if not lines:
        lines.append("  " + json.dumps(machine, sort_keys=True)[:400])
    return lines


def render_cloud_status_text(payload: Mapping[str, object]) -> str:
    posture = payload.get("fleet_posture")
    posture = posture if isinstance(posture, Mapping) else {}
    last_sent = posture.get("last_sent")
    lines = [f"Last sync: {payload.get('last_sync_at') or 'never'}"]
    detail = posture.get("reporting")
    suffix = " (managed install, cannot be turned off)" if posture.get("managed") else ""
    lines.append(f"Fleet posture reporting: {detail}{suffix}")
    if posture.get("full_inventory_requested"):
        lines.append("Full inventory: queued for the next sync")
    if isinstance(last_sent, Mapping):
        lines.append(
            f"Last sent: {last_sent.get('sent_at')} ({last_sent.get('inventory_mode')} inventory, "
            f"{last_sent.get('payload_bytes')} bytes)"
        )
        tools = last_sent.get("tools")
        if isinstance(tools, Mapping):
            for harness, state in tools.items():
                lines.append(f"  {harness}: {state}")
        lines.append(
            f"  policy: {last_sent.get('policy_status')} (bundle {last_sent.get('policy_bundle_version') or 'none'})"
        )
    else:
        lines.append("Last sent: nothing yet. Run `hol-guard sync` after connecting.")
    sees = payload.get("cloud_sees")
    if isinstance(sees, Mapping):
        lines.append("Cloud sees:")
        machine = sees.get("machine")
        if sees.get("status") == "ok" and isinstance(machine, Mapping):
            lines.extend(_machine_lines(machine))
        else:
            lines.append(f"  {sees.get('message')}")
    return "\n".join(lines)
