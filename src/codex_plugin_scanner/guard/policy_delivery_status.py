"""What policy is Live on this device and has Guard Cloud's latest version reached it.

``policy status`` combines what the device already knows (the cached bundle, its acknowledgement and any
rejection reason) with one authenticated read of ``/api/guard/policy/delivery``. The remote read is best
effort: offline, signed out or an older Cloud simply leaves ``delivery`` unavailable and never fails.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
from typing import Final

from .policy_decision_explain import ACTIVE_POLICY_ERRORS, active_policy_document
from .policy_document import policy_document_digest
from .store import GuardStore
from .synced_policy import synced_policy_bundle_validation

DELIVERY_PATH: Final = "/api/guard/policy/delivery"
MAX_DEVICES: Final = 500
_DEVICE_STATES: Final = frozenset({"applied", "pending", "rejected"})


def _text(value: object, limit: int = 200) -> str | None:
    return value.strip()[:limit] if isinstance(value, str) and value.strip() else None


def _version_text(value: object) -> str | None:
    """A bundle version as text: legacy bundles carry a string, version-two bundles an integer."""

    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return _text(value)


def normalized_policy_delivery_url(sync_url: str) -> str:
    """Map the receipts sync URL onto the Cloud policy delivery route on the same host."""

    parsed = urllib.parse.urlsplit(sync_url)
    prefix = parsed.path.rstrip("/")
    for suffix in ("/registry/api/v1/guard/receipts/sync", "/api/guard/receipts/sync"):
        if prefix == suffix:
            path = suffix.replace("/receipts/sync", "/policy/delivery")
            return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, DELIVERY_PATH, parsed.query, ""))


def _local_policy(store: GuardStore) -> dict[str, object] | None:
    """The policy installed on this device (imported file or synced rules), apart from Cloud bundle metadata."""

    try:
        document = active_policy_document(store)
    except ACTIVE_POLICY_ERRORS:
        return None
    if not document.rules:
        return None
    return {
        "documentId": document.metadata.id,
        "digest": policy_document_digest(document),
        "rules": len(document.rules),
    }


def local_policy_status(store: GuardStore) -> dict[str, object]:
    """The Live version, mode, last sync, last acknowledgement and rejection reason known on this device."""

    cached = store.get_sync_payload("policy_bundle")
    bundle = cached if isinstance(cached, dict) else {}
    validated, rejection = synced_policy_bundle_validation(store)
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    ack = acknowledgement if isinstance(acknowledgement, dict) else {}
    summary = store.get_sync_payload("sync_summary")
    last_error = store.get_sync_payload("policy_bundle_last_error")
    defaults = validated.get("policyDefaults") if validated is not None else None
    mode = _text(defaults.get("mode")) if isinstance(defaults, dict) else None
    stored_error = last_error if isinstance(last_error, dict) else {}
    stored_reason = _text(stored_error.get("reason"))
    reason = rejection or stored_reason
    # The remediation and the rule that caused it describe the stored
    # rejection, so they are reported only while that is the reason shown.
    stored_shown = reason is not None and reason == stored_reason
    message = _text(stored_error.get("message"), 512) if stored_shown else None
    rule_id = _text(stored_error.get("ruleId"), 128) if stored_shown else None
    live_version = _version_text(bundle.get("bundleVersion"))
    ack_version = _version_text(ack.get("bundleVersion"))
    ack_status = _text(ack.get("status"))
    return {
        "local": _local_policy(store),
        "live": {
            "version": live_version,
            "bundleHash": _text(bundle.get("bundleHash")),
            "mode": mode,
            "rolloutState": _text(bundle.get("rolloutState")),
            "enforced": validated is not None,
        },
        "lastSync": _text(summary.get("synced_at") if isinstance(summary, dict) else None),
        "lastAck": {
            "status": ack_status,
            "appliedAt": _text(ack.get("appliedAt")) or _text(ack.get("observedAt")),
            "version": ack_version,
            "currentVersion": live_version is not None and ack_version == live_version,
        },
        "rejectionReason": reason,
        "rejectionRuleId": rule_id,
        "rejectionMessage": message,
    }


def _bounded_devices(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    devices: list[dict[str, object]] = []
    for item in value[:MAX_DEVICES]:
        if not isinstance(item, dict):
            continue
        state = _text(item.get("state"), 32)
        devices.append(
            {
                "id": _text(item.get("id"), 128),
                "name": _text(item.get("name"), 128),
                "state": state if state in _DEVICE_STATES else "pending",
                "reason": _text(item.get("reason")),
            }
        )
    return devices


def fetch_policy_delivery(store: GuardStore) -> dict[str, object]:
    """Read ``/api/guard/policy/delivery``; return ``{"available": False, "reason": ...}`` on any failure."""

    from .runtime.runner import (
        GuardSyncAuthorizationExpiredError,
        GuardSyncNotConfiguredError,
        _guard_sync_request,
        _resolve_guard_sync_auth_context,
        _urlopen_json_with_timeout_retry,
    )

    try:
        auth_context = _resolve_guard_sync_auth_context(store)
        request_url = normalized_policy_delivery_url(str(auth_context["sync_url"]))
        request = _guard_sync_request(
            auth_context, request_url=request_url, method="GET", data=None, extra_headers=None
        )
        response = _urlopen_json_with_timeout_retry(request=request, timeout_seconds=15, retry_timeout_seconds=20)
    except (GuardSyncNotConfiguredError, GuardSyncAuthorizationExpiredError):
        return {"available": False, "reason": "not_signed_in"}
    except urllib.error.HTTPError as error:
        return {"available": False, "reason": "not_supported" if error.code == 404 else f"http_{error.code}"}
    except (OSError, ValueError, KeyError):
        return {"available": False, "reason": "unreachable"}
    except RuntimeError:
        # A non-object response, a rate-limited refresh or an unavailable sync: status still prints.
        return {"available": False, "reason": "unavailable"}
    if not isinstance(response, dict):
        return {"available": False, "reason": "invalid_response"}
    version = response.get("versionNumber")
    metadata = store.get_device_metadata()
    installation_id = metadata.get("installation_id") if isinstance(metadata, dict) else None
    devices = _bounded_devices(response.get("devices"))
    this_device = next((device for device in devices if device["id"] == installation_id), None)
    return {
        "available": True,
        "versionNumber": version if isinstance(version, int) and not isinstance(version, bool) else None,
        "devices": devices,
        "thisDevice": this_device,
    }


def policy_status_payload(store: GuardStore, *, offline: bool) -> dict[str, object]:
    payload = local_policy_status(store)
    payload["delivery"] = {"available": False, "reason": "offline"} if offline else fetch_policy_delivery(store)
    return payload


def format_policy_status(payload: dict[str, object]) -> str:
    live = payload["live"] if isinstance(payload["live"], dict) else {}
    ack = payload["lastAck"] if isinstance(payload["lastAck"], dict) else {}
    delivery = payload["delivery"] if isinstance(payload["delivery"], dict) else {}
    local_value = payload.get("local")
    local = local_value if isinstance(local_value, dict) else None
    lines = [
        f"Local policy: {local['documentId']} ({local['rules']} rules)" if local else "Local policy: none",
        f"Live version: {live.get('version') or 'none'}",
        f"Mode: {live.get('mode') or 'unknown'}",
        f"Last sync: {payload.get('lastSync') or 'never'}",
        f"Last ACK: {ack.get('status') or 'none'}"
        + (f" at {ack['appliedAt']}" if ack.get("appliedAt") else "")
        + ("" if ack.get("currentVersion") or not ack.get("status") else " (older version)"),
        f"Rejection: {payload.get('rejectionReason') or 'none'}"
        + (f" (rule {payload['rejectionRuleId']})" if payload.get("rejectionRuleId") else ""),
    ]
    if payload.get("rejectionMessage"):
        lines.append(f"  {payload['rejectionMessage']}")
    if delivery.get("available"):
        raw_devices = delivery.get("devices")
        devices = raw_devices if isinstance(raw_devices, list) else []
        counts = {
            state: sum(1 for item in devices if isinstance(item, dict) and item.get("state") == state)
            for state in sorted(_DEVICE_STATES)
        }
        lines.append(
            f"Cloud version {delivery.get('versionNumber')}: "
            + ", ".join(f"{count} {state}" for state, count in counts.items())
        )
        mine = delivery.get("thisDevice")
        if isinstance(mine, dict):
            lines.append(f"This device: {mine.get('state')}" + (f" ({mine['reason']})" if mine.get("reason") else ""))
    else:
        lines.append(f"Cloud delivery: unavailable ({delivery.get('reason')})")
    return "\n".join(lines)


__all__ = [
    "DELIVERY_PATH",
    "fetch_policy_delivery",
    "format_policy_status",
    "local_policy_status",
    "normalized_policy_delivery_url",
    "policy_status_payload",
]
