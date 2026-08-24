from __future__ import annotations

import hmac

_DOMAIN = b"hol-guard-review-event-integrity-v1"


def review_event_payload_digest(
    payload_json: str,
    *,
    oauth_source: object,
    oauth_subject_hash: object,
    workspace_id: object,
    machine_id: object,
    machine_installation_id: object,
) -> str:
    binding = "\0".join(
        str(value) if value is not None else ""
        for value in (oauth_source, oauth_subject_hash, workspace_id, machine_id, machine_installation_id)
    ).encode("utf-8")
    return hmac.digest(_DOMAIN + b"\0" + binding, payload_json.encode("utf-8"), "sha256").hex()
