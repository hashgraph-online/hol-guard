from __future__ import annotations

MAX_OUTBOX_ITEMS = 256
MAX_DEAD_LETTERS = 64
TRANSIENT_STATUSES = {408, 425, 429, 500, 502, 503, 504, 599}
PERMANENT_STATUSES = {400, 404, 405, 413, 415, 422}
PROVEN_DUPLICATE_CODES = {
    "ack_duplicate",
    "health_duplicate",
    "remediation_result_duplicate",
}


def response_error_code(payload: object | None) -> str:
    if isinstance(payload, dict) and isinstance(payload.get("error"), str):
        return payload["error"]
    return "unknown_error"
