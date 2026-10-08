"""Distinguish safe inference transport recovery from replaying a tool."""

from __future__ import annotations

import re
from typing import Any


def reconcile_rounds(rounds: list[dict[str, Any]]) -> tuple[bool, int]:
    """Accept only completed rounds or identical, zero-byte HTTP retries.

    A failed partial stream cannot qualify. This function never retries a
    request and never excuses a repeated, blocked or failed host tool call.
    """
    if not rounds:
        return False, 0
    recovered = 0
    for index, row in enumerate(rounds):
        if row.get("status") == "completed":
            if (
                any(
                    not isinstance(row.get(key), str) or re.fullmatch(r"[0-9a-f]{64}", row[key]) is None
                    for key in ("request_sha256", "response_sha256")
                )
                or type(row.get("response_bytes")) is not int
                or row["response_bytes"] <= 0
                or not isinstance(row.get("response_models"), list)
                or not row["response_models"]
            ):
                return False, recovered
            continue
        status = row.get("http_status")
        if (
            row.get("status") != "provider-error"
            or row.get("error_type") != "HTTPError"
            or row.get("delivered_bytes") != 0
            or type(status) is not int
            or not (status == 429 or 500 <= status <= 599)
            or not isinstance(row.get("request_sha256"), str)
        ):
            return False, recovered
        same_request_completed = False
        for retry in rounds[index + 1 :]:
            if retry.get("request_sha256") != row["request_sha256"]:
                break
            if retry.get("status") == "completed":
                same_request_completed = True
                break
        if not same_request_completed:
            return False, recovered
        recovered += 1
    return True, recovered
