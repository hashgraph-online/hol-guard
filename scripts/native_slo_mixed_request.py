"""Keep private fixture attempt labels separate from opaque harness IDs."""

from __future__ import annotations

import re
from collections.abc import Mapping
from uuid import uuid4

from scripts.native_slo_adapter import payload

_ATTEMPT = re.compile(r"^mixed-(?:load|policy|recovery)-[0-9]{1,6}$")
_NATIVE_FIELDS = {"claude-code": "tool_use_id", "codex": "tool_call_id"}


def attempt_label(value: object) -> str | None:
    return value if isinstance(value, str) and _ATTEMPT.fullmatch(value) is not None else None


def request_attempt(request: object) -> str | None:
    if not isinstance(request, Mapping):
        return None
    return attempt_label(request.get("native_slo_attempt"))


def fixture_request(
    harness: str,
    event: str,
    size_class: str = "1k",
    *,
    attempt: str,
    request_payload: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if harness not in _NATIVE_FIELDS or attempt_label(attempt) is None:
        raise ValueError("mixed fixture request identity outside declared scope")
    return {
        **(payload(event, size_class) if request_payload is None else request_payload),
        "native_slo_attempt": attempt,
        # Each harness receives its real native field and fresh randomness.
        # A readable counter belongs only to diagnostic joins, never to the
        # production strong-identifier input or a fabricated receipt.
        _NATIVE_FIELDS[harness]: f"fixture-{uuid4().hex}",
    }
