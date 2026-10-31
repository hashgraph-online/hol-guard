"""Thin transport to native review wire binding checks; no adapter-side decisions."""

from __future__ import annotations

from collections.abc import Mapping

from ..native_context import _resolve_digest_home, native_context_digest


def valid_bound_bash_review(
    prepared: Mapping[str, object],
    *,
    harness: str,
    exact_token: object,
    review_binding: object,
    decision: Mapping[str, object],
    native_receipt: object,
) -> bool:
    result = native_context_digest(
        "native_bash_reply_validation",
        {
            "reply_kind": "review",
            "material": dict(prepared),
            "request": {
                "harness": harness,
                "exact_token": exact_token,
                "review_binding": review_binding,
                "decision": dict(decision),
                "native_receipt": native_receipt,
            },
        },
        guard_home=_resolve_digest_home(None),
    )
    return isinstance(result, dict) and result.get("native_bash_reply_valid") is True
