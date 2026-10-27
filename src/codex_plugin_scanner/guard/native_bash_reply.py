"""Thin transport to native Bash reply validation; no adapter-side decisions."""

from __future__ import annotations

from typing import cast

from .native_bash_protocol import NativeBashError
from .native_context import _resolve_digest_home, native_context_digest


def supported_execution_assurance(value: object) -> bool:
    return isinstance(value, str) and value in {
        "macos-readonly-root-framed-outputs-v1",
        "macos-readonly-root-http-read-v1",
        "macos-hardened-broker-v1",
    }


def validate_review_lineage(lineage: object) -> dict[str, object]:
    result = native_context_digest(
        "native_bash_reply_validation",
        {"reply_kind": "lineage", "material": lineage, "request": None},
        guard_home=_resolve_digest_home(None),
    )
    if not isinstance(result, dict) or result.get("native_bash_reply_valid") is not True:
        raise NativeBashError("native_bash_response_invalid")
    return cast(dict[str, object], lineage)
