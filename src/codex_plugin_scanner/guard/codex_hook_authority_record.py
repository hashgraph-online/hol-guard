"""Seal and open signed Codex hook authority records through the native runtime.

The runtime owns what each record may contain and whether it opens: the
pending publication inverse, the retained authority receipt and the repair
and inverse review requests. Callers read the key and the files, then raise
the refused reason with their own error type. No answer is a refusal.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Literal, Protocol

_FEATURE = "native-codex-hook-authority-record-v1"
_SCHEMA = "codex-hook-authority-record.v1"
_TIMEOUT_SECONDS = 10.0
# Records stay under 24 MiB of ASCII; the answer carries one as a JSON string.
_OUTPUT_LIMIT = 64 * 1024 * 1024
RUNTIME_UNAVAILABLE = "runtime_unavailable"

RecordKind = Literal["recovery", "receipt", "repair_request", "inverse_request"]


class HookKey(Protocol):
    key: bytes
    key_id: str
    installation_id: str


class AuthorityRecordRefusedError(Exception):
    """The runtime refused a record, or did not answer."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def seal_authority_record(
    kind: RecordKind,
    payload: Mapping[str, object],
    hook_key: HookKey,
    *,
    signed_at: str | None = None,
) -> bytes:
    """Sign `payload` and return the record's exact bytes."""

    request: dict[str, object] = {"payload": dict(payload)}
    if signed_at is not None:
        request["signed_at"] = signed_at
    answer = _ask("seal", kind, hook_key, request)
    text = answer.get("text")
    if not isinstance(text, str):
        raise AuthorityRecordRefusedError(RUNTIME_UNAVAILABLE)
    return text.encode("ascii")


def open_authority_record(
    kind: RecordKind,
    raw: bytes | str,
    hook_key: HookKey,
    *,
    guard_home: str,
    config_path: str | None = None,
    live_config_conflict: bool = False,
) -> tuple[dict[str, object], str]:
    """Authenticate a record; return its payload without authentication and its signed_at."""

    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    except UnicodeDecodeError as exc:
        raise AuthorityRecordRefusedError("undecodable") from exc
    request: dict[str, object] = {"text": text, "guard_home": guard_home}
    if config_path is not None:
        request["config_path"] = config_path
    if live_config_conflict:
        request["live_config_conflict"] = True
    if kind in ("repair_request", "inverse_request"):
        request["now_monotonic"] = time.monotonic()
    answer = _ask("open", kind, hook_key, request)
    payload, signed_at = answer.get("payload"), answer.get("signed_at")
    if not isinstance(payload, dict) or not isinstance(signed_at, str):
        raise AuthorityRecordRefusedError(RUNTIME_UNAVAILABLE)
    return payload, signed_at


def check_receipt_manifest(
    manifest: Mapping[str, object],
    hook_key: HookKey,
    *,
    guard_home: str,
    config_path: str,
) -> None:
    """Refuse an authenticated manifest that describes another config or home."""

    _ask(
        "receipt_manifest",
        "receipt",
        hook_key,
        {"manifest": dict(manifest), "guard_home": guard_home, "config_path": config_path},
    )


def repair_proof_matches(payload: Mapping[str, object], proof: Mapping[str, object]) -> bool:
    """Whether a native admission proof saw exactly the published repair."""

    answer = _call({"op": "repair_proof", "payload": dict(payload), "proof": dict(proof)})
    matches = answer.get("matches")
    if not isinstance(matches, bool):
        raise AuthorityRecordRefusedError(RUNTIME_UNAVAILABLE)
    return matches


def _ask(op: str, kind: RecordKind, hook_key: HookKey, request: dict[str, object]) -> dict[str, object]:
    return _call(
        {
            "op": op,
            "kind": kind,
            "key_hex": hook_key.key.hex(),
            "key_id": hook_key.key_id,
            "installation_id": hook_key.installation_id,
            **request,
        }
    )


def _call(request: dict[str, object]) -> dict[str, object]:
    from .codex_hook_file_integrity import active_hook_validation_deadline
    from .mdm.runtime_request import runtime_answer

    bounds = [time.monotonic() + _TIMEOUT_SECONDS, active_hook_validation_deadline()]
    try:
        answer = runtime_answer(
            _FEATURE,
            "codex-hook-authority-record",
            {"schema": _SCHEMA, **request},
            output_limit=_OUTPUT_LIMIT,
            deadline=min(bound for bound in bounds if bound is not None),
        )
    except (TypeError, ValueError) as exc:
        raise AuthorityRecordRefusedError("invalid") from exc
    if not isinstance(answer, dict):
        raise AuthorityRecordRefusedError(RUNTIME_UNAVAILABLE)
    error = answer.get("error")
    if isinstance(error, str):
        raise AuthorityRecordRefusedError(error)
    return answer


__all__ = [
    "RUNTIME_UNAVAILABLE",
    "AuthorityRecordRefusedError",
    "check_receipt_manifest",
    "open_authority_record",
    "repair_proof_matches",
    "seal_authority_record",
]
