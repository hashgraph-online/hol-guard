"""Project the native pre-tool command model into the Python value type.

The Rust runtime parses the command, owns its structure and binds the model to
the request: ``native_pretool`` refuses a reply whose normalized text is not
the request's. Python only presents that model; it does not re-derive
executables, wrappers or environment names. Command PreToolUse authority lives
in the Rust runtime and native_pretool transport.
"""

from __future__ import annotations

from typing import Any

from .runtime.command_model import CanonicalCommand, _canonical_from_wire

_IDENTITY_PREFIX = "command-security-v2:"
_HEX_DIGITS = frozenset("0123456789abcdef")
_REQUEST_SHAPE = {"dialect": "posix", "transport": "shell_string", "extraction_provenance": "guard-shell"}
_MAX_SEGMENTS = 128


def _valid_identity(identity: object) -> bool:
    if not isinstance(identity, str) or not identity.startswith(_IDENTITY_PREFIX):
        return False
    digest = identity.removeprefix(_IDENTITY_PREFIX)
    return len(digest) == 64 and set(digest) <= _HEX_DIGITS


def _segments_fit(payload: dict[str, Any]) -> bool:
    """Check the model's shape only: segment count, string texts and spans that lie in the normalized text in order."""
    text = payload.get("normalized_text")
    segments = payload.get("segments")
    if not isinstance(text, str) or not isinstance(segments, list) or len(segments) > _MAX_SEGMENTS:
        return False
    if payload.get("confidence") == "uncertain":
        return not segments
    if not segments or payload.get("uncertainty_reason") is not None:
        return False
    previous_end = 0
    for segment in segments:
        span = segment.get("span") if isinstance(segment, dict) else None
        if not isinstance(span, dict) or span.get("source") != "normalized":
            return False
        start, end = span.get("start"), span.get("end")
        if not isinstance(start, int) or not isinstance(end, int) or isinstance(start, bool) or isinstance(end, bool):
            return False
        if not previous_end <= start < end <= len(text):
            return False
        # The text may differ from its span: Rust rewrites a complete `[[ ... ]]`
        # test to the single-bracket form and keeps the span on the original.
        if not isinstance(segment.get("text"), str):
            return False
        previous_end = end
    return True


def _canonical_command_from_native(
    command: str,
    payload: dict[str, Any],
) -> CanonicalCommand | None:
    """Present an exact native model as ``CanonicalCommand``, or None when it is malformed."""
    if any(payload.get(name) != value for name, value in _REQUEST_SHAPE.items()):
        return None
    if payload.get("confidence") not in {"exact", "uncertain"} or not _segments_fit(payload):
        return None
    identity = payload.get("security_identity")
    if identity is not None and not _valid_identity(identity):
        return None
    value = {
        **payload,
        "raw_text": command.strip(),
        "redirects": [],
        "embedded_commands": [],
        # Older exact payloads omit the identity; keep their lazy API.
        "security_identity": identity or "",
    }
    try:
        canonical = _canonical_from_wire(value)
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    if payload.get("path_overridden") is not canonical.path_overridden:
        return None
    if identity is None:
        object.__setattr__(canonical, "_bound_identity", None)
    return canonical
