"""Extract text from hook payloads for server-side output scanning.

This module mirrors the Pi extension's TypeScript ``collectOutputText``
function. It traverses a hook payload's output fields and extracts
all text-bearing content — the same text the model would see — so the
server-side engine can scan the FULL output, not just a bounded excerpt.

The extraction rules are intentionally simple and match the TypeScript
implementation:

- Strings are accumulated directly.
- ``{"type": "text", "text": "..."}`` objects contribute their ``text`` field.
- Arrays and nested objects are traversed recursively.
- Cycles, excessive depth, and oversized arrays are stopped gracefully.

The result is a bounded text blob suitable for streaming secret scanning.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

OUTPUT_TEXT_KEYS: tuple[str, ...] = (
    "stdout",
    "stderr",
    "output",
    "content",
    "result",
    "message",
    "text",
)

# Payload keys that hold the tool's response/output across harnesses.
# These are checked in order — first match wins.
PAYLOAD_OUTPUT_KEYS: tuple[str, ...] = (
    "tool_response",
    "tool_output",
    "tool_result",
    "toolOutput",
    "stdout",
    "stderr",
    "output",
    "content",
    "result",
    "response",
)

MAX_DEPTH = 24
MAX_CONTENT_ITEMS = 24
MAX_OBJECT_KEYS = 24
MAX_OUTPUT_CHARS = 5 * 1024 * 1024  # 5 MiB — matches SOURCE_READ_MAX_SCAN_BYTES


@dataclass(frozen=True, slots=True)
class ExtractedOutput:
    """Result of extracting output text from a hook payload."""

    text: str
    chars: int
    truncated: bool


def collect_output_text(value: object) -> ExtractedOutput:
    """Traverse a payload value and extract all text-bearing content.

    Returns an :class:`ExtractedOutput` with the concatenated text and
    a ``truncated`` flag if any limit was hit.
    """
    parts: list[str] = []
    chars = 0
    truncated = False
    seen: set[int] = set()

    def _append(text: str) -> None:
        nonlocal chars, truncated
        if truncated or not text:
            return
        if chars + len(text) > MAX_OUTPUT_CHARS:
            remaining = MAX_OUTPUT_CHARS - chars
            if remaining > 0:
                parts.append(text[:remaining])
                chars += remaining
            truncated = True
            return
        parts.append(text)
        chars += len(text)

    def _traverse(val: object, depth: int) -> None:
        nonlocal truncated
        if truncated:
            return
        if isinstance(val, str):
            _append(val)
            return
        if val is None or isinstance(val, (int, float, bool)):
            return
        if isinstance(val, bytes):
            _append(val.decode("utf-8", errors="replace"))
            return
        if not isinstance(val, (Mapping, list)):
            return
        obj_id = id(val)
        if obj_id in seen:
            truncated = True
            return
        if depth > MAX_DEPTH:
            truncated = True
            return
        seen.add(obj_id)
        try:
            if isinstance(val, list):
                if len(val) > MAX_CONTENT_ITEMS:
                    truncated = True
                    return
                for item in val:
                    if truncated:
                        return
                    _traverse(item, depth + 1)
                return
            # Mapping — match collectOutputText: only extract text from
            # {type: "text", text: ...} objects, not from metadata keys.
            record = val
            if record.get("type") == "text" and isinstance(record.get("text"), str):
                _append(record["text"])  # type: ignore[literal-required]
                return
            key_count = 0
            for key in OUTPUT_TEXT_KEYS:
                if key not in record:
                    continue
                if key_count >= MAX_OBJECT_KEYS:
                    truncated = True
                    return
                key_count += 1
                if truncated:
                    return
                _traverse(record[key], depth + 1)  # type: ignore[index]
        finally:
            seen.discard(obj_id)

    _traverse(value, 0)
    return ExtractedOutput(text="".join(parts), chars=chars, truncated=truncated)


def extract_payload_output(payload: Mapping[str, object]) -> ExtractedOutput:
    """Extract and concatenate text from all output fields in a hook payload.

    Scans ALL present output keys (``tool_response``, ``stdout``,
    ``stderr``, etc.) — not just the first match — to ensure no output
    field is left unscanned. This prevents secrets in ``stderr`` from
    being missed when ``stdout`` is also non-empty.
    """
    all_parts: list[str] = []
    total_chars = 0
    any_truncated = False

    for key in PAYLOAD_OUTPUT_KEYS:
        value = payload.get(key)
        if value is not None:
            result = collect_output_text(value)
            if result.text:
                all_parts.append(result.text)
                total_chars += result.chars
                if result.truncated:
                    any_truncated = True

    if not all_parts:
        return ExtractedOutput(text="", chars=0, truncated=False)

    joined = "\n".join(all_parts)
    return ExtractedOutput(
        text=joined,
        chars=len(joined),
        truncated=any_truncated or len(joined) > MAX_OUTPUT_CHARS,
    )


__all__ = [
    "MAX_OUTPUT_CHARS",
    "OUTPUT_TEXT_KEYS",
    "PAYLOAD_OUTPUT_KEYS",
    "ExtractedOutput",
    "collect_output_text",
    "extract_payload_output",
]
