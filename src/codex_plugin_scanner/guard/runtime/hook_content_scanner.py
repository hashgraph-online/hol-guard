"""Deterministic streaming content scanner wrapping existing secret detection.

This scanner wraps ``classify_secret_content()`` from
``runtime/secret_sensitivity.py`` with bounded, streaming semantics:

- byte budget (``max_bytes``)
- match limit (``HOOK_SCANNER_MAX_MATCHES``)
- wall-clock deadline (``deadline_monotonic``)
- rolling context window (``HOOK_SCANNER_CONTEXT_CHARS``)

It never produces secret sample text. It never runs an LLM. It never
calls the network. It is safe to call from the daemon hot path.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass

from .secret_sensitivity import classify_secret_content, secret_content_rule_version

HOOK_CONTENT_SCANNER_VERSION = "hook-content-v1"
HOOK_SCANNER_CONTEXT_CHARS = 8192
HOOK_SCANNER_MAX_MATCHES = 16
HOOK_SCANNER_DEFAULT_MAX_BYTES = 5 * 1024 * 1024

_EARLY_EXIT_SENSITIVITIES = frozenset({"high", "critical"})


@dataclass(frozen=True, slots=True)
class ContentScanMatch:
    """One secret-family match found by the scanner (no sample text)."""

    classifier: str
    family: str
    sensitivity: str
    reason: str


@dataclass(frozen=True, slots=True)
class ContentScanResult:
    """Result of scanning one or more text chunks."""

    matches: tuple[ContentScanMatch, ...]
    bytes_scanned: int
    chunks_scanned: int
    budget_exhausted: bool
    reason_code: str


class ContentScanner:
    """Bounded streaming scanner over ``classify_secret_content()``.

    Use ``scan_text()`` for a single string or ``scan_chunks()`` for
    streaming input (file reads, stdout). The rolling context window
    ensures tokens split across chunk boundaries are detected.
    """

    @property
    def version(self) -> str:
        return f"{HOOK_CONTENT_SCANNER_VERSION}:{secret_content_rule_version()}"

    def scan_text(
        self,
        text: str,
        *,
        local_content: bool,
        source_context: bool,
        max_bytes: int = HOOK_SCANNER_DEFAULT_MAX_BYTES,
        deadline_monotonic: float | None = None,
    ) -> ContentScanResult:
        return self.scan_chunks(
            [text],
            local_content=local_content,
            source_context=source_context,
            max_bytes=max_bytes,
            deadline_monotonic=deadline_monotonic,
        )

    def scan_chunks(
        self,
        chunks: Iterable[str],
        *,
        local_content: bool,
        source_context: bool,
        max_bytes: int = HOOK_SCANNER_DEFAULT_MAX_BYTES,
        deadline_monotonic: float | None = None,
    ) -> ContentScanResult:
        tail = ""
        matches_by_classifier: dict[str, ContentScanMatch] = {}
        bytes_scanned = 0
        chunks_scanned = 0

        for chunk in chunks:
            if not isinstance(chunk, str):
                # Safe fail: non-string chunk means caller typed badly.
                # Skip rather than crash the hot path. The caller is
                # responsible for ensuring str input.
                continue

            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                return ContentScanResult(
                    matches=tuple(matches_by_classifier.values()),
                    bytes_scanned=bytes_scanned,
                    chunks_scanned=chunks_scanned,
                    budget_exhausted=True,
                    reason_code="deadline_exceeded",
                )

            chunk_bytes = len(chunk.encode("utf-8"))
            remaining = max_bytes - bytes_scanned

            if chunk_bytes > remaining:
                # Scan only the allowed prefix by truncating to byte boundary.
                # We need to truncate by UTF-8 bytes safely.
                chunk_part = _truncate_to_byte_limit(chunk, remaining)
                if not chunk_part and remaining <= 0:
                    return ContentScanResult(
                        matches=tuple(matches_by_classifier.values()),
                        bytes_scanned=bytes_scanned,
                        chunks_scanned=chunks_scanned,
                        budget_exhausted=True,
                        reason_code="max_bytes_exceeded",
                    )
                window = tail + chunk_part
                bytes_scanned += len(chunk_part.encode("utf-8"))
                chunks_scanned += 1
                _scan_window(
                    window,
                    local_content=local_content,
                    source_context=source_context,
                    matches_by_classifier=matches_by_classifier,
                )
                return ContentScanResult(
                    matches=tuple(matches_by_classifier.values()),
                    bytes_scanned=bytes_scanned,
                    chunks_scanned=chunks_scanned,
                    budget_exhausted=True,
                    reason_code="max_bytes_exceeded",
                )

            bytes_scanned += chunk_bytes
            chunks_scanned += 1
            window = tail + chunk

            _scan_window(
                window,
                local_content=local_content,
                source_context=source_context,
                matches_by_classifier=matches_by_classifier,
            )

            # Early exit on high/critical secrets.
            if any(m.sensitivity in _EARLY_EXIT_SENSITIVITIES for m in matches_by_classifier.values()):
                return ContentScanResult(
                    matches=tuple(matches_by_classifier.values()),
                    bytes_scanned=bytes_scanned,
                    chunks_scanned=chunks_scanned,
                    budget_exhausted=False,
                    reason_code="secret_match_early_exit",
                )

            if len(matches_by_classifier) >= HOOK_SCANNER_MAX_MATCHES:
                return ContentScanResult(
                    matches=tuple(matches_by_classifier.values()),
                    bytes_scanned=bytes_scanned,
                    chunks_scanned=chunks_scanned,
                    budget_exhausted=False,
                    reason_code="max_matches_reached",
                )

            tail = window[-HOOK_SCANNER_CONTEXT_CHARS:] if len(window) > HOOK_SCANNER_CONTEXT_CHARS else window

        reason_code = "clean" if not matches_by_classifier else "matches"

        return ContentScanResult(
            matches=tuple(matches_by_classifier.values()),
            bytes_scanned=bytes_scanned,
            chunks_scanned=chunks_scanned,
            budget_exhausted=False,
            reason_code=reason_code,
        )


def _scan_window(
    window: str,
    *,
    local_content: bool,
    source_context: bool,
    matches_by_classifier: dict[str, ContentScanMatch],
) -> None:
    """Classify one rolling window and merge new matches."""
    suppressed_matches = classify_secret_content(window, suppress_samples=True)
    for match in suppressed_matches:
        if match.classifier not in matches_by_classifier:
            matches_by_classifier[match.classifier] = ContentScanMatch(
                classifier=match.classifier,
                family=match.family,
                sensitivity=match.sensitivity,
                reason=match.reason,
            )

    # Preserve current local-content escalation semantics:
    # if no sample-suppressed matches were found and local_content is True,
    # retry with suppress_samples=False to catch sample-looking assignments.
    if not suppressed_matches and local_content:
        unsuppressed = classify_secret_content(window, suppress_samples=False)
        for match in unsuppressed:
            if match.classifier not in matches_by_classifier:
                matches_by_classifier[match.classifier] = ContentScanMatch(
                    classifier=match.classifier,
                    family=match.family,
                    sensitivity=match.sensitivity,
                    reason=match.reason,
                )


def _truncate_to_byte_limit(text: str, max_bytes: int) -> str:
    """Truncate a string so its UTF-8 encoding fits within max_bytes.

    If max_bytes <= 0, return empty string.
    """
    if max_bytes <= 0:
        return ""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    # Decode the truncated bytes, allowing partial final char to be dropped.
    truncated = encoded[:max_bytes]
    return truncated.decode("utf-8", errors="ignore")


__all__ = [
    "HOOK_CONTENT_SCANNER_VERSION",
    "HOOK_SCANNER_CONTEXT_CHARS",
    "HOOK_SCANNER_DEFAULT_MAX_BYTES",
    "HOOK_SCANNER_MAX_MATCHES",
    "ContentScanMatch",
    "ContentScanResult",
    "ContentScanner",
]
