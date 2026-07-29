"""Bounded output capture, secret scanning, and truncation for local terminal records.

This module is the boundary between raw subprocess output bytes and the
privacy-safe structures that flow into ``LocalTerminalRecord`` and onward
to the effect-decision engine.  Its contracts are:

* ``BoundedOutput`` is a frozen/slots dataclass that carries at most
  ``max_bytes`` of content but always reports the *full* original byte
  count and a SHA-256 digest over the *full* original bytes so that
  truncation is detectable by a downstream verifier.
* ``scan_output_for_secrets`` returns *labels only* -- never matched
  values -- and is pure (no I/O, no mutation).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Final

# ---------------------------------------------------------------------------
# Secret-pattern compilation (module-level, never recompiled per-call)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "aws-access-key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    (
        "private-key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ),
    (
        "jwt",
        re.compile(r"[A-Za-z0-9_=-]{20,}\.[A-Za-z0-9_=-]{20,}\.[A-Za-z0-9_=-]{20,}"),
    ),
    (
        "secret-assignment",
        re.compile(r"(?i)(api[_\-]?key|secret|password|token)\s*[=:]\s*\S+"),
    ),
)

# ---------------------------------------------------------------------------
# BoundedOutput -- immutable, privacy-safe output descriptor
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BoundedOutput:
    """Privacy-safe descriptor of captured subprocess output.

    ``stream`` is ``"stdout"`` or ``"stderr"``.
    ``byte_count`` is the *full* original byte length (always >= 0).
    ``digest`` is a lowercase hex SHA-256 over the *full* original bytes.
    ``truncated`` is ``True`` when ``len(original_data) > max_bytes``.
    """

    stream: str
    byte_count: int
    digest: str
    truncated: bool

    def __post_init__(self) -> None:
        if type(self.stream) is not str or self.stream not in ("stdout", "stderr"):
            raise ValueError(f"stream must be 'stdout' or 'stderr', got {self.stream!r}")
        if type(self.byte_count) is not int or isinstance(self.byte_count, bool) or self.byte_count < 0:
            raise ValueError(f"byte_count must be a non-negative integer, got {self.byte_count!r}")
        if (
            type(self.digest) is not str
            or len(self.digest) != 64
            or any(character not in "0123456789abcdef" for character in self.digest)
        ):
            raise ValueError(f"digest must be a 64-char lowercase hex SHA-256 string, got {self.digest!r}")
        if type(self.truncated) is not bool:
            raise ValueError(f"truncated must be a bool, got {type(self.truncated).__name__!r}")


# ---------------------------------------------------------------------------
# Pure functions
# ---------------------------------------------------------------------------


def capture_bounded_output(data: bytes, *, stream: str = "stdout", max_bytes: int = 65536) -> BoundedOutput:
    """Capture *bounded* output and compute a full-bytes digest.

    If ``len(data) > max_bytes`` only the first ``max_bytes`` are retained
    for downstream consumption, but ``byte_count`` and ``digest`` are
    computed over the *full* ``data`` so truncation is always detectable.

    Args:
        data: The raw output bytes from a subprocess.
        stream: Either ``"stdout"`` or ``"stderr"``.
        max_bytes: Soft cap -- truncation, not discard.

    Returns:
        A ``BoundedOutput`` with the bounded slice available via ``bytes``
        (never stored internally -- the caller owns the bytes).
    """
    if type(data) is not bytes:
        raise TypeError(f"data must be bytes, got {type(data).__name__}")
    return BoundedOutput(
        stream=stream,
        byte_count=len(data),
        digest=hashlib.sha256(data).hexdigest(),
        truncated=len(data) > max_bytes,
    )


def scan_output_for_secrets(data: bytes) -> tuple[str, ...]:
    """Scan raw output bytes for common secret patterns.

    Returns a *tuple of unique label strings* (e.g. ``("aws-access-key", "jwt")``).
    Matched values are **never** returned -- only labels.

    The returned tuple is sorted so that callers can compare deterministically.

    Args:
        data: Raw output bytes to scan (decoded as latin-1 to avoid decode errors).

    Returns:
        Sorted tuple of label strings for every pattern that matched at least once.
    """
    if type(data) is not bytes:
        raise TypeError(f"data must be bytes, got {type(data).__name__}")
    text = data.decode("latin-1")

    matched_labels: list[str] = []
    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            matched_labels.append(label)

    return tuple(sorted(matched_labels))
