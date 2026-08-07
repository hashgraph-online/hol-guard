"""Causal-context propagation through the execution-assurance local core.

Implements a frozen, immutable ``ExecutionContextLink`` that carries causal
identifiers across execution boundaries (parent, root, retry linkage, depth,
and a domain-framed digest for tamper-evidence).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from .execution_assurance_contract import framed_digest

_EXECUTION_CONTEXT_LINK_DOMAIN: Final = "guard.execution-context-link.v1"
_MAX_FIELD_LENGTH: Final = 128
_SHA256_LENGTH: Final = 64
_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}")
_MAX_DEPTH: Final = 32


def _require_nonempty_str(value: object, label: str, *, max_length: int = _MAX_FIELD_LENGTH) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ValueError(f"{label} must be a non-empty string of at most {max_length} characters")
    return value


def _require_sha256(value: object, label: str) -> str:
    text = _require_nonempty_str(value, label, max_length=_SHA256_LENGTH)
    if _SHA256_RE.fullmatch(text) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _require_non_negative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


@dataclass(frozen=True, slots=True)
class ExecutionContextLink:
    """Immutable causal execution context linkage.

    Carries parent/root identifiers, retry-of correlation, an attempt nonce,
    propagation depth (bounded to ``_MAX_DEPTH``), and a domain-framed digest
    for tamper-evidence.
    """

    correlation_id: str
    parent_correlation_id: str | None
    retry_of_correlation_id: str | None
    attempt_nonce: str
    depth: int
    root_id: str
    continuation_digest: str

    def __post_init__(self) -> None:
        _ = _require_nonempty_str(self.correlation_id, "correlation_id")
        if self.parent_correlation_id is not None:
            _ = _require_nonempty_str(self.parent_correlation_id, "parent_correlation_id")
        if self.retry_of_correlation_id is not None:
            _ = _require_nonempty_str(self.retry_of_correlation_id, "retry_of_correlation_id")
        _ = _require_nonempty_str(self.attempt_nonce, "attempt_nonce")
        _ = _require_non_negative_int(self.depth, "depth")
        if self.depth > _MAX_DEPTH:
            raise ValueError(f"depth must be at most {_MAX_DEPTH}; got {self.depth}")
        _ = _require_nonempty_str(self.root_id, "root_id")
        _ = _require_sha256(self.continuation_digest, "continuation_digest")

    @property
    def is_root(self) -> bool:
        """True when this link has no parent correlation."""
        return self.parent_correlation_id is None

    @property
    def is_retry(self) -> bool:
        """True when this link carries retry linkage."""
        return self.retry_of_correlation_id is not None


def construct_execution_context_link(
    *,
    correlation_id: str,
    root_id: str,
    attempt_nonce: str,
    parent_correlation_id: str | None = None,
    retry_of_correlation_id: str | None = None,
    depth: int = 0,
    continuation_digest: str | None = None,
) -> ExecutionContextLink:
    """Build an ``ExecutionContextLink`` with optional parent/retry linkage.

    When ``continuation_digest`` is omitted a fresh domain-framed digest is
    computed from the stable fields.
    """
    _ = _require_nonempty_str(correlation_id, "correlation_id")
    _ = _require_nonempty_str(root_id, "root_id")
    _ = _require_nonempty_str(attempt_nonce, "attempt_nonce")
    if parent_correlation_id is not None:
        _ = _require_nonempty_str(parent_correlation_id, "parent_correlation_id")
    if retry_of_correlation_id is not None:
        _ = _require_nonempty_str(retry_of_correlation_id, "retry_of_correlation_id")
    _ = _require_non_negative_int(depth, "depth")
    if depth > _MAX_DEPTH:
        raise ValueError(f"depth must be at most {_MAX_DEPTH}; got {depth}")

    if continuation_digest is None:
        payload: dict[str, object] = {
            "correlation_id": correlation_id,
            "root_id": root_id,
            "attempt_nonce": attempt_nonce,
            "parent_correlation_id": parent_correlation_id,
            "retry_of_correlation_id": retry_of_correlation_id,
            "depth": depth,
        }
        continuation_digest = framed_digest(_EXECUTION_CONTEXT_LINK_DOMAIN, payload)

    return ExecutionContextLink(
        correlation_id=correlation_id,
        parent_correlation_id=parent_correlation_id,
        retry_of_correlation_id=retry_of_correlation_id,
        attempt_nonce=attempt_nonce,
        depth=depth,
        root_id=root_id,
        continuation_digest=continuation_digest,
    )


def derive_child_link(
    parent: ExecutionContextLink,
    *,
    retry: bool = False,
    child_correlation_id: str | None = None,
    child_attempt_nonce: str | None = None,
) -> ExecutionContextLink:
    """Derive a child ``ExecutionContextLink`` from a parent.

    - ``depth`` is incremented (parent depth + 1).
    - ``root_id`` is preserved from the parent.
    - ``parent_correlation_id`` is set to the parent's correlation id.
    - When ``retry`` is ``True``, ``retry_of_correlation_id`` is set to the
      parent's correlation id.
    - A fresh ``continuation_digest`` is computed automatically.
    """
    new_depth = parent.depth + 1
    if new_depth > _MAX_DEPTH:
        raise ValueError(f"child depth {new_depth} exceeds maximum {_MAX_DEPTH}")

    # Default child IDs are opaque digests derived from the parent, so chained
    # derivation never lets the ID length grow without bound across depth.
    if child_correlation_id is None:
        child_correlation_id = framed_digest(
            _EXECUTION_CONTEXT_LINK_DOMAIN,
            {"correlation_id": parent.correlation_id, "depth": new_depth, "kind": "child-correlation"},
        )
    if child_attempt_nonce is None:
        child_attempt_nonce = framed_digest(
            _EXECUTION_CONTEXT_LINK_DOMAIN,
            {"attempt_nonce": parent.attempt_nonce, "depth": new_depth, "kind": "child-nonce"},
        )

    return construct_execution_context_link(
        correlation_id=child_correlation_id,
        root_id=parent.root_id,
        attempt_nonce=child_attempt_nonce,
        parent_correlation_id=parent.correlation_id,
        retry_of_correlation_id=parent.correlation_id if retry else None,
        depth=new_depth,
    )
