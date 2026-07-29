"""Local terminal record — the unsigned-local cousin of TerminalStatement.

Mirrors ``execution_assurance_contract.TerminalStatement`` fields but is
built exclusively from local subprocess output (no provider, no attestation
signing).  Every instance carries ``attestation_trust=SELF_ATTESTED``
because unsigned local output is **never** verified.

This module is pure and side-effect-free.
"""

from __future__ import annotations

from dataclasses import dataclass

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    ExecutionOutcome,
    GuardExecutionAttestationTrust,
)
from codex_plugin_scanner.guard.runtime.local_output_review import BoundedOutput

__all__ = [
    "LocalTerminalRecord",
    "build_local_terminal_record",
]

# ---------------------------------------------------------------------------
# LocalTerminalRecord — frozen/slots mirror of TerminalStatement fields
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LocalTerminalRecord:
    """Bound-local terminal record, never signed/verified.

    Mirrors the fields of ``TerminalStatement`` (``outcome``, ``exit_code``,
    ``stream_byte_counts``, ``stream_digests``, ``attestation_trust``) and
    adds ``truncated``, ``declared_output_digests``, ``cleanup_complete``,
    and ``execution_instance``.  Always carries
    ``attestation_trust=SELF_ATTESTED``.
    """

    outcome: ExecutionOutcome
    exit_code: int | None
    stream_byte_counts: tuple[tuple[str, int], ...]
    stream_digests: tuple[tuple[str, str], ...]
    truncated: bool
    declared_output_digests: tuple[str, ...]
    cleanup_complete: bool
    execution_instance: str
    attestation_trust: GuardExecutionAttestationTrust

    def __post_init__(self) -> None:
        # Validation of typed fields uses `type()` to avoid basedpyright
        # "unnecessary isinstance" warnings on already-typed attributes.
        if type(self.stream_byte_counts) is not tuple:
            raise ValueError("stream_byte_counts must be a tuple")
        if type(self.stream_digests) is not tuple:
            raise ValueError("stream_digests must be a tuple")
        if type(self.declared_output_digests) is not tuple:
            raise ValueError("declared_output_digests must be a tuple")
        for digest in self.declared_output_digests:
            if type(digest) is not str or len(digest) != 64:
                raise ValueError(f"declared_output_digests entry must be a 64-char hex SHA-256 string, got {digest!r}")
            try:
                _ = int(digest, 16)
            except ValueError:
                raise ValueError(f"declared_output_digests entry must be hex, got {digest!r}") from None
        if type(self.truncated) is not bool:
            raise ValueError("truncated must be a bool")
        if type(self.cleanup_complete) is not bool:
            raise ValueError("cleanup_complete must be a bool")
        if type(self.execution_instance) is not str or not self.execution_instance:
            raise ValueError("execution_instance must be a non-empty string")

        # Cross-field invariant: byte_counts and digests share the same keys.
        max_streams = 8
        if len(self.stream_byte_counts) > max_streams or len(self.stream_digests) > max_streams:
            raise ValueError(f"too many streams (max {max_streams})")
        bc_keys = {k for k, _ in self.stream_byte_counts}
        d_keys = {k for k, _ in self.stream_digests}
        if bc_keys != d_keys:
            raise ValueError(
                f"stream keys mismatch: byte_counts={sorted(bc_keys)}, digests={sorted(d_keys)}"
            )
        # Individual validation
        for key, count in self.stream_byte_counts:
            if type(key) is not str or not key:
                raise ValueError("stream_byte_counts entry key must be a non-empty string")
            if type(count) is not int or isinstance(count, bool) or count < 0:
                raise ValueError(f"stream_byte_counts entry count must be a non-negative int, got {count!r}")
        for key, digest in self.stream_digests:
            if type(key) is not str or not key:
                raise ValueError("stream_digests entry key must be a non-empty string")
            if type(digest) is not str or len(digest) != 64:
                raise ValueError(f"stream_digests entry digest must be a 64-char hex SHA-256 string, got {digest!r}")
            try:
                _ = int(digest, 16)
            except ValueError:
                raise ValueError(f"stream_digests entry digest must be hex, got {digest!r}") from None


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_local_terminal_record(
    *,
    outcome: ExecutionOutcome,
    exit_code: int | None,
    outputs: tuple[BoundedOutput, ...],
    declared_output_digests: tuple[str, ...] | None = None,
    cleanup_complete: bool = False,
    execution_instance: str = "",
) -> LocalTerminalRecord:
    """Build a ``LocalTerminalRecord`` from a tuple of ``BoundedOutput``.

    Derives ``stream_byte_counts``, ``stream_digests``, and
    ``truncated`` from ``outputs``, and always sets
    ``attestation_trust=SELF_ATTESTED``.

    Args:
        outcome: The subprocess outcome (succeeded / failed / cancelled / unknown).
        exit_code: The raw exit code or ``None`` if unavailable.
        outputs: A tuple of ``BoundedOutput`` (typically one per stdout and stderr).
        declared_output_digests: Optional extra digests to carry (empty tuple by default).
        cleanup_complete: Whether subprocess cleanup (filehandles, etc.) is done.
        execution_instance: Human-readable identifier for the execution instance.

    Returns:
        A fully-validated ``LocalTerminalRecord`` with ``attestation_trust``
        set to ``SELF_ATTESTED``.
    """
    if type(outcome) is not ExecutionOutcome:
        raise TypeError(f"outcome must be ExecutionOutcome, got {type(outcome).__name__}")
    if type(outputs) is not tuple:
        raise TypeError(f"outputs must be a tuple, got {type(outputs).__name__}")

    stream_byte_counts: tuple[tuple[str, int], ...] = tuple(
        (output.stream, output.byte_count) for output in outputs
    )
    stream_digests: tuple[tuple[str, str], ...] = tuple(
        (output.stream, output.digest) for output in outputs
    )
    truncated = any(output.truncated for output in outputs)
    if declared_output_digests is None:
        declared_output_digests = ()

    return LocalTerminalRecord(
        outcome=outcome,
        exit_code=exit_code,
        stream_byte_counts=stream_byte_counts,
        stream_digests=stream_digests,
        truncated=truncated,
        declared_output_digests=declared_output_digests,
        cleanup_complete=cleanup_complete,
        execution_instance=execution_instance,
        attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
    )
