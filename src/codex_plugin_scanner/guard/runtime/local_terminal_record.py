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

_HEX_DIGITS = frozenset("0123456789abcdef")
_MAX_STREAMS = 8


def _require_outcome(value: object) -> None:
    if not isinstance(value, ExecutionOutcome):
        raise ValueError("outcome must be an ExecutionOutcome")


def _require_trust(value: object) -> None:
    if not isinstance(value, GuardExecutionAttestationTrust):
        raise ValueError("attestation_trust must be a GuardExecutionAttestationTrust")


def _require_exit_code(value: object) -> None:
    if value is None:
        return
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("exit_code must be an int or None")


def _require_execution_instance(value: object) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError("execution_instance must be a non-empty string")


def _require_lowercase_sha256(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(character not in _HEX_DIGITS for character in value):
        raise ValueError(f"{label} must be a 64-char lowercase SHA-256 hex digest")


def _require_stream_table(
    byte_counts: tuple[tuple[str, int], ...],
    digests: tuple[tuple[str, str], ...],
) -> None:
    if type(byte_counts) is not tuple:
        raise ValueError("stream_byte_counts must be a tuple")
    if type(digests) is not tuple:
        raise ValueError("stream_digests must be a tuple")
    if len(byte_counts) > _MAX_STREAMS or len(digests) > _MAX_STREAMS:
        raise ValueError(f"too many streams (max {_MAX_STREAMS})")
    bc_keys = tuple(key for key, _ in byte_counts)
    d_keys = tuple(key for key, _ in digests)
    if len(set(bc_keys)) != len(bc_keys) or len(set(d_keys)) != len(d_keys):
        raise ValueError("duplicate stream entries are not allowed")
    if set(bc_keys) != set(d_keys):
        raise ValueError("stream digests must cover every stream byte count")


def _require_stream_entries(
    byte_counts: tuple[tuple[str, int], ...],
    digests: tuple[tuple[str, str], ...],
) -> None:
    for key, count in byte_counts:
        if type(key) is not str or not key:
            raise ValueError("stream_byte_counts entry key must be a non-empty string")
        if type(count) is not int or isinstance(count, bool) or count < 0:
            raise ValueError("stream_byte_counts entry count must be a non-negative integer")
    for key, digest in digests:
        if type(key) is not str or not key:
            raise ValueError("stream_digests entry key must be a non-empty string")
        _require_lowercase_sha256(digest, "stream_digests entry digest")


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
        _require_outcome(self.outcome)
        _require_trust(self.attestation_trust)
        if self.attestation_trust is not GuardExecutionAttestationTrust.SELF_ATTESTED:
            raise ValueError("local terminal records are always SELF_ATTESTED")
        _require_exit_code(self.exit_code)
        _require_stream_table(self.stream_byte_counts, self.stream_digests)
        _require_stream_entries(self.stream_byte_counts, self.stream_digests)
        if type(self.declared_output_digests) is not tuple:
            raise ValueError("declared_output_digests must be a tuple")
        for digest in self.declared_output_digests:
            _require_lowercase_sha256(digest, "declared_output_digests entry")
        if type(self.truncated) is not bool:
            raise ValueError("truncated must be a bool")
        if type(self.cleanup_complete) is not bool:
            raise ValueError("cleanup_complete must be a bool")
        _require_execution_instance(self.execution_instance)


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
    execution_instance: str,
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

    stream_byte_counts: tuple[tuple[str, int], ...] = tuple((output.stream, output.byte_count) for output in outputs)
    stream_digests: tuple[tuple[str, str], ...] = tuple((output.stream, output.digest) for output in outputs)
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
