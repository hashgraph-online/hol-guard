"""Tests for local_terminal_record — frozen dataclass and builder invariants.

Focus on:
* byte counts and digests consistent with outputs
* attestation is always SELF_ATTESTED
* cleanup_complete binding (True/False)
* validation failures on malformed input
* immutability
"""

from __future__ import annotations

import hashlib

import pytest

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    ExecutionOutcome,
    GuardExecutionAttestationTrust,
)
from codex_plugin_scanner.guard.runtime.local_output_review import (
    capture_bounded_output,
)
from codex_plugin_scanner.guard.runtime.local_terminal_record import (
    build_local_terminal_record,
)

# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def _stdout_output(size: int = 100) -> bytes:
    """Generate deterministic test bytes."""
    return b"S" * size


def _stderr_output(size: int = 50) -> bytes:
    return b"E" * size


def test_build_simple_record() -> None:
    stdout_data = _stdout_output(100)
    stderr_data = _stderr_output(50)
    outputs = (
        capture_bounded_output(stdout_data, stream="stdout"),
        capture_bounded_output(stderr_data, stream="stderr"),
    )
    record = build_local_terminal_record(
        outcome=ExecutionOutcome.SUCCEEDED,
        exit_code=0,
        outputs=outputs,
        cleanup_complete=True,
        execution_instance="test-instance-1",
    )

    assert record.outcome == ExecutionOutcome.SUCCEEDED
    assert record.exit_code == 0
    assert record.cleanup_complete is True
    assert record.execution_instance == "test-instance-1"
    assert record.attestation_trust == GuardExecutionAttestationTrust.SELF_ATTESTED

    # Verify derived fields match inputs
    assert len(record.stream_byte_counts) == 2
    assert len(record.stream_digests) == 2

    bc_map = {k: v for k, v in record.stream_byte_counts}
    assert bc_map["stdout"] == 100
    assert bc_map["stderr"] == 50

    d_map = {k: v for k, v in record.stream_digests}
    assert d_map["stdout"] == hashlib.sha256(stdout_data).hexdigest()
    assert d_map["stderr"] == hashlib.sha256(stderr_data).hexdigest()


def test_build_without_stderr() -> None:
    """A single output (stdout only) is valid."""
    outputs = (capture_bounded_output(b"hello", stream="stdout"),)
    record = build_local_terminal_record(
        outcome=ExecutionOutcome.FAILED,
        exit_code=1,
        outputs=outputs,
        execution_instance="solo",
    )
    assert len(record.stream_byte_counts) == 1
    assert record.stream_byte_counts[0] == ("stdout", 5)


def test_build_with_none_exit_code() -> None:
    outputs: tuple[()] = ()
    record = build_local_terminal_record(
        outcome=ExecutionOutcome.UNKNOWN,
        exit_code=None,
        outputs=outputs,
        execution_instance="no-exit",
    )
    assert record.exit_code is None


# ---------------------------------------------------------------------------
# attestation_trust — always SELF_ATTESTED
# ---------------------------------------------------------------------------


def test_attestation_is_self_attested() -> None:
    record = build_local_terminal_record(
        outcome=ExecutionOutcome.SUCCEEDED,
        exit_code=0,
        outputs=(capture_bounded_output(b"x"),),
        execution_instance="test",
    )
    assert record.attestation_trust == GuardExecutionAttestationTrust.SELF_ATTESTED


# ---------------------------------------------------------------------------
# cleanup_complete — binding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [True, False])
def test_cleanup_complete_is_bound(value: bool) -> None:
    record = build_local_terminal_record(
        outcome=ExecutionOutcome.SUCCEEDED,
        exit_code=0,
        outputs=(capture_bounded_output(b"x"),),
        cleanup_complete=value,
        execution_instance="test",
    )
    assert record.cleanup_complete is value


# ---------------------------------------------------------------------------
# Consistency — byte counts and digests match outputs
# ---------------------------------------------------------------------------


def test_byte_counts_consistent_with_outputs() -> None:
    data = b"X" * 500
    outputs = (capture_bounded_output(data, stream="stdout"),)
    record = build_local_terminal_record(
        outcome=ExecutionOutcome.SUCCEEDED,
        exit_code=0,
        outputs=outputs,
        execution_instance="test",
    )
    bc_map = {k: v for k, v in record.stream_byte_counts}
    assert bc_map["stdout"] == len(data)


def test_digests_consistent_with_outputs() -> None:

    data = b"Y" * 300
    outputs = (capture_bounded_output(data, stream="stderr"),)
    record = build_local_terminal_record(
        outcome=ExecutionOutcome.SUCCEEDED,
        exit_code=0,
        outputs=outputs,
        execution_instance="test",
    )
    d_map = {k: v for k, v in record.stream_digests}
    assert d_map["stderr"] == hashlib.sha256(data).hexdigest()


def test_digest_of_truncated_output_covers_full_original() -> None:

    data = b"Z" * 100_000
    outputs = (capture_bounded_output(data, stream="stdout", max_bytes=1024),)
    record = build_local_terminal_record(
        outcome=ExecutionOutcome.FAILED,
        exit_code=1,
        outputs=outputs,
        execution_instance="trunc-test",
    )
    d_map = {k: v for k, v in record.stream_digests}
    assert d_map["stdout"] == hashlib.sha256(data).hexdigest()
    # The digest covers all 100k bytes even though only 1k was captured.


# ---------------------------------------------------------------------------
# Validation failures
# ---------------------------------------------------------------------------


def test_build_requires_nonempty_execution_instance() -> None:
    with pytest.raises(ValueError, match="execution_instance"):
        build_local_terminal_record(
            outcome=ExecutionOutcome.SUCCEEDED,
            exit_code=0,
            outputs=(capture_bounded_output(b"x"),),
            execution_instance="",
        )


def test_build_outputs_must_be_tuple() -> None:
    with pytest.raises(TypeError, match="outputs must be a tuple"):
        build_local_terminal_record(
            outcome=ExecutionOutcome.SUCCEEDED,
            exit_code=0,
            outputs=[capture_bounded_output(b"x")],  # type: ignore[arg-type]
            execution_instance="test",
        )


def test_build_outcome_must_be_execution_outcome() -> None:
    with pytest.raises(TypeError, match="outcome must be"):
        build_local_terminal_record(
            outcome="succeeded",  # type: ignore[arg-type]
            exit_code=0,
            outputs=(capture_bounded_output(b"x"),),
            execution_instance="test",
        )


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


def test_local_terminal_record_is_immutable() -> None:
    record = build_local_terminal_record(
        outcome=ExecutionOutcome.SUCCEEDED,
        exit_code=0,
        outputs=(capture_bounded_output(b"x"),),
        execution_instance="test",
    )
    with pytest.raises(AttributeError):
        record.outcome = ExecutionOutcome.FAILED


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_build_with_declared_output_digests() -> None:
    """Extra declared_output_digests are accepted and stored."""
    outputs = (capture_bounded_output(b"data"),)
    record = build_local_terminal_record(
        outcome=ExecutionOutcome.SUCCEEDED,
        exit_code=0,
        outputs=outputs,
        declared_output_digests=("a" * 64,),
        execution_instance="test",
    )
    # declared_output_digests is stored on LocalTerminalRecord
    assert record.declared_output_digests == ("a" * 64,)


class TestReviewFixes:
    def test_builder_requires_execution_instance(self) -> None:
        from codex_plugin_scanner.guard.runtime.execution_assurance_contract import ExecutionOutcome
        from codex_plugin_scanner.guard.runtime.local_output_review import capture_bounded_output
        from codex_plugin_scanner.guard.runtime.local_terminal_record import build_local_terminal_record

        try:
            build_local_terminal_record(
                outcome=ExecutionOutcome.SUCCEEDED,
                exit_code=0,
                outputs=(capture_bounded_output(b"x"),),
                cleanup_complete=True,
            )
        except TypeError:
            return
        raise AssertionError("execution_instance must be required")

    def test_duplicate_stream_keys_rejected(self) -> None:
        from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
            ExecutionOutcome,
            GuardExecutionAttestationTrust,
        )
        from codex_plugin_scanner.guard.runtime.local_terminal_record import LocalTerminalRecord

        with __import__("pytest").raises(ValueError, match="duplicate stream"):
            LocalTerminalRecord(
                outcome=ExecutionOutcome.SUCCEEDED,
                exit_code=0,
                stream_byte_counts=(("stdout", 1), ("stdout", 2)),
                stream_digests=(("stdout", "a" * 64),),
                truncated=False,
                declared_output_digests=(),
                cleanup_complete=True,
                execution_instance="i1",
                attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
            )

    def test_non_self_attested_rejected(self) -> None:
        from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
            ExecutionOutcome,
            GuardExecutionAttestationTrust,
        )
        from codex_plugin_scanner.guard.runtime.local_terminal_record import LocalTerminalRecord

        with __import__("pytest").raises(ValueError, match="SELF_ATTESTED"):
            LocalTerminalRecord(
                outcome=ExecutionOutcome.SUCCEEDED,
                exit_code=0,
                stream_byte_counts=(),
                stream_digests=(),
                truncated=False,
                declared_output_digests=(),
                cleanup_complete=True,
                execution_instance="i1",
                attestation_trust=GuardExecutionAttestationTrust.VERIFIED,
            )
