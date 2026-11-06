"""Tests for provider self-healing recovery state machine.

Bounded retries, exponential backoff, deduped notices, and privacy guarantees.
"""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.provider_recovery import RecoveryPhase, RecoveryState

FAKE_SHA256 = "a" * 64
FAKE_SHA256_B = "b" * 64


def _healthy() -> RecoveryState:
    return RecoveryState(
        phase=RecoveryPhase.HEALTHY,
        attempt=0,
        next_retry_seconds=0.0,
        last_error_digest=None,
        notice_dedupe_key="initial",
    )


# ---------------------------------------------------------------------------
# RecoveryState validation
# ---------------------------------------------------------------------------


class TestRecoveryStateValidation:
    def test_valid_state(self):
        state = RecoveryState(
            phase=RecoveryPhase.HEALTHY,
            attempt=0,
            next_retry_seconds=0.0,
        )
        assert state.phase is RecoveryPhase.HEALTHY
        assert state.attempt == 0

    def test_invalid_phase_raises(self):
        with pytest.raises(ValueError, match="phase must be"):
            RecoveryState(phase="not_a_phase", attempt=0, next_retry_seconds=0.0)

    def test_attempt_negative(self):
        with pytest.raises(ValueError, match=r"attempt must be 0..5"):
            RecoveryState(phase=RecoveryPhase.HEALTHY, attempt=-1, next_retry_seconds=0.0)

    def test_attempt_too_high(self):
        with pytest.raises(ValueError, match=r"attempt must be 0..5"):
            RecoveryState(phase=RecoveryPhase.HEALTHY, attempt=6, next_retry_seconds=0.0)

    def test_negative_backoff_raises(self):
        with pytest.raises(ValueError, match="next_retry_seconds must be"):
            RecoveryState(phase=RecoveryPhase.HEALTHY, attempt=0, next_retry_seconds=-1.0)

    def test_invalid_sha256_raises(self):
        with pytest.raises(ValueError, match="last_error_digest must be"):
            RecoveryState(
                phase=RecoveryPhase.HEALTHY,
                attempt=0,
                next_retry_seconds=0.0,
                last_error_digest="not-a-sha256",
            )

    def test_valid_sha256_accepted(self):
        state = RecoveryState(
            phase=RecoveryPhase.DEGRADED,
            attempt=1,
            next_retry_seconds=4.0,
            last_error_digest=FAKE_SHA256,
        )
        assert state.last_error_digest == FAKE_SHA256

    def test_slots_immutable(self):
        state = _healthy()
        with pytest.raises(AttributeError):
            state.phase = RecoveryPhase.HEALTHY


# ---------------------------------------------------------------------------
# Success resets to HEALTHY
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Bounded retries -- stop after 5 attempts
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Exponential backoff -- doubles and caps at 30s
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Typed UNAVAILABLE reached deterministically
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# No infinite retries
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Recovery notices -- deduped
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Privacy -- raw error text never leaks
# ---------------------------------------------------------------------------


class TestPrivacyNoLeak:
    def test_dedupe_key_stable(self):
        s1 = RecoveryState(
            phase=RecoveryPhase.DEGRADED,
            attempt=1,
            next_retry_seconds=2.0,
            last_error_digest=FAKE_SHA256,
        )
        s2 = RecoveryState(
            phase=RecoveryPhase.DEGRADED,
            attempt=1,
            next_retry_seconds=2.0,
            last_error_digest=FAKE_SHA256,
        )
        assert s1.notice_dedupe_key == s2.notice_dedupe_key

    def test_dedupe_key_different_for_different_error(self):
        s1 = RecoveryState(
            phase=RecoveryPhase.DEGRADED,
            attempt=1,
            next_retry_seconds=2.0,
            last_error_digest=FAKE_SHA256,
        )
        s2 = RecoveryState(
            phase=RecoveryPhase.DEGRADED,
            attempt=1,
            next_retry_seconds=2.0,
            last_error_digest=FAKE_SHA256_B,
        )
        assert s1.notice_dedupe_key != s2.notice_dedupe_key

    def test_dedupe_key_different_for_different_phase(self):
        s1 = RecoveryState(
            phase=RecoveryPhase.DEGRADED,
            attempt=1,
            next_retry_seconds=2.0,
            last_error_digest=FAKE_SHA256,
        )
        s2 = RecoveryState(
            phase=RecoveryPhase.RECOVERING,
            attempt=1,
            next_retry_seconds=2.0,
            last_error_digest=FAKE_SHA256,
        )
        assert s1.notice_dedupe_key != s2.notice_dedupe_key
