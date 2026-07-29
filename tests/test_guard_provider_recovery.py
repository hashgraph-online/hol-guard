"""Tests for provider self-healing recovery state machine.

Bounded retries, exponential backoff, deduped notices, and privacy guarantees.
"""

from __future__ import annotations

import re

import pytest

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import ProviderHealthState
from codex_plugin_scanner.guard.runtime.provider_recovery import (
    RecoveryPhase,
    RecoveryState,
    from_provider_health_state,
    next_recovery_state,
    recovery_notice,
)

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


class TestSuccessResets:
    def test_success_from_healthy_resets(self):
        state = _healthy()
        result = next_recovery_state(state, succeeded=True)
        assert result.phase is RecoveryPhase.HEALTHY
        assert result.attempt == 0
        assert result.next_retry_seconds == 0.0
        assert result.last_error_digest is None

    def test_success_from_degraded_resets(self):
        state = RecoveryState(
            phase=RecoveryPhase.DEGRADED,
            attempt=2,
            next_retry_seconds=8.0,
            last_error_digest=FAKE_SHA256,
        )
        result = next_recovery_state(state, succeeded=True)
        assert result.phase is RecoveryPhase.HEALTHY
        assert result.attempt == 0
        assert result.next_retry_seconds == 0.0
        assert result.last_error_digest is None

    def test_success_from_unavailable_resets(self):
        state = RecoveryState(
            phase=RecoveryPhase.UNAVAILABLE,
            attempt=5,
            next_retry_seconds=30.0,
            last_error_digest=FAKE_SHA256,
        )
        result = next_recovery_state(state, succeeded=True)
        assert result.phase is RecoveryPhase.HEALTHY
        assert result.attempt == 0
        assert result.next_retry_seconds == 0.0
        assert result.last_error_digest is None


# ---------------------------------------------------------------------------
# Bounded retries -- stop after 5 attempts
# ---------------------------------------------------------------------------


class TestBoundedRetries:
    def test_bounded_retries_stop_after_five(self):
        state = _healthy()
        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.attempt == 1

        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.attempt == 2

        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.attempt == 3

        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.attempt == 4

        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.attempt == 5
        assert state.phase is RecoveryPhase.UNAVAILABLE

        # Attempt 6 stays at 5.
        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.attempt == 5
        assert state.phase is RecoveryPhase.UNAVAILABLE

    def test_retries_increase_monotonically(self):
        state = _healthy()
        last = 0
        for _ in range(5):
            state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
            assert state.attempt > last
            last = state.attempt


# ---------------------------------------------------------------------------
# Exponential backoff -- doubles and caps at 30s
# ---------------------------------------------------------------------------


class TestBoundedBackoff:
    def test_backoff_doubles_each_attempt(self):
        state = _healthy()

        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.next_retry_seconds == 2.0  # 2^1

        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.next_retry_seconds == 4.0  # 2^2

        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.next_retry_seconds == 8.0  # 2^3

        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.next_retry_seconds == 16.0  # 2^4

        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.next_retry_seconds == 30.0  # 2^5 = 32 -> capped at 30

    def test_backoff_capped_at_30_seconds(self):
        state = _healthy()
        for _ in range(5):
            state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.next_retry_seconds == 30.0

    def test_success_resets_backoff(self):
        state = _healthy()
        for _ in range(5):
            state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.next_retry_seconds == 30.0

        state = next_recovery_state(state, succeeded=True)
        assert state.next_retry_seconds == 0.0


# ---------------------------------------------------------------------------
# Typed UNAVAILABLE reached deterministically
# ---------------------------------------------------------------------------


class TestTypedUnavailable:
    def test_unavailable_at_attempt_5(self):
        state = _healthy()
        for i in range(5):
            state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
            if i < 4:
                assert state.phase is not RecoveryPhase.UNAVAILABLE
        assert state.phase is RecoveryPhase.UNAVAILABLE

    def test_unavailable_has_correct_attempt(self):
        state = _healthy()
        for _ in range(5):
            state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.attempt == 5

    def test_unavailable_stays_on_extra_failures(self):
        state = _healthy()
        for _ in range(5):
            state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        initial_phase = state.phase

        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.phase is initial_phase
        assert state.attempt == 5

    def test_no_raw_error_text_in_state(self):
        state = _healthy()
        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        digest = state.last_error_digest
        assert digest is not None
        assert len(digest) == 64
        assert re.fullmatch(r"[0-9a-f]{64}", digest)
        assert "raw" not in digest
        assert "error" not in digest.lower()


# ---------------------------------------------------------------------------
# No infinite retries
# ---------------------------------------------------------------------------


class TestNoInfiniteRetries:
    def test_five_failures_then_unavailable(self):
        state = _healthy()
        for _ in range(5):
            state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.phase is RecoveryPhase.UNAVAILABLE

    def test_ten_failures_still_five_attempts(self):
        state = _healthy()
        for _ in range(10):
            state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.attempt == 5
        assert state.phase is RecoveryPhase.UNAVAILABLE


# ---------------------------------------------------------------------------
# Recovery notices -- deduped
# ---------------------------------------------------------------------------


class TestRecoveryNotice:
    def test_first_non_healthy_emits_notice(self):
        state = RecoveryState(
            phase=RecoveryPhase.DEGRADED,
            attempt=1,
            next_retry_seconds=2.0,
        )
        notice = recovery_notice(state, previous=None)
        assert notice is not None
        assert "DEGRADED" in notice

    def test_first_healthy_returns_none(self):
        state = _healthy()
        notice = recovery_notice(state, previous=None)
        assert notice is None

    def test_no_notice_on_same_phase(self):
        state = _healthy()
        notice = recovery_notice(state, previous=state)
        assert notice is None

    def test_notice_on_phase_change(self):
        state = RecoveryState(
            phase=RecoveryPhase.DEGRADED,
            attempt=1,
            next_retry_seconds=2.0,
        )
        notice = recovery_notice(state, previous=_healthy())
        assert notice is not None
        assert "DEGRADED" in notice

    def test_no_duplicate_notice_on_same_phase(self):
        degraded = RecoveryState(
            phase=RecoveryPhase.DEGRADED,
            attempt=1,
            next_retry_seconds=2.0,
        )
        notice1 = recovery_notice(degraded, previous=_healthy())
        assert notice1 is not None
        # Same phase as current state -- no new notice.
        notice2 = recovery_notice(degraded, previous=degraded)
        assert notice2 is None

    def test_notice_on_different_error_same_phase(self):
        degraded = RecoveryState(
            phase=RecoveryPhase.DEGRADED,
            attempt=1,
            next_retry_seconds=2.0,
            last_error_digest=FAKE_SHA256,
        )
        degraded_b = RecoveryState(
            phase=RecoveryPhase.DEGRADED,
            attempt=1,
            next_retry_seconds=2.0,
            last_error_digest=FAKE_SHA256_B,
        )
        notice1 = recovery_notice(degraded, previous=_healthy())
        assert notice1 is not None
        # Same phase but different error -> dedupe key differs -> notice emitted
        notice2 = recovery_notice(degraded_b, previous=degraded)
        assert notice2 is not None

    def test_notice_contains_attempt_count(self):
        state = _healthy()
        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        notice = recovery_notice(state, previous=_healthy())
        assert notice is not None
        assert "attempt" in notice
        assert "1" in notice

    def test_unavailable_notice_text(self):
        state = _healthy()
        for _ in range(5):
            state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        notice = recovery_notice(state, previous=_healthy())
        assert notice is not None
        assert "UNAVAILABLE" in notice
        assert "attempt" in notice

    def test_healthy_notice_on_recovery(self):
        state = _healthy()
        for _ in range(5):
            state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        state = next_recovery_state(state, succeeded=True)
        unavailable = RecoveryState(
            phase=RecoveryPhase.UNAVAILABLE,
            attempt=5,
            next_retry_seconds=30.0,
            last_error_digest=FAKE_SHA256,
        )
        notice = recovery_notice(state, previous=unavailable)
        assert notice is not None
        assert "HEALTHY" in notice or "recovered" in notice.lower()


# ---------------------------------------------------------------------------
# Privacy -- raw error text never leaks
# ---------------------------------------------------------------------------


class TestPrivacyNoLeak:
    def test_error_digest_not_raw_text(self):
        state = _healthy()
        state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        digest = state.last_error_digest
        assert digest is not None
        assert len(digest) == 64
        assert re.fullmatch(r"[0-9a-f]{64}", digest)
        assert "failed" not in digest
        assert "/some" not in digest
        assert "/tmp" not in digest
        assert ".env" not in digest

    def test_notice_contains_no_sensitive_data(self):
        state = _healthy()
        for _ in range(5):
            state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        notice = recovery_notice(state, previous=_healthy())
        assert notice is not None
        for pattern in ["/tmp/", "/home/", "/var/", ".env", "secret", "password", "token"]:
            assert pattern not in notice.lower()

    def test_notice_is_typed_not_raw(self):
        state = _healthy()
        for _ in range(3):
            state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        notice = recovery_notice(state, previous=_healthy())
        assert notice is not None
        assert state.phase.value.upper() in notice

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

    def test_full_recovery_cycle(self):
        state = _healthy()
        assert state.phase is RecoveryPhase.HEALTHY

        for _ in range(5):
            state = next_recovery_state(state, succeeded=False, error_digest=FAKE_SHA256)
        assert state.phase is RecoveryPhase.UNAVAILABLE
        assert state.attempt == 5

        state = next_recovery_state(state, succeeded=True)
        assert state.phase is RecoveryPhase.HEALTHY
        assert state.attempt == 0
        assert state.next_retry_seconds == 0.0
        assert state.last_error_digest is None


def test_all_health_states_map_to_a_recovery_phase() -> None:
    for state in ProviderHealthState:
        phase = from_provider_health_state(state)
        assert phase in set(RecoveryPhase)
