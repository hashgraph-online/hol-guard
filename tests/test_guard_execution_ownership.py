"""Tests for execution-ownership grading and enforcement."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.execution_ownership import (
    _DELEGABLE_GRADES,
    _WEAK_GRADES,
    ExecutionOwnershipGrade,
    resolve_execution_ownership,
)

# ── Enum completeness ─────────────────────────────────────────────────────


class TestEnumCompleteness:
    """ExecutionOwnershipGrade has the expected members."""

    def test_all_five_members(self) -> None:
        members = set(ExecutionOwnershipGrade)
        assert members == {
            ExecutionOwnershipGrade.GUARD_OWNED_LOCAL,
            ExecutionOwnershipGrade.DELEGABLE_REMOTE_AUTHENTICATED,
            ExecutionOwnershipGrade.DECISION_ONLY,
            ExecutionOwnershipGrade.DEGRADED_OBSERVE_ONLY,
            ExecutionOwnershipGrade.UNSUPPORTED,
        }

    def test_expected_values(self) -> None:
        assert ExecutionOwnershipGrade.GUARD_OWNED_LOCAL.value == "guard-owned-local"
        assert ExecutionOwnershipGrade.DELEGABLE_REMOTE_AUTHENTICATED.value == "delegable-remote-authenticated"
        assert ExecutionOwnershipGrade.DECISION_ONLY.value == "decision-only"
        assert ExecutionOwnershipGrade.DEGRADED_OBSERVE_ONLY.value == "degraded-observe-only"
        assert ExecutionOwnershipGrade.UNSUPPORTED.value == "unsupported"


# ── resolve_execution_ownership — can_return_result ──────────────────────


class TestCanReturnResult:
    """When can_return_result is False, grade MUST degrade to DECISION_ONLY."""

    def test_guard_owned_degrades_to_decision_only(self) -> None:
        result = resolve_execution_ownership(
            ExecutionOwnershipGrade.GUARD_OWNED_LOCAL,
            can_return_result=False,
        )
        assert result == ExecutionOwnershipGrade.DECISION_ONLY

    def test_delegable_degrades_to_decision_only(self) -> None:
        result = resolve_execution_ownership(
            ExecutionOwnershipGrade.DELEGABLE_REMOTE_AUTHENTICATED,
            can_return_result=False,
        )
        assert result == ExecutionOwnershipGrade.DECISION_ONLY

    def test_decision_only_stays_decision_only(self) -> None:
        result = resolve_execution_ownership(
            ExecutionOwnershipGrade.DECISION_ONLY,
            can_return_result=False,
        )
        assert result == ExecutionOwnershipGrade.DECISION_ONLY

    def test_degraded_degrades_to_decision_only(self) -> None:
        result = resolve_execution_ownership(
            ExecutionOwnershipGrade.DEGRADED_OBSERVE_ONLY,
            can_return_result=False,
        )
        assert result == ExecutionOwnershipGrade.DECISION_ONLY

    def test_unsupported_degrades_to_decision_only(self) -> None:
        result = resolve_execution_ownership(
            ExecutionOwnershipGrade.UNSUPPORTED,
            can_return_result=False,
        )
        assert result == ExecutionOwnershipGrade.DECISION_ONLY

    def test_guard_owned_can_return_result_keeps_grade(self) -> None:
        result = resolve_execution_ownership(
            ExecutionOwnershipGrade.GUARD_OWNED_LOCAL,
            can_return_result=True,
        )
        assert result == ExecutionOwnershipGrade.GUARD_OWNED_LOCAL

    def test_delegable_can_return_result_keeps_grade(self) -> None:
        result = resolve_execution_ownership(
            ExecutionOwnershipGrade.DELEGABLE_REMOTE_AUTHENTICATED,
            can_return_result=True,
        )
        assert result == ExecutionOwnershipGrade.DELEGABLE_REMOTE_AUTHENTICATED


# ── resolve_execution_ownership — no upgrade path ────────────────────────


class TestNoUpgradePath:
    """Weak grades can never be upgraded to owned/delegable."""

    @pytest.mark.parametrize(
        "weak_grade",
        [
            ExecutionOwnershipGrade.DECISION_ONLY,
            ExecutionOwnershipGrade.DEGRADED_OBSERVE_ONLY,
            ExecutionOwnershipGrade.UNSUPPORTED,
        ],
    )
    def test_weak_grade_no_upgrade_can_return_true(self, weak_grade: ExecutionOwnershipGrade) -> None:
        result = resolve_execution_ownership(weak_grade, can_return_result=True)
        assert result == weak_grade

    @pytest.mark.parametrize(
        "weak_grade",
        [
            ExecutionOwnershipGrade.DECISION_ONLY,
            ExecutionOwnershipGrade.DEGRADED_OBSERVE_ONLY,
            ExecutionOwnershipGrade.UNSUPPORTED,
        ],
    )
    def test_weak_grade_cannot_claim_result(self, weak_grade: ExecutionOwnershipGrade) -> None:
        """Even when can_return_result is True, weak grades stay weak."""
        result = resolve_execution_ownership(weak_grade, can_return_result=True)
        assert result not in _DELEGABLE_GRADES


# ── resolve_execution_ownership — invalid input ──────────────────────────


class TestInvalidInput:
    """Grade validation."""

    def test_non_enum_raises(self) -> None:
        with pytest.raises(ValueError, match="ExecutionOwnershipGrade"):
            resolve_execution_ownership("guard-owned-local")

    def test_int_raises(self) -> None:
        with pytest.raises(ValueError, match="ExecutionOwnershipGrade"):
            resolve_execution_ownership(1)


# ── Delegation constraint ────────────────────────────────────────────────


class TestDelegationConstraint:
    """Only GUARD_OWNED_LOCAL and DELEGABLE_REMOTE_AUTHENTICATED are delegable."""

    def test_guard_owned_is_delegable(self) -> None:
        assert ExecutionOwnershipGrade.GUARD_OWNED_LOCAL in _DELEGABLE_GRADES

    def test_delegable_remote_is_delegable(self) -> None:
        assert ExecutionOwnershipGrade.DELEGABLE_REMOTE_AUTHENTICATED in _DELEGABLE_GRADES

    def test_decision_only_not_delegable(self) -> None:
        assert ExecutionOwnershipGrade.DECISION_ONLY not in _DELEGABLE_GRADES

    def test_degraded_not_delegable(self) -> None:
        assert ExecutionOwnershipGrade.DEGRADED_OBSERVE_ONLY not in _DELEGABLE_GRADES

    def test_unsupported_not_delegable(self) -> None:
        assert ExecutionOwnershipGrade.UNSUPPORTED not in _DELEGABLE_GRADES

    def test_all_weak_grades_non_delegable(self) -> None:
        for weak in _WEAK_GRADES:
            assert weak not in _DELEGABLE_GRADES

    def test_only_two_delegable(self) -> None:
        assert len(_DELEGABLE_GRADES) == 2

    def test_only_three_weak(self) -> None:
        assert len(_WEAK_GRADES) == 3


# ── Edge cases ───────────────────────────────────────────────────────────


class TestEdgeCases:
    """Boundary and edge conditions."""

    def test_default_can_return_result_true(self) -> None:
        """can_return_result defaults to True."""
        result = resolve_execution_ownership(
            ExecutionOwnershipGrade.GUARD_OWNED_LOCAL,
        )
        assert result == ExecutionOwnershipGrade.GUARD_OWNED_LOCAL

    def test_degraded_to_decision_only_chain(self) -> None:
        """Degraded → decision-only when can't return, stays degraded otherwise."""
        assert (
            resolve_execution_ownership(
                ExecutionOwnershipGrade.DEGRADED_OBSERVE_ONLY,
                can_return_result=False,
            )
            == ExecutionOwnershipGrade.DECISION_ONLY
        )
        assert (
            resolve_execution_ownership(
                ExecutionOwnershipGrade.DEGRADED_OBSERVE_ONLY,
                can_return_result=True,
            )
            == ExecutionOwnershipGrade.DEGRADED_OBSERVE_ONLY
        )

    def test_monotonic_no_reversal(self) -> None:
        """Once degraded, cannot go back up — verified by no upgrade path test."""
        # GUARD_OWNED_LOCAL + can_return=False → DECISION_ONLY
        step1 = resolve_execution_ownership(
            ExecutionOwnershipGrade.GUARD_OWNED_LOCAL,
            can_return_result=False,
        )
        # DECISION_ONLY + can_return=True → stays DECISION_ONLY (no upgrade)
        step2 = resolve_execution_ownership(
            step1,
            can_return_result=True,
        )
        assert step2 == ExecutionOwnershipGrade.DECISION_ONLY
        assert step2 != ExecutionOwnershipGrade.GUARD_OWNED_LOCAL


def test_reroute_intent_requires_delegable_grade() -> None:
    from codex_plugin_scanner.guard.runtime.execution_ownership import (
        ExecutionOwnershipGrade,
        resolve_execution_ownership,
    )

    assert (
        resolve_execution_ownership(ExecutionOwnershipGrade.DECISION_ONLY, reroute_to_remote=True)
        is ExecutionOwnershipGrade.DECISION_ONLY
    )
    assert (
        resolve_execution_ownership(ExecutionOwnershipGrade.GUARD_OWNED_LOCAL, reroute_to_remote=True)
        is ExecutionOwnershipGrade.GUARD_OWNED_LOCAL
    )
