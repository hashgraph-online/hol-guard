from __future__ import annotations

import pytest

from tests.managed_controls.operations import (
    ManagedControlsHealth,
    ManagedControlsPerformanceBudget,
    health_snapshot,
)


def test_performance_budgets_are_explicit_and_enforced() -> None:
    budget = ManagedControlsPerformanceBudget()
    budget.assert_within("atomic_apply", 499)
    with pytest.raises(ValueError):
        budget.assert_within("atomic_apply", 501)


def test_invalid_authority_has_one_actionable_recovery_path() -> None:
    snapshot = health_snapshot(
        authority_valid=False,
        supported=True,
        last_successful_revision=4,
        catalog_digest="catalog",
    )
    assert snapshot.health is ManagedControlsHealth.RECOVERY_REQUIRED
    assert snapshot.recovery_action == "repair_protection"
