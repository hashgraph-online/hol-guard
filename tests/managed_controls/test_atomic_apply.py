from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.atomic_apply import (
    AppliedManagedControls,
    AtomicApplyError,
    AtomicManagedControlsStore,
    PreparedProjection,
)


def _state(revision: int, value: str) -> AppliedManagedControls[str]:
    return AppliedManagedControls(
        revision,
        f"bundle-{revision}",
        "catalog",
        f"effective-{revision}",
        value,
    )


def test_policy_and_extension_projection_commit_together() -> None:
    store = AtomicManagedControlsStore(_state(1, "old"))
    result = store.apply(
        _state(2, "new"),
        validate=lambda _: None,
        compile_projection=lambda _: PreparedProjection(lambda: None, lambda: None),
    )
    assert result.value == "new"
    assert store.last_known_good == result


def test_failed_second_projection_preserves_complete_previous_state() -> None:
    previous = _state(1, "old")
    store = AtomicManagedControlsStore(previous)

    def fail(_: AppliedManagedControls[str]) -> PreparedProjection:
        raise ValueError("compiler failed")

    with pytest.raises(AtomicApplyError):
        store.apply(_state(2, "new"), validate=lambda _: None, compile_projection=fail)
    assert store.current == previous
    assert store.last_known_good == previous


def test_revision_rollback_is_rejected() -> None:
    store = AtomicManagedControlsStore(_state(3, "current"))
    with pytest.raises(AtomicApplyError):
        store.apply(
            _state(2, "old"),
            validate=lambda _: None,
            compile_projection=lambda _: PreparedProjection(lambda: None, lambda: None),
        )


def test_failed_commit_rolls_back_external_projection() -> None:
    previous = _state(1, "old")
    store = AtomicManagedControlsStore(previous)
    external = ["old"]

    def stage(_: AppliedManagedControls[str]) -> PreparedProjection:
        def commit() -> None:
            external.append("partial")
            raise ValueError("second projection failed")

        def rollback() -> None:
            external[:] = ["old"]

        return PreparedProjection(commit, rollback)

    with pytest.raises(AtomicApplyError):
        store.apply(_state(2, "new"), validate=lambda _: None, compile_projection=stage)
    assert external == ["old"]
    assert store.current == previous


def test_initial_negative_revision_is_rejected() -> None:
    with pytest.raises(AtomicApplyError):
        _state(-1, "invalid")


def test_validation_failure_never_stages_or_changes_state() -> None:
    previous = _state(1, "old")
    store = AtomicManagedControlsStore(previous)
    compiled = False

    def reject(_: AppliedManagedControls[str]) -> None:
        raise ValueError("catalog changed")

    def compile_projection(_: AppliedManagedControls[str]) -> PreparedProjection:
        nonlocal compiled
        compiled = True
        return PreparedProjection(lambda: None, lambda: None)

    with pytest.raises(AtomicApplyError, match="apply failed"):
        store.apply(_state(2, "new"), validate=reject, compile_projection=compile_projection)
    assert not compiled
    assert store.current == previous
    assert store.last_known_good == previous


def test_rollback_failure_is_distinct_and_does_not_publish_candidate() -> None:
    previous = _state(1, "old")
    store = AtomicManagedControlsStore(previous)

    def stage(_: AppliedManagedControls[str]) -> PreparedProjection:
        def commit() -> None:
            raise ValueError("commit failed")

        def rollback() -> None:
            raise ValueError("rollback failed")

        return PreparedProjection(commit, rollback)

    with pytest.raises(AtomicApplyError, match="apply and rollback failed"):
        store.apply(_state(2, "new"), validate=lambda _: None, compile_projection=stage)
    assert store.current == previous
    assert store.last_known_good == previous


def test_restore_without_last_known_good_fails_closed() -> None:
    store: AtomicManagedControlsStore[str] = AtomicManagedControlsStore()
    with pytest.raises(AtomicApplyError, match="no last-known-good"):
        store.restore_last_known_good()
