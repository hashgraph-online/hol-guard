from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.acknowledgement import (
    AcknowledgementError,
    ManagedControlsAcknowledgement,
    accept_acknowledgement,
)
from codex_plugin_scanner.guard.managed_controls.atomic_apply import (
    AppliedManagedControls,
    AtomicApplyError,
    AtomicManagedControlsStore,
    PreparedProjection,
)
from codex_plugin_scanner.guard.managed_controls.authority import (
    AuthorityMode,
    ControlEffect,
    ControlInstruction,
    compose_control_instructions,
)


def test_contextual_allow_cannot_bypass_managed_extension_block() -> None:
    result = compose_control_instructions(
        (
            ControlInstruction(
                "command.git",
                "push",
                ControlEffect.BLOCK,
                AuthorityMode.MANAGED_RESTRICTIVE,
                "managed",
            ),
            ControlInstruction(
                "command.git",
                "push",
                ControlEffect.PERMIT,
                AuthorityMode.PERSONAL_SHARED,
                "local",
            ),
        )
    )
    assert result.effect is ControlEffect.BLOCK


def test_partial_apply_and_revision_rollback_fail_closed() -> None:
    original = AppliedManagedControls(2, "bundle", "catalog", "effective", {})
    store = AtomicManagedControlsStore(original)
    with pytest.raises(AtomicApplyError):
        store.apply(
            AppliedManagedControls(3, "new", "catalog", "new-effective", {}),
            validate=lambda _: None,
            compile_projection=lambda _: PreparedProjection(
                lambda: (_ for _ in ()).throw(ValueError("boom")),
                lambda: None,
            ),
        )
    assert store.current == original


def test_conflicting_same_revision_acknowledgement_is_rejected() -> None:
    old = ManagedControlsAcknowledgement(1, "a", "c", "e", 1)
    conflicting = ManagedControlsAcknowledgement(1, "b", "c", "e", 1)
    with pytest.raises(AcknowledgementError):
        accept_acknowledgement(old, conflicting)
