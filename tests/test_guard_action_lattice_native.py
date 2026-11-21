"""Lattice composition assertions answered by the native runtime.

Composition rules live in the Rust runtime, so these cases need a compiled
resident and cannot run in an ordinary unit-test checkout. They stay out of
``test_guard_action_lattice.py`` so the rest of the lattice contract keeps
running without ``HOL_GUARD_NATIVE_BINARY``.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.action_lattice import UNKNOWN_GUARD_ACTION_REASON
from codex_plugin_scanner.guard.models import GuardAction


@pytest.mark.parametrize("protected_action", ("require-reapproval", "sandbox-required"))
def test_false_positive_composition_never_lowers_protected_actions(
    protected_action: GuardAction,
    native_signal_composition: Callable[[Sequence[object], object], SimpleNamespace],
) -> None:
    from codex_plugin_scanner.guard.runtime.signals import RiskSignalV2

    false_positive = RiskSignalV2(
        signal_id="fp:source-search:read-only",
        category="false_positive",
        severity="info",
        confidence="strong",
        detector="test",
        title="Read-only search",
        plain_reason="Read-only source search.",
        technical_detail=None,
        evidence_ref=None,
        redaction_level="summary",
        false_positive_hint=None,
        advisory_id=None,
    )

    assert native_signal_composition((false_positive,), protected_action).action == protected_action


def test_signal_composition_normalizes_unknown_base_and_preserves_diagnostics(
    native_signal_composition: Callable[[Sequence[object], object], SimpleNamespace],
) -> None:
    result = native_signal_composition((), "future-action")

    assert result.action == "block"
    assert result.normalization_reason_code == UNKNOWN_GUARD_ACTION_REASON
    assert result.original_action == "future-action"
