"""Contract tests for the canonical Guard action lattice."""

from __future__ import annotations

from itertools import product
from typing import get_args

import pytest

from codex_plugin_scanner.guard.action_lattice import (
    GUARD_ACTION_LATTICE,
    GUARD_ACTION_SEVERITY,
    UNKNOWN_GUARD_ACTION_REASON,
    guard_action_severity,
    most_restrictive_guard_action,
    normalize_guard_action,
    normalize_guard_action_result,
)
from codex_plugin_scanner.guard.cli.commands_hook_runtime_eval import _requested_policy_action_normalization
from codex_plugin_scanner.guard.config import (
    GuardConfig,
    _coerce_action_map,
    _coerce_risk_action_map,
    load_guard_config,
)
from codex_plugin_scanner.guard.mdm.policy import _merge_strongest_actions, _strongest_security_value
from codex_plugin_scanner.guard.models import GUARD_ACTION_VALUES, GuardAction
from codex_plugin_scanner.guard.policy.engine import decide_action
from codex_plugin_scanner.guard.policy.engine import guard_action_severity as policy_engine_action_severity
from codex_plugin_scanner.guard.proxy.runtime_mcp import _guard_action, _most_restrictive_package_policy_action
from codex_plugin_scanner.guard.receipts.manager import _resolve_policy_decision
from codex_plugin_scanner.guard.runtime.composition_rules import compose_action_from_signals
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import PackageRequestEvaluation

EXPECTED_LATTICE: tuple[GuardAction, ...] = (
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
)


def test_lattice_is_exhaustive_ordered_and_contiguous() -> None:
    assert GUARD_ACTION_LATTICE == EXPECTED_LATTICE
    assert frozenset(GUARD_ACTION_LATTICE) == frozenset(GUARD_ACTION_VALUES)
    assert frozenset(GUARD_ACTION_LATTICE) == frozenset(get_args(GuardAction))
    assert tuple(GUARD_ACTION_SEVERITY.values()) == tuple(range(len(EXPECTED_LATTICE)))


@pytest.mark.parametrize(("left", "right"), product(EXPECTED_LATTICE, repeat=2))
def test_most_restrictive_composition_is_commutative_for_every_valid_pair(
    left: GuardAction,
    right: GuardAction,
) -> None:
    expected = max((left, right), key=EXPECTED_LATTICE.index)

    assert most_restrictive_guard_action(left, right) == expected
    assert most_restrictive_guard_action(right, left) == expected
    assert _merge_strongest_actions(left, right) == expected
    assert _strongest_security_value(left, right) == expected


def test_most_restrictive_composition_is_idempotent_and_associative() -> None:
    for first, second, third in product(EXPECTED_LATTICE, repeat=3):
        assert most_restrictive_guard_action(first, first) == first
        assert most_restrictive_guard_action(most_restrictive_guard_action(first, second), third) == (
            most_restrictive_guard_action(first, most_restrictive_guard_action(second, third))
        )


@pytest.mark.parametrize("weaker", ("allow", "warn", "review", "require-reapproval"))
def test_sandbox_required_cannot_be_downgraded_by_package_or_managed_composition(weaker: GuardAction) -> None:
    assert _most_restrictive_package_policy_action("sandbox-required", weaker) == "sandbox-required"
    assert _most_restrictive_package_policy_action(weaker, "sandbox-required") == "sandbox-required"
    assert _merge_strongest_actions("sandbox-required", weaker) == "sandbox-required"
    assert _strongest_security_value(weaker, "sandbox-required") == "sandbox-required"


@pytest.mark.parametrize("value", ("future-action", "", None, 7, False, {"action": "allow"}))
def test_unknown_inputs_fail_closed_with_stable_diagnostics(value: object) -> None:
    result = normalize_guard_action_result(value)

    assert result.action == "review"
    assert result.reason_code == UNKNOWN_GUARD_ACTION_REASON
    assert result.original_action == (value if isinstance(value, str) else None)
    assert result.original_type == type(value).__name__
    assert result.recognized is False
    assert guard_action_severity(value) == GUARD_ACTION_SEVERITY["review"]


def test_unknown_action_never_loses_to_allow_or_warn() -> None:
    assert most_restrictive_guard_action("future-action", "allow") == "review"
    assert most_restrictive_guard_action("warn", "future-action") == "review"
    assert _most_restrictive_package_policy_action("allow", "future-action") == "review"
    assert _most_restrictive_package_policy_action("future-action", "warn") == "review"
    assert _merge_strongest_actions("sandbox-required", "future-action") == "block"
    assert _merge_strongest_actions(None, "future-action") == "block"


def test_policy_engine_present_unknown_actions_do_not_fall_through_to_allow(tmp_path) -> None:
    config = GuardConfig(guard_home=tmp_path / "guard", workspace=None, default_action="allow")

    assert decide_action("future-action", "allow", config, changed=False) == "require-reapproval"
    assert decide_action(None, "future-action", config, changed=False) == "require-reapproval"


@pytest.mark.parametrize("payload_action", ("future-action", "", None, 7))
def test_runtime_hook_present_unknown_action_normalizes_with_diagnostics(payload_action: object) -> None:
    result = _requested_policy_action_normalization(None, None, {"policy_action": payload_action})

    assert result is not None
    assert result.action == "require-reapproval"
    assert result.reason_code == UNKNOWN_GUARD_ACTION_REASON
    assert result.original_action == (payload_action if isinstance(payload_action, str) else None)


def test_runtime_hook_absent_action_preserves_computed_policy_fallback() -> None:
    assert _requested_policy_action_normalization(None, None, {}) is None


def test_runtime_policy_and_receipt_boundaries_share_canonical_normalization() -> None:
    assert normalize_guard_action("sandbox-required") == "sandbox-required"
    assert _guard_action("sandbox-required") == "sandbox-required"
    assert policy_engine_action_severity("sandbox-required") == GUARD_ACTION_SEVERITY["sandbox-required"]
    assert policy_engine_action_severity("future-action") == GUARD_ACTION_SEVERITY["review"]
    assert _resolve_policy_decision("future-action") == "require-reapproval"


def test_unknown_fallback_must_itself_be_a_known_action() -> None:
    with pytest.raises(ValueError, match="unknown_action is not a GuardAction"):
        normalize_guard_action("future-action", unknown_action="future-fallback")  # type: ignore[arg-type]


@pytest.mark.parametrize("cached_action", (None, "", "future-action", 7))
def test_cached_package_actions_fail_closed_and_keep_diagnostics(cached_action: object) -> None:
    payload: dict[str, object] = {
        "decision": "monitor",
        "policy_action": cached_action,
        "reasons": [],
        "packages": [],
        "risk_summary": "cached evaluation",
        "user_copy": {
            "title": "Cached package",
            "summary": "Cached package evaluation.",
            "harness_message": "Cached package evaluation.",
        },
    }

    evaluation = PackageRequestEvaluation.from_cache_dict(
        payload,
        package_intent_hash="sha256:intent",
        policy_version="policy-v1",
        bundle_version=None,
        workspace_fingerprint=None,
    )

    assert evaluation.policy_action == "require-reapproval"
    assert evaluation.reasons[-1]["code"] == UNKNOWN_GUARD_ACTION_REASON
    assert evaluation.reasons[-1]["original_action"] == (cached_action if isinstance(cached_action, str) else None)
    assert "Review this request in HOL Guard" in evaluation.user_copy.harness_message


def test_present_invalid_local_config_actions_do_not_fall_back_to_warn(tmp_path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(
        'default_action = "future-action"\nsubprocess_action = "future-action"\n',
        encoding="utf-8",
    )

    config = load_guard_config(guard_home)

    assert config.default_action == "require-reapproval"
    assert config.subprocess_action == "require-reapproval"


@pytest.mark.parametrize("invalid_value", (None, 7, False, {}, {"action": None}, {"default_action": 7}))
def test_present_invalid_action_map_values_do_not_disappear(invalid_value: object) -> None:
    assert _coerce_action_map({"codex": invalid_value}) == {"codex": "require-reapproval"}
    assert _coerce_risk_action_map({"network_egress": invalid_value}) == {"network_egress": "require-reapproval"}


@pytest.mark.parametrize("protected_action", ("require-reapproval", "sandbox-required"))
def test_false_positive_composition_never_lowers_protected_actions(protected_action: GuardAction) -> None:
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

    assert compose_action_from_signals((false_positive,), protected_action).action == protected_action


def test_signal_composition_normalizes_unknown_base_and_preserves_diagnostics() -> None:
    result = compose_action_from_signals((), "future-action")

    assert result.action == "block"
    assert result.normalization_reason_code == UNKNOWN_GUARD_ACTION_REASON
    assert result.original_action == "future-action"
