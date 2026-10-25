"""The shipped catalog's risk classes, and what the activity record claims for one this vocabulary does not name."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.command_activity_lifecycle import _activity_match
from codex_plugin_scanner.guard.runtime.command_evaluation_types import (
    CommandRuleMatch,
    OwnedCommandRuleMatch,
)
from codex_plugin_scanner.guard.runtime.command_risk_effects import COMMAND_RISK_EFFECTS
from codex_plugin_scanner.guard.runtime.effect_contract import EffectKind
from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import (
    load_generated_command_catalog,
)

# Every risk class the packaged catalog ships that `COMMAND_RISK_EFFECTS` does
# not name. The catalog is authored outside this table, so the gap is expected;
# pinning it means a newly shipped class is a decision someone makes rather than
# one the fallback quietly absorbs. Map a class and drop it from here.
UNMAPPED_SHIPPED_RISK_CLASSES = frozenset(
    {
        "credential_access",
        "permission_change",
        "remote_execution",
    }
)


def _shipped_risk_classes() -> frozenset[str]:
    catalog = load_generated_command_catalog()
    classes: set[str] = set()
    for extension in catalog.extensions:
        classes.update(extension.risk_classes)
        for rule in extension.rules:
            classes.update(rule.risk_classes)
    return frozenset(classes)


def test_the_packaged_catalog_ships_exactly_the_recorded_unmapped_classes() -> None:
    assert _shipped_risk_classes() - set(COMMAND_RISK_EFFECTS) == UNMAPPED_SHIPPED_RISK_CLASSES


def _owned(rule_id: str) -> OwnedCommandRuleMatch:
    catalog = load_generated_command_catalog()
    for extension in catalog.extensions:
        for rule in extension.rules:
            if rule.rule_id == rule_id:
                return OwnedCommandRuleMatch(
                    extension=extension,
                    match=CommandRuleMatch(rule=rule, action_class=None, reason="probe", command=None),
                )
    raise AssertionError(f"{rule_id} is not in the packaged catalog")


@pytest.mark.parametrize(
    ("rule_id", "claimed"),
    [
        # `credential_access` and `permission_change` are unmapped, so each rule
        # claims only the fallback beside its mapped `network_egress`.
        ("command.cloud.digitalocean.credential-exposure", {EffectKind.NETWORK_WRITE, EffectKind.PROCESS_EXECUTION}),
        ("command.cloud.digitalocean.access-change", {EffectKind.NETWORK_WRITE, EffectKind.PROCESS_EXECUTION}),
        ("command.cloud.digitalocean.remote-execution", {EffectKind.NETWORK_WRITE, EffectKind.PROCESS_EXECUTION}),
    ],
)
def test_a_shipped_rule_with_an_unmapped_class_still_builds_its_record(rule_id: str, claimed: set[EffectKind]) -> None:
    match = _activity_match("activity:01", 0, _owned(rule_id))
    assert match.effect_claims == frozenset(claimed)
    assert match.identity.rule_id == rule_id


def test_the_fallback_is_reached_only_through_a_class_the_table_omits() -> None:
    """The record above claims `process-execution` because its class is unmapped.

    The decision plane claims the same beside it, and pins that half itself
    (`effect_claims_answer_for_a_risk_class_the_vocabulary_does_not_name`,
    command_decision_adapter.rs): a Python-only assertion here would still
    pass if the Rust table or its fallback changed on its own.
    """

    owned = _owned("command.cloud.digitalocean.credential-exposure")
    assert set(owned.match.rule.risk_classes) - set(COMMAND_RISK_EFFECTS) == {"credential_access"}
    assert set(owned.match.rule.risk_classes) & set(COMMAND_RISK_EFFECTS) == {"network_egress"}
    assert COMMAND_RISK_EFFECTS["network_egress"] == frozenset({EffectKind.NETWORK_WRITE})
    assert _activity_match("activity:02", 0, owned).effect_claims == frozenset(
        {EffectKind.NETWORK_WRITE, EffectKind.PROCESS_EXECUTION}
    )


def test_every_mapped_class_names_exactly_one_effect() -> None:
    """Rust holds the same table as `Option<EffectKind>`, one kind per class.

    A class mapped to two kinds would still build a Python record and have no
    faithful Rust spelling, so the shape is pinned where it can be seen rather
    than left to the next person to notice.
    """

    assert {name: len(effects) for name, effects in COMMAND_RISK_EFFECTS.items()} == dict.fromkeys(
        COMMAND_RISK_EFFECTS, 1
    )
