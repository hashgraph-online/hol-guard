from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.network_legacy_config import migrate_new_network_domain_action
from codex_plugin_scanner.guard.runtime.network_policy_contract import NetworkAction
from codex_plugin_scanner.guard.runtime.network_status import build_network_status


@pytest.mark.parametrize(
    ("legacy", "expected", "sandbox_required"),
    (
        ("allow", NetworkAction.ALLOW, False),
        ("warn", NetworkAction.APPROVE, False),
        ("review", NetworkAction.APPROVE, False),
        ("require-reapproval", NetworkAction.APPROVE, False),
        ("sandbox-required", NetworkAction.DENY, True),
        ("block", NetworkAction.DENY, False),
    ),
)
def test_legacy_domain_action_migrates_once_into_network_policy_intent(
    legacy: GuardAction,
    expected: NetworkAction,
    sandbox_required: bool,
) -> None:
    migrated = migrate_new_network_domain_action(legacy)

    assert migrated.action is expected
    assert migrated.sandbox_required is sandbox_required


def test_network_status_bridges_live_legacy_config_into_policy_intent() -> None:
    status = build_network_status((), legacy_domain_action="sandbox-required")

    assert status["legacy_domain_policy"] == {
        "action": NetworkAction.DENY.value,
        "sandbox_required": True,
    }
