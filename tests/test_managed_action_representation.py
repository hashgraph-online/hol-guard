"""Accepted action encodings cannot erase another origin's stronger choice."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import load_guard_config, resolve_risk_action
from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState
from codex_plugin_scanner.guard.mdm.policy import apply_managed_policy, parse_managed_policy


@pytest.mark.parametrize(
    ("local", "managed"),
    [
        ('"block"', {"action": "allow"}),
        ('{ action = "block" }', "allow"),
        ('"block"', {"default_action": "allow"}),
        ('{ default_action = "block" }', {"action": "allow"}),
    ],
)
@pytest.mark.parametrize(
    "table", ["artifacts", "publishers", "harnesses", "risk_actions", "harness_risk_actions.codex"]
)
@pytest.mark.parametrize("lock", ["table", "selector", "none"])
def test_loaded_cross_origin_encodings_preserve_block(
    tmp_path: Path, local: str, managed: object, table: str, lock: str
) -> None:
    selector = "local_secret_read" if "risk_actions" in table else "codex" if table == "harnesses" else "target"
    (tmp_path / "config.toml").write_text(f'mode="enforce"\ndefault_action="allow"\n[{table}]\n{selector}={local}\n')
    settings = (
        {"harness_risk_actions": {"codex": {selector: managed}}} if "." in table else {table: {selector: managed}}
    )
    policy = parse_managed_policy(
        {
            "schemaVersion": "hol-guard-mdm-policy.v1",
            "settings": settings,
            "lockedSettings": [] if lock == "none" else [table if lock == "table" else f"{table}.{selector}"],
        }
    )
    config = load_guard_config(tmp_path, managed_policy_state=ManagedPolicyState("active", "fixture", policy=policy))
    if "risk_actions" in table:
        actual = resolve_risk_action(config, "local_secret_read", harness="codex")
    else:
        actual = config.resolve_action_override("codex", "target", "target")
    assert actual == "block"


def test_action_metadata_survives_without_becoming_an_action_selector() -> None:
    local = {"artifacts": {"target": {"default_action": "block", "note": "local", "metadata": {"left": 1}}}}
    settings = {"artifacts": {"target": {"action": "allow", "reason": "managed", "metadata": {"right": 2}}}}
    before = deepcopy((local, settings))
    policy = parse_managed_policy(
        {
            "schemaVersion": "hol-guard-mdm-policy.v1",
            "settings": settings,
            "lockedSettings": ["artifacts"],
        }
    )
    result = apply_managed_policy(local, policy)
    assert result["artifacts"] == {
        "target": {
            "action": "block",
            "default_action": "block",
            "note": "local",
            "reason": "managed",
            "metadata": {"left": 1, "right": 2},
        }
    }
    assert (local, settings) == before


@pytest.mark.parametrize("selector", ["action", "default_action"])
def test_selector_names_are_not_mistaken_for_wrapper_fields(selector: str) -> None:
    policy = parse_managed_policy(
        {
            "schemaVersion": "hol-guard-mdm-policy.v1",
            "settings": {"artifacts": {selector: "allow", "other": "warn"}},
            "lockedSettings": ["artifacts"],
        }
    )
    assert apply_managed_policy({"artifacts": {selector: "block"}}, policy)["artifacts"] == {
        selector: "block",
        "other": "warn",
    }


@pytest.mark.parametrize("unrecognized", ["future-action", {"action": "future-action"}, {"unexpected": True}])
def test_unknown_action_encoding_cannot_weaken_a_known_local_action(unrecognized: object) -> None:
    policy = parse_managed_policy(
        {
            "schemaVersion": "hol-guard-mdm-policy.v1",
            "settings": {"artifacts": {"target": unrecognized}},
            "lockedSettings": ["artifacts.target"],
        }
    )
    result = apply_managed_policy({"artifacts": {"target": "warn"}}, policy)["artifacts"]
    assert isinstance(result, dict)
    action = result["target"]
    assert (action.get("action") if isinstance(action, dict) else action) == "block"
