"""Exact Python composition expectations for the native policy snapshot."""

from __future__ import annotations

from codex_plugin_scanner.guard.native_policy_snapshot import _merge_effective_native_policies
from tests.native_policy_snapshot_test_fixtures import _config


def test_python_snapshot_composition_preserves_exact_floors() -> None:
    allow = {**_config(), "default_action": "allow", "mode": "enforce"}
    review = {**_config(), "default_action": "review", "mode": "prompt"}
    block = {**_config(), "default_action": "block", "mode": "enforce"}
    observe = {**_config(), "mode": "observe", "default_action": "block"}
    unknown = {**_config(), "unknown_publisher_action": "block"}
    changed = {**_config(), "changed_hash_action": "block"}

    merged_allow_block = _merge_effective_native_policies((allow, block))
    assert merged_allow_block["default_action"] == "block"
    assert merged_allow_block["mode"] == "enforce"

    merged_review = _merge_effective_native_policies((allow, review))
    assert merged_review["default_action"] == "review"
    assert merged_review["mode"] == "enforce"

    merged_observe = _merge_effective_native_policies((observe, allow))
    assert merged_observe["mode"] == "enforce"
    assert merged_observe["default_action"] == "block"
    publisher = _merge_effective_native_policies((unknown, changed))
    assert publisher["unknown_publisher_action"] == "block"
    assert publisher["changed_hash_action"] == "block"
