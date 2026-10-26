"""Authenticated ownership cannot extend to altered command execution fields."""

from copy import deepcopy

import pytest

from codex_plugin_scanner.guard.codex_hook_inventory import enumerate_codex_hooks
from codex_plugin_scanner.guard.codex_hook_registration import remove_manifest_bound_hook_events


@pytest.mark.parametrize(
    "changes",
    (
        {},
        {"command": "python bridge.py --unexpected"},
        {"statusMessage": "changed"},
        {"timeout": 99},
        {"env": {"GUARD_TEST_FIELD": "changed"}},
    ),
)
def test_inventory_and_replacement_require_exact_authenticated_handler(tmp_path, changes):
    expected_handler = {"type": "command", "command": "python bridge.py", "statusMessage": "original"}
    expected_group = {"matcher": "Bash", "hooks": [expected_handler]}
    binding = {"event": "PreToolUse", "group": expected_group, "handler": expected_handler}
    actual_group = deepcopy(expected_group)
    actual_group["hooks"][0].update(changes)
    hooks = {"PreToolUse": [actual_group]}
    inventory = enumerate_codex_hooks(
        {"hooks": hooks},
        source_path=tmp_path / "config.toml",
        source_scope="user",
        source_format="toml",
        source_hooks_enabled=True,
        authenticated_bindings=(binding,),
    )
    assert len(inventory.records) == 1
    assert inventory.records[0].ownership == ("unmanaged" if changes else "authenticated_manifest")
    remaining, removed = remove_manifest_bound_hook_events(hooks, (binding,))
    assert removed is (not bool(changes))
    assert remaining == (hooks if changes else {})
