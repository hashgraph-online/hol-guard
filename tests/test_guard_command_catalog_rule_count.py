from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import command_extensions_payload


def test_command_extension_registry_is_deterministic_and_complete() -> None:
    payload = command_extensions_payload()
    ids = [extension["extension_id"] for extension in payload["extensions"]]

    assert ids == sorted(ids)
    assert payload["count"] == len(BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions)
    assert "command.shell-mutations" in ids
    assert "command.ollama" in ids
    assert BUILT_IN_COMMAND_EXTENSION_REGISTRY.for_action_class("destructive shell command") is not None
    assert BUILT_IN_COMMAND_EXTENSION_REGISTRY.rule_for_action_class("destructive shell command") is not None
    assert BUILT_IN_COMMAND_EXTENSION_REGISTRY.for_action_class("GitHub merge command") is not None
    assert BUILT_IN_COMMAND_EXTENSION_REGISTRY.rule_for_action_class("GitHub merge command") is not None
    assert BUILT_IN_COMMAND_EXTENSION_REGISTRY.for_action_class("Ollama model publication command") is not None
    program_path = Path(__file__).resolve().parents[1] / "contracts/extensions/native-command-program.v1.json"
    program = json.loads(program_path.read_bytes())
    expected_ids = [extension["extension_id"] for extension in program["extensions"]]
    assert expected_ids
    assert len(expected_ids) == len(set(expected_ids))
    assert ids == sorted(expected_ids)

    native_rule_ids = [rule["rule_id"] for rule in program["rules"]]
    assert len(native_rule_ids) == len(set(native_rule_ids))
    native_rule_counts = Counter(rule["extension_id"] for rule in program["rules"])
    assert set(native_rule_counts) <= set(expected_ids)
    assert {extension["extension_id"]: extension["rule_count"] for extension in payload["extensions"]} == {
        extension_id: native_rule_counts[extension_id] for extension_id in expected_ids
    }
    assert sum(extension["rule_count"] for extension in payload["extensions"]) == len(native_rule_ids)
