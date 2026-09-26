from __future__ import annotations

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
    assert sum(extension["rule_count"] for extension in payload["extensions"]) == 241
