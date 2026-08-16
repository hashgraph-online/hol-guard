from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.cline_hook_payload import prepare_cline_hook_payload

_FIXTURES = Path(__file__).parent / "fixtures" / "cline"


def _fixture(name: str) -> dict[str, object]:
    payload = json.loads((_FIXTURES / name).read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_pinned_cline_version_matrix() -> None:
    matrix = _fixture("version-matrix.json")
    assert matrix["vscode_extension"]["version"] == "4.1.6"  # type: ignore[index]
    assert matrix["vscode_extension"]["tag_commit"] == "81cce3d70e10244cdde40dbd0eb0bb711c93006d"  # type: ignore[index]
    assert matrix["cli"]["version"] == "3.0.51"  # type: ignore[index]
    assert matrix["core"]["version"] == "0.0.71"  # type: ignore[index]
    assert matrix["jetbrains"]["guard_status"] == "detect_only_unverified"  # type: ignore[index]


def test_current_and_compatibility_pretool_fixtures_normalize_equivalently() -> None:
    current = prepare_cline_hook_payload(_fixture("current-pretool.json"))
    legacy = prepare_cline_hook_payload(_fixture("legacy-pretool.json"))

    assert current["hook_event_name"] == legacy["hook_event_name"] == "PreToolUse"
    assert current["tool_name"] == legacy["tool_name"] == "bash"
    current_input = current["tool_input"]
    legacy_input = legacy["tool_input"]
    assert isinstance(current_input, dict) and isinstance(legacy_input, dict)
    assert current_input["command"] == legacy_input["command"] == "printf fixture-safe"


def test_current_and_compatibility_posttool_fixtures_preserve_output() -> None:
    current = prepare_cline_hook_payload(_fixture("current-posttool.json"))
    legacy = prepare_cline_hook_payload(_fixture("legacy-posttool.json"))

    assert current["hook_event_name"] == legacy["hook_event_name"] == "PostToolUse"
    assert current["tool_name"] == legacy["tool_name"] == "read_file"
    assert current["tool_response"] == legacy["tool_response"] == "fixture output"
