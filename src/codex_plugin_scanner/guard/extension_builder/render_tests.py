"""Generate runnable native contract tests; discovery never executes them."""

from __future__ import annotations

from .models import Discovery
from .python_literals import emit
from .review import Review


def _catalog_tests() -> list[str]:
    return [
        "def test_generated_catalog_is_external_and_off() -> None:",
        "    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_CATALOG_ID)",
        "    assert extension is not None",
        "    payload = extension.to_dict()",
        '    assert payload["trust_class"] == "external"',
        '    assert payload["activation"] == "opt-in"',
        '    assert payload["enabled"] is False',
        "",
        "",
    ]


def render_cli_tests(discovery: Discovery, review: Review) -> str:
    metadata = discovery.metadata
    safe = tuple(
        sorted(" ".join((metadata.executable, *argv)) for _, decision in review.entries for argv in decision.safe_argv)
    )
    blocked = tuple(
        f"{metadata.catalog_id}.{row.operation_id}"
        for row in discovery.operations
        if review.by_id()[row.operation_id].state == "block"
    )
    cases = tuple(
        (" ".join((metadata.executable, *row.path)), f"{metadata.catalog_id}.{row.operation_id}")
        for row in discovery.operations
    )
    lines = [
        '"""Generated native contract cases. These parse strings but never run the target."""',
        "",
        "from __future__ import annotations",
        "",
        "from pathlib import Path",
        "",
        "import pytest",
        "",
        "from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command",
        "from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY",
        "from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command",
        "",
        *emit(metadata.catalog_id, prefix="_CATALOG_ID = "),
        *emit(metadata.executable + " _guard_builder_unknown_", prefix="_UNKNOWN = "),
        *emit(cases, prefix="_CASES = "),
        *(emit(safe, prefix="_SAFE_COMMANDS = ") if safe else []),
        *(emit(blocked, prefix="_BLOCKED_RULES = ") if blocked else []),
        "",
        "",
        *_catalog_tests(),
        '@pytest.mark.parametrize(("command", "rule_id"), _CASES)',
        "def test_generated_inventory_emits_base_evidence(command: str, rule_id: str) -> None:",
        "    observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(parse_shell_command(command))",
        "    assert any(item.rule.rule_id == rule_id and item.matcher_evidence for item in observations)",
        "",
        "",
        "def test_generated_unknown_operation_retains_review() -> None:",
        "    observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(parse_shell_command(_UNKNOWN))",
        '    fallback = next(item for item in observations if item.rule.rule_id == _CATALOG_ID + ".unclassified")',
        "    assert fallback.effective_evidence",
        '    assert fallback.rule.default_mode == "review"',
        "",
        "",
        "def test_generated_extension_is_inert_until_enabled(tmp_path: Path) -> None:",
        "    result = evaluate_command(_UNKNOWN, cwd=tmp_path, home_dir=tmp_path)",
        "    assert all(item.extension.extension_id != _CATALOG_ID for item in result.extension_observations)",
        "",
        "",
        "def test_generated_extension_does_not_match_another_executable() -> None:",
        '    command = parse_shell_command("_guard_builder_unrelated_ status")',
        "    observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(command)",
        "    assert all(item.extension.extension_id != _CATALOG_ID for item in observations)",
        "",
    ]
    if safe:
        lines.extend(
            [
                "",
                '@pytest.mark.parametrize("command", _SAFE_COMMANDS)',
                "def test_generated_reviewed_literals_are_narrow(command: str) -> None:",
                "    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY",
                "    observations = registry.observations(parse_shell_command(command))",
                "    owned = [item for item in observations if item.extension.extension_id == _CATALOG_ID]",
                "    assert owned and all(not item.effective_evidence for item in owned)",
                '    for changed in (command + " --guard-builder-extra", command + "; " + command):',
                "        observations = registry.observations(parse_shell_command(changed))",
                "        owned = [item for item in observations if item.extension.extension_id == _CATALOG_ID]",
                "        assert any(item.effective_evidence for item in owned)",
                "",
            ]
        )
    if blocked:
        lines.extend(
            [
                "",
                '@pytest.mark.parametrize("rule_id", _BLOCKED_RULES)',
                "def test_generated_explicit_blocks_have_no_safe_variants(rule_id: str) -> None:",
                "    rule = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get_rule(rule_id)",
                "    assert rule is not None",
                '    assert rule.default_mode == "enforce"',
                "    assert not rule.safe_variants",
                "",
            ]
        )
    return "\n".join(lines)


def render_mcp_tests(discovery: Discovery, review: Review) -> str:
    decisions = review.by_id()
    cases = tuple((row.name, decisions[row.operation_id].state) for row in discovery.operations)
    return "\n".join(
        [
            '"""Generated MCP contract cases. No server or tool is invoked."""',
            "",
            "from __future__ import annotations",
            "",
            "import pytest",
            "",
            "from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY",
            "from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (",
            "    mcp_payload_for_catalog_id,",
            "    mcp_tool_state,",
            "    validate_mcp_contribution,",
            ")",
            "",
            *emit(discovery.metadata.catalog_id, prefix="_CATALOG_ID = "),
            *emit(cases, prefix="_TOOL_CASES = "),
            "",
            "",
            *_catalog_tests(),
            '@pytest.mark.parametrize(("tool_name", "expected"), _TOOL_CASES)',
            "def test_generated_tool_defaults(tool_name: str, expected: str) -> None:",
            "    payload = mcp_payload_for_catalog_id(_CATALOG_ID)",
            "    assert payload is not None",
            "    validate_mcp_contribution(payload)",
            "    assert mcp_tool_state(payload, tool_name) == expected",
            "",
            "",
            "def test_generated_unknown_tool_inherits() -> None:",
            "    payload = mcp_payload_for_catalog_id(_CATALOG_ID)",
            "    assert payload is not None",
            '    assert mcp_tool_state(payload, "z" * 129) == "inherit"',
            "",
        ]
    )
