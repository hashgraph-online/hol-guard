"""Keep reviewed option-token and workflow-trigger boundaries executable."""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path

import pytest
import yaml

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.source_oclif import _flag_names


@pytest.mark.parametrize(
    ("name", "fields"),
    [
        ("foo.bar", {}),
        ("foo+bar", {}),
        ("foo", {"aliases": ["foo.bar"]}),
        ("foo", {"aliases": ["foo+bar"]}),
        ("foo", {"charAliases": ["xy"]}),
        ("foo", {"char": "xy"}),
        ("x" * 63, {}),
        ("x" * 60, {"type": "boolean", "allowNo": True}),
        ("foo", {"aliases": ["é"]}),
        ("foo", {"char": 7}),
    ],
)
def test_oclif_rejects_invalid_options_before_grammar_assembly(name: str, fields: dict[str, object]) -> None:
    with pytest.raises(BuilderError):
        _flag_names(name, fields)


def test_oclif_keeps_valid_prefixed_aliases_and_one_character_short_options() -> None:
    names = _flag_names(
        "foo_bar",
        {
            "type": "boolean",
            "char": "Q",
            "aliases": ["quiet_mode", "q"],
            "charAliases": ["V"],
            "allowNo": True,
        },
    )
    assert names == ("--foo_bar", "-Q", "--quiet_mode", "-q", "-V", "--no-foo_bar")


@pytest.mark.parametrize(
    "changed_path",
    [
        "tests/test_guard_extension_contribution.py",
        "tests/test_guard_extension_trust.py",
        "tests/test_guard_mcp_server_contribution.py",
        "tests/guard_command_decision_diff.py",
        "tests/guard_command_decision_diff_runner.py",
        "tests/guard_command_corpus_oracle.py",
        "tests/fixtures/guard-command-corpus/seed-manifest.json",
        "scripts/release/stage_guard_cloud_review_artifacts.py",
        "contracts/mcp-servers/contribution.v1.schema.json",
        "contributions/mcp-servers/mcp.filesystem.json",
        "src/codex_plugin_scanner/guard/runtime/command_path_set_matcher.py",
    ],
)
def test_direct_authoring_validation_inputs_trigger_the_workflow(changed_path: str) -> None:
    root = Path(__file__).resolve().parents[1]
    document = yaml.safe_load((root / ".github/workflows/extension-builder-ci.yml").read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    # PyYAML's YAML 1.1 loader interprets the Actions key "on" as Boolean True.
    triggers = document.get("on", document.get(True))
    assert isinstance(triggers, dict)
    patterns = triggers["pull_request"]["paths"]
    assert any(fnmatchcase(changed_path, pattern) for pattern in patterns)
