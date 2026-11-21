"""Keep reviewed option-token and workflow-trigger boundaries executable."""

from __future__ import annotations

import pytest

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
