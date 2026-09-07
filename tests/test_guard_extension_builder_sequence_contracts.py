"""Variable-length authoring sequences retain immutable public contracts."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.extension_builder.source_oclif import _command_path
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_reviewed_literal_matcher import ReviewedLiteralCommandMatcher


@pytest.mark.parametrize("separator", ["colon", "space"])
@pytest.mark.parametrize("command_id", ["", "."])
def test_oclif_root_paths_are_empty_immutable_sequences(command_id: str, separator: str) -> None:
    result = _command_path(command_id, separator)
    assert isinstance(result, tuple)
    assert not result


@pytest.mark.parametrize(
    ("command_id", "separator", "expected"),
    [
        ("version", "colon", ("version",)),
        ("version", "space", ("version",)),
        ("items:list", "colon", ("items:list",)),
        ("items:list", "space", ("items", "list")),
        ("items:settings:list", "space", ("items", "settings", "list")),
    ],
)
def test_oclif_paths_keep_the_configured_token_boundaries(
    command_id: str, separator: str, expected: tuple[str, ...]
) -> None:
    result = _command_path(command_id, separator)
    assert isinstance(result, tuple)
    assert result == expected


@pytest.mark.parametrize(
    ("text", "count"),
    [
        ("samplectl items list", 1),
        ("samplectl items list extra", 0),
        ("samplectl items list; otherctl", 0),
        ("samplectl items list > output.txt", 0),
        ("env samplectl items list", 0),
        ("OTHER=value samplectl items list", 0),
        ("samplectl items delete", 0),
        ("otherctl", 0),
    ],
)
def test_literal_evidence_is_an_immutable_sequence_without_relaxing_scope(text: str, count: int) -> None:
    matcher = ReviewedLiteralCommandMatcher("samplectl", ("items", "list"))
    evidence = matcher.match(parse_shell_command(text))
    assert isinstance(evidence, tuple)
    assert len(evidence) == count
