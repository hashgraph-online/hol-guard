"""Variable-length authoring sequences retain immutable public contracts."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.extension_builder.source_oclif import _command_path


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
