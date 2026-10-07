"""Retained reference parsing boundaries; these tests grant no runtime authority."""

import pytest

from codex_plugin_scanner.guard.runtime.command_option_parsing import flags_present_in_all_option_parses


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (("-a", "synthetic"), True),
        (("-asynthetic",), True),
        (("-ja", "synthetic"), True),
        (("-a",), False),
        (("-ja",), False),
        (("-a", "synthetic", "--body"), False),
        (("--body", "-a"), False),
        (("--", "-a", "synthetic"), False),
        (("--future", "-a", "synthetic"), False),
    ],
)
def test_short_value_option_presence_preserves_parse_boundaries(arguments: tuple[str, ...], expected: bool) -> None:
    assert (
        flags_present_in_all_option_parses(
            arguments,
            frozenset({"-a"}),
            options_with_values=frozenset({"-a", "--body"}),
            known_flags=frozenset({"-j"}),
        )
        is expected
    )
