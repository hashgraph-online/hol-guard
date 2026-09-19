"""Executable matchers preserve literal, option, and bounded-parse decisions."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime import command_option_parsing as options
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_rules import ExecutableMatcher


def _matcher(*, conservative: bool = True, required_flags: frozenset[str] = frozenset()) -> ExecutableMatcher:
    return ExecutableMatcher(
        executables=frozenset({"tool"}),
        subcommands=("purge",),
        required_flags=required_flags,
        allow_leading_options=True,
        leading_options_with_values=frozenset({"--profile"}),
        interspersed_options_with_values=frozenset({"--config", "-c"}),
        interspersed_flags=frozenset({"--verbose", "-v"}),
        required_flags_in_all_arguments=True,
        fail_secure_unknown_options=conservative,
    )


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("tool list purge", False),
        ("tool '' purge", False),
        ("tool purge archive", True),
        ("tool PURGE archive", True),
        ("tool -- purge archive", True),
        ("tool -- list purge", False),
        ("tool --config purge list", False),
        ("tool --config value purge", True),
        ("tool --config=value purge", True),
        ("tool --profile value purge", True),
        ("tool --verbose list purge", False),
        ("tool list --config purge", False),
        ("tool list --config=value purge", False),
        ("tool --future value purge", True),
        ("tool --future purge", True),
        ("tool --future=value list purge", False),
        ("tool -vc value purge", True),
        ("tool -vc purge list", False),
        ("tool -xc purge", True),
        ("tool - purge", True),
        ("env MODE=x tool list purge", False),
        ("env MODE=x tool purge", True),
        ("tool list; tool purge", True),
        ("other purge", False),
    ],
)
def test_executable_prefix_retains_option_and_wrapper_semantics(command: str, expected: bool) -> None:
    assert bool(_matcher().match(parse_shell_command(command))) is expected


@pytest.mark.parametrize("budget", [0, 1, 16_384])
@pytest.mark.parametrize("conservative", [False, True])
@pytest.mark.parametrize("command", ["tool list purge", "tool '' purge", "tool"])
def test_literal_mismatch_preserves_exhausted_state_budget(
    monkeypatch: pytest.MonkeyPatch, budget: int, conservative: bool, command: str
) -> None:
    monkeypatch.setattr(options, "_MAX_OPTION_PARSE_STATES", budget)
    expected = conservative and budget == 0
    assert bool(_matcher(conservative=conservative).match(parse_shell_command(command))) is expected


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("tool purge --confirm", True),
        ("tool purge --confirm=false", False),
        ("tool purge --confirm=true", True),
        ("tool list --confirm purge", False),
        ("tool --config=purge list --confirm", False),
        ("tool --config value purge --confirm", True),
        ("tool --future --confirm purge", False),
        ("tool --future=value purge --confirm", True),
    ],
)
def test_prefix_selection_preserves_required_flag_evidence(command: str, expected: bool) -> None:
    assert bool(_matcher(required_flags=frozenset({"--confirm"})).match(parse_shell_command(command))) is expected
