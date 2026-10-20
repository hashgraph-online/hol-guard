"""A system `timeout` bounds the run; the program it wraps is what runs."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.contained_command_prefix import peel_timeout_clock


def test_a_system_clock_is_peeled_to_the_program_it_bounds() -> None:
    for command, seconds in [
        (["timeout", "20", "pytest", "-q"], 20),
        (["timeout", "--", "20", "pytest", "-q"], 20),
        (["timeout", "5m", "pytest", "-q"], 300),
        (["timeout", "1.5", "pytest", "-q"], 2),
        (["timeout", "2h", "pytest", "-q"], 7200),
        (["/usr/bin/timeout", "30", "pytest", "-q"], 30),
        (["/bin/timeout", "30", "pytest", "-q"], 30),
    ]:
        assert peel_timeout_clock(list(command)) == (["pytest", "-q"], seconds), command


def test_the_shortest_clock_bounds_a_doubled_wrapper() -> None:
    assert peel_timeout_clock(["timeout", "60", "timeout", "20", "pytest"]) == (["pytest"], 20)
    assert peel_timeout_clock(["timeout", "20", "timeout", "60", "pytest"]) == (["pytest"], 20)


def test_anything_that_is_not_that_clock_stays_in_the_command() -> None:
    for command in [
        # A `timeout` named by path is whatever that file holds.
        ["./timeout", "20", "pytest", "-q"],
        ["bin/timeout", "20", "pytest", "-q"],
        ["/tmp/timeout", "20", "pytest", "-q"],
        # An option is not a duration, so the word after it is not the program.
        ["timeout", "-k", "5", "20", "pytest"],
        ["timeout", "--signal=KILL", "20", "pytest"],
        # Durations this does not read.
        ["timeout", "20x", "pytest"],
        ["timeout", "1e9", "pytest"],
        ["timeout", "99999999999", "pytest"],
        ["timeout", "", "pytest"],
        ["timeout", "s", "pytest"],
        # A non-ASCII digit is not a duration either.
        ["timeout", "٢٠", "pytest"],
        # The clock has to bound a program named in the text.
        ["timeout", "20"],
        ["timeout", "20", "-q"],
        ["timeout", "20", "PYTHONPATH=/tmp"],
        ["pytest", "-q"],
    ]:
        assert peel_timeout_clock(list(command)) == (command, None), command


def test_a_zero_duration_peels_without_bounding_the_run() -> None:
    """`timeout 0` turns the clock off, so the peel must not invent one."""
    for command in [
        ["timeout", "0", "pytest", "-q"],
        ["timeout", "0.0", "pytest", "-q"],
        ["timeout", "0s", "pytest", "-q"],
        ["timeout", "0m", "pytest", "-q"],
    ]:
        assert peel_timeout_clock(list(command)) == (["pytest", "-q"], None), command
    # A fractional clock rounds up, so the run keeps the whole time it was given.
    assert peel_timeout_clock(["timeout", "0.4", "pytest"]) == (["pytest"], 1)
    assert peel_timeout_clock(["timeout", "2.1", "pytest"]) == (["pytest"], 3)
    assert peel_timeout_clock(["timeout", "0.5m", "pytest"]) == (["pytest"], 30)
    # An unbounded wrapper never loosens the clock inside it, or the reverse.
    assert peel_timeout_clock(["timeout", "0", "timeout", "20", "pytest"]) == (["pytest"], 20)
    assert peel_timeout_clock(["timeout", "20", "timeout", "0", "pytest"]) == (["pytest"], 20)
