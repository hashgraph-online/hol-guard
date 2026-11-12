from __future__ import annotations

from codex_plugin_scanner.guard.runtime.contained_command_prefix import planned_route_argv


def test_a_sink_asks_about_a_planned_bun_run_as_the_caller_spelled_it() -> None:
    bun = "/opt/homebrew/bin/bun"
    assert planned_route_argv([bun, "--no-env-file", "-e", "console.log(1)"]) == [bun, "-e", "console.log(1)"]
    assert planned_route_argv([bun, "--no-env-file", "test"]) == [bun, "test"]


def test_any_other_planned_argv_is_asked_about_unchanged() -> None:
    for command in (
        ["/usr/bin/node", "--no-env-file", "-e", "1"],
        ["/opt/homebrew/bin/bun", "-e", "--no-env-file"],
        ["/opt/homebrew/bin/bun", "test"],
    ):
        assert planned_route_argv(command) == command
