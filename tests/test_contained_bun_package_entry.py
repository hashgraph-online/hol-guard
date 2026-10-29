"""Bun started on an installed entrypoint is planned as the Node run it is.

Native authority reads the same shape (`bun_package_entry.rs`) and gives it the
receipt `node` gets, so the sink has to hand the planners the `node` spelling.
"""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime import contained_command_prefix as prefix


@pytest.mark.parametrize(
    "command",
    [
        ["bun", "node_modules/vite/bin/vite.js", "build"],
        ["bun", "dashboard/node_modules/vite/bin/vite.js", "build", "--root", "/work/tree/dashboard"],
        ["/opt/bun/bin/bun", "/work/app/node_modules/vitest/vitest.mjs", "run"],
        ["bun", "./node_modules/eslint/bin/eslint.js", "src"],
    ],
)
def test_an_installed_entrypoint_is_planned_as_node(command: list[str]) -> None:
    assert prefix.bun_package_entry_as_node(command) == ["node", *command[1:]]


@pytest.mark.parametrize(
    "command",
    [
        ["bun"],
        ["bun", "install"],
        ["bun", "add", "left-pad"],
        ["bun", "x", "vite", "build"],
        ["bun", "run", "build"],
        ["bun", "./script.mjs"],
        ["bun", "src/report.ts"],
        ["bun", "https://example.com/node_modules/vite/bin/vite.js", "build"],
        ["bun", "--cwd", "node_modules/vite", "build"],
        ["bun", "node_modules/"],
        ["bunx", "node_modules/vite/bin/vite.js", "build"],
        ["node", "node_modules/vite/bin/vite.js", "build"],
    ],
)
def test_other_commands_keep_their_spelling(command: list[str]) -> None:
    assert prefix.bun_package_entry_as_node(command) == command


def test_the_planners_receive_the_node_spelling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(prefix, "peel_timeout_clock", lambda command: (command, None))
    monkeypatch.setattr(prefix, "_peel_launcher", lambda command: command)

    command, clock = prefix.peel_run_prefixes(["bun", "node_modules/vite/bin/vite.js", "build"])

    assert (command, clock) == (["node", "node_modules/vite/bin/vite.js", "build"], None)
