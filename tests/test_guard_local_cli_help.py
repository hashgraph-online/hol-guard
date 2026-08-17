from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.local_cli_commands import (
    command_tokens_for_invocation,
    match_command_id,
    merge_discovered_commands,
)
from codex_plugin_scanner.guard.runtime.local_cli_help import (
    _HELP_OUTPUT_LIMIT,
    discover_local_cli_commands,
    parse_cli_help_text,
    run_cli_help,
)
from codex_plugin_scanner.guard.runtime.local_cli_identity import identify_unlisted_cli

WRANGLER_HELP = """
Usage: wrangler [OPTIONS] COMMAND [ARGS]...

Commands:
  docs [COMMAND..]  Open Wrangler docs
  init [NAME]       Initialize a Worker
  dev [SCRIPT]      Listen for local files
  deploy [SCRIPT]   Deploy a Worker
  pages             Commands for Pages
  help              Show help
"""

ARGPARSE_HELP = """
usage: ship.py [-h] {deploy,status,rollback} ...

positional arguments:
  {deploy,status,rollback}
    deploy              Ship the build
    status              Show status
    rollback            Undo the last ship
"""

COBRA_HELP = """
Available Commands:
  auth        Authenticate
  browse      Open the repository
  pr          Manage pull requests
"""


def test_parse_wrangler_style_help() -> None:
    commands = parse_cli_help_text(WRANGLER_HELP)
    names = [command.name for command in commands]
    assert names == ["docs", "init", "dev", "deploy", "pages"]
    assert "help" not in names


def test_parse_argparse_help() -> None:
    commands = parse_cli_help_text(ARGPARSE_HELP)
    assert [command.command_id for command in commands] == ["deploy", "status", "rollback"]


def test_parse_cobra_help() -> None:
    commands = parse_cli_help_text(COBRA_HELP)
    assert [command.command_id for command in commands] == ["auth", "browse", "pr"]


def test_merge_keeps_root_and_other() -> None:
    discovered = parse_cli_help_text(WRANGLER_HELP)
    merged = merge_discovered_commands("wrangler", discovered)
    assert merged[0].command_id == "root"
    assert merged[-1].command_id == "other"
    assert [command.command_id for command in merged[1:-1]] == ["docs", "init", "dev", "deploy", "pages"]


def test_match_longest_subcommand(tmp_path: Path) -> None:
    tool = tmp_path / "ship"
    tool.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    tool.chmod(0o755)
    identity = identify_unlisted_cli(f"{tool} pages deploy --env prod", cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    tokens = command_tokens_for_invocation(
        f"{tool} pages deploy --env prod",
        cwd=tmp_path,
        home_dir=tmp_path,
        identity=identity,
    )
    assert tokens == ("pages", "deploy")
    catalog = merge_discovered_commands(
        "ship",
        parse_cli_help_text("Commands:\n  pages  Pages\n"),
    )
    assert match_command_id(tokens, catalog) == "pages"
    nested = merge_discovered_commands(
        "ship",
        (
            *parse_cli_help_text("Commands:\n  pages  Pages\n"),
            parse_cli_help_text("Commands:\n  deploy  Deploy\n", parent_id="pages")[0],
        ),
    )
    assert match_command_id(tokens, nested) == "pages.deploy"


def test_discover_uses_help_runner(tmp_path: Path) -> None:
    tool = tmp_path / "ship"
    tool.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    tool.chmod(0o755)
    identity = identify_unlisted_cli(str(tool), cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None

    def runner(argv: tuple[str, ...]) -> str:
        if argv[-2:] == ("pages", "--help"):
            return "Commands:\n  deploy  Deploy a page\n"
        return WRANGLER_HELP

    commands, status = discover_local_cli_commands(identity, (str(tool), "--help"), runner=runner)
    assert status == "ok"
    ids = [command.command_id for command in commands]
    assert "deploy" in ids
    assert "pages.deploy" in ids


def test_run_cli_help_stops_after_output_limit(tmp_path: Path) -> None:
    tool = tmp_path / "flood"
    tool.write_text("#!/bin/sh\npython3 -c 'print(\"a\" * 20000)'\n", encoding="utf-8")
    tool.chmod(0o755)
    output = run_cli_help((str(tool), "--help"))
    assert len(output) <= _HELP_OUTPUT_LIMIT
