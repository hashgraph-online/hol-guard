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
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity, identify_unlisted_cli

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


YARGS_WRANGLER_HELP = """
wrangler

COMMANDS
  wrangler docs [search..]        Open Wrangler's command documentation in your browser
  wrangler init [name]            Create a new project

ACCOUNT
  wrangler login                  Login to Cloudflare
  wrangler whoami                 Retrieve your user information

COMPUTE & AI
  wrangler d1                     Manage Workers D1 databases

GLOBAL FLAGS
  -c, --config  Path to Wrangler configuration file  [string]
  -h, --help    Show help  [boolean]

EXAMPLES
  wrangler tail my-worker         Stream logs
"""

YARGS_WRANGLER_D1_HELP = """
wrangler d1

COMMANDS
  wrangler d1 list                List D1 databases
  wrangler d1 execute <database>  Execute a command or SQL file
"""


def test_parse_yargs_rows_strip_program_name() -> None:
    commands = parse_cli_help_text(YARGS_WRANGLER_HELP, invocation=("wrangler",))
    assert [command.command_id for command in commands] == ["docs", "init", "login", "whoami", "d1"]
    nested = parse_cli_help_text(YARGS_WRANGLER_D1_HELP, invocation=("wrangler", "d1"))
    assert [command.command_id for command in nested] == ["list", "execute"]


KUBECTL_STYLE_HELP = """
kubectl controls the Kubernetes cluster manager.

Commands:
  get           Display one or many resources

Examples:
  # List all pods
  kubectl get pods -o wide
"""


def test_colon_terminated_yargs_group_heading() -> None:
    text = "ACCOUNT:\n  wrangler login   Login\n  wrangler whoami  Show user\n"
    commands = parse_cli_help_text(text, invocation=("wrangler",))
    assert [command.command_id for command in commands] == ["login", "whoami"]


def test_program_prefixed_prose_and_examples_are_not_commands() -> None:
    commands = parse_cli_help_text(KUBECTL_STYLE_HELP, invocation=("kubectl",))
    assert [command.command_id for command in commands] == ["get"]
    nested = parse_cli_help_text(KUBECTL_STYLE_HELP, invocation=("kubectl", "get"))
    assert [command.command_id for command in nested] == ["get"]


def test_discover_yargs_help_has_no_program_named_commands() -> None:
    identity = UnlistedCliIdentity(
        cli_id="local-cli.wrangler-00000000",
        name="wrangler",
        kind="executable",
        identity_hash="0" * 64,
        example_label="wrangler",
    )

    def _probe(argv):
        return YARGS_WRANGLER_D1_HELP if "d1" in argv else YARGS_WRANGLER_HELP

    commands, status = discover_local_cli_commands(identity, ("wrangler", "--help"), runner=_probe)
    ids = [command.command_id for command in commands]
    assert status == "ok"
    assert "wrangler" not in ids
    assert not any(command_id.startswith("wrangler.") for command_id in ids)
    assert {"docs", "whoami", "d1.list", "d1.execute"} <= set(ids)


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
