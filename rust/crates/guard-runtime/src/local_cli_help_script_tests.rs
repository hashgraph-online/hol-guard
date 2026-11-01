use super::super::facts::HelpHandler;
use super::super::{script_facts, variations};

fn handler(source: &str) -> HelpHandler {
    script_facts(source, &["tool".to_owned()]).help
}

fn imports(source: &str) -> Vec<String> {
    script_facts(source, &["tool".to_owned()]).imports
}

fn ids(source: &str) -> Vec<String> {
    variations(source, &["tool".to_owned()], true)
        .into_iter()
        .map(|row| row.command_id)
        .collect()
}

fn description(source: &str, id: &str) -> String {
    variations(source, &["tool".to_owned()], true)
        .into_iter()
        .find(|row| row.command_id == id)
        .unwrap_or_else(|| panic!("{id} missing"))
        .description
}

/// A pinning script that destructures its arguments and refuses anything else.
const PIN_SCRIPT: &str = r#"#!/usr/bin/env node
import { readFileSync } from 'node:fs';
const [,, action, command] = process.argv;
if (action !== 'pin' && action !== 'unpin') {
  console.error('expected pin or unpin');
  process.exit(1);
}
if (command === 'all') {
  console.log('the second argument is not a subcommand');
}
"#;

#[test]
fn destructured_arguments_compared_to_words_are_subcommands() {
    assert_eq!(ids(PIN_SCRIPT), vec!["pin", "unpin"]);
}

#[test]
fn a_script_that_never_looks_for_help_is_not_run() {
    assert_eq!(handler(PIN_SCRIPT), HelpHandler::None);
}

#[test]
fn a_switch_on_a_lowercased_argument_with_a_fallback_names_its_cases() {
    let script = r#"const actionArg = process.argv[2];
const action = (actionArg || 'status').toLowerCase();
switch (action) {
  case 'status': // Show hook state
    show();
    break;
  case 'install':
  case 'uninstall':
    change(action);
    break;
  default:
    process.exit(1);
}
switch (process.env.MODE) {
  case 'prod':
    break;
}
"#;
    assert_eq!(ids(script), vec!["status", "install", "uninstall"]);
    assert_eq!(description(script, "status"), "Show hook state");
}

#[test]
fn a_nested_switch_case_is_not_a_subcommand() {
    let script = r#"const [command, target] = process.argv.slice(2);
switch (command) {
  case 'build': {
    switch (target) {
      case 'docs':
        break;
    }
    break;
  }
  case 'test':
    break;
}
"#;
    assert_eq!(ids(script), vec!["build", "test"]);
}

#[test]
fn python_match_on_a_parameter_given_the_argument_list() {
    let script = r#"import sys

def main(argv):
    match argv[0] if argv else "help":
        case "build":
            build()
        case "test" | "check":
            test()
        case _:
            usage()

main(sys.argv[1:])
"#;
    assert_eq!(ids(script), vec!["build", "test", "check"]);
}

#[test]
fn python_match_on_the_list_reads_the_first_item_of_each_pattern() {
    let script = r#"import sys
match sys.argv[1:]:
    case ["serve", *rest]:
        serve(rest)
    case ["stop"]:
        stop()
"#;
    assert_eq!(ids(script), vec!["serve", "stop"]);
}

#[test]
fn ruby_case_when_on_a_shifted_argument() {
    let script = r#"#!/usr/bin/env ruby
command = ARGV.shift
case command
when "start", "run" then start
when "stop"
  stop
end
if ARGV.first == "later"
  puts "the argument after the command is not one"
end
"#;
    assert_eq!(ids(script), vec!["start", "run", "stop"]);
}

#[test]
fn membership_tests_name_every_listed_word() {
    let python = "import sys\nCOMMANDS = (\"serve\", \"stop\")\ncmd = sys.argv[1]\nif cmd not in COMMANDS:\n    sys.exit(2)\n";
    assert_eq!(ids(python), vec!["serve", "stop"]);
    let node = "if (!['lint', 'fix'].includes(process.argv[2])) process.exit(1);\n";
    assert_eq!(ids(node), vec!["lint", "fix"]);
}

#[test]
fn a_word_compared_to_something_else_is_not_a_subcommand() {
    let script = "if (process.env.MODE === 'prod') run();\nif (process.argv[3] === 'fast') go();\n";
    assert!(ids(script).is_empty());
}

#[test]
fn options_compared_against_any_argument_are_variations() {
    let script = r#"const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
for (const arg of args) {
  if (arg === '--force') force = true;
}
const { values } = parseArgs({ options: {
  verbose: { type: 'boolean', short: 'v' },
  out: { type: 'string' },
} });
"#;
    let found = ids(script);
    for option in ["--dry-run", "--force", "--verbose", "-v", "--out"] {
        assert!(
            found.contains(&option.to_owned()),
            "{option} missing from {found:?}"
        );
    }
}

#[test]
fn argparse_subparsers_name_top_level_commands_only() {
    let script = r#"#!/usr/bin/env python3
import argparse

parser = argparse.ArgumentParser(description="Manage the cache.")
sub = parser.add_subparsers(dest="command")
sub.add_parser("clear", help="Remove every entry")
prune = sub.add_parser("prune", help="Remove stale entries")
prune_sub = prune.add_subparsers()
prune_sub.add_parser("deep")
"#;
    let found = ids(script);
    assert_eq!(found, vec!["clear", "prune"]);
    assert_eq!(description(script, "prune"), "Remove stale entries");
    assert_eq!(handler(script), HelpHandler::Framework);
}

#[test]
fn click_commands_are_named_by_argument_or_function() {
    let script = r#"import click

@click.group()
def cli():
    """Deploy tools."""

@cli.command()
@click.option("--force", is_flag=True)
def ship_it(force):
    """Ship the build."""

@cli.command("roll-back", help="Undo the last ship")
def rollback():
    pass
"#;
    let found = ids(script);
    assert!(found.contains(&"ship-it".to_owned()), "{found:?}");
    assert!(found.contains(&"roll-back".to_owned()), "{found:?}");
    assert!(!found.contains(&"cli".to_owned()), "{found:?}");
    assert_eq!(description(script, "ship-it"), "Ship the build.");
    assert_eq!(description(script, "roll-back"), "Undo the last ship");
}

#[test]
fn commander_commands_on_the_program_are_read_and_nested_ones_are_not() {
    let script = r#"import { Command } from 'commander';
const program = new Command();
program
  .command('build')
  .description('Build the site');
program.command('serve <port>', 'Start the server');
const db = program.command('db');
db.command('migrate');
program.parse();
"#;
    assert_eq!(ids(script), vec!["build", "serve", "db"]);
    assert_eq!(description(script, "build"), "Build the site");
    assert_eq!(description(script, "serve"), "Start the server");
}

#[test]
fn framework_calls_in_a_script_without_the_framework_are_ignored() {
    let script = "const queue = makeQueue();\nqueue.command('flush');\nparser.add_parser('x')\n";
    assert!(ids(script).is_empty());
}

#[test]
fn options_and_commands_are_never_confused() {
    let script = "const cmd = process.argv[2];\nif (cmd === '--version' || cmd === 'help') {}\n";
    // `--version` is not a command name, and `help` is never a variation.
    assert!(ids(script).is_empty());
}

#[test]
fn the_help_handler_follows_the_strongest_evidence() {
    let checks = [
        (
            "if (process.argv.includes('--help')) usage();\n",
            HelpHandler::Script,
        ),
        (
            "if [ \"$1\" = \"-h\" ]; then usage; fi\n",
            HelpHandler::Script,
        ),
        (
            "import argparse\nargparse.ArgumentParser().parse_args()\n",
            HelpHandler::Framework,
        ),
        (
            "import argparse\np = argparse.ArgumentParser(\n    add_help=False,\n)\n",
            HelpHandler::None,
        ),
        ("import argparse\n", HelpHandler::None),
        (
            "import { program } from 'commander';\n",
            HelpHandler::Framework,
        ),
        ("// Pass --help for usage.\nrun();\n", HelpHandler::None),
        (
            "case \"$1\" in\n  -h|--help) usage ;;\nesac\n",
            HelpHandler::Script,
        ),
        (
            "if arg in (\"-h\", \"--help\"):\n    usage()\n",
            HelpHandler::Script,
        ),
        (
            "if [[ $1 == --help ]]; then usage; fi\n",
            HelpHandler::Script,
        ),
        ("when '-h', '--help' then usage\n", HelpHandler::Script),
        (
            "from argparse import ArgumentParser\np = ArgumentParser()\n",
            HelpHandler::Framework,
        ),
        (
            "from argparse import ArgumentParser\np = ArgumentParser(add_help=False)\n",
            HelpHandler::None,
        ),
        (
            "class ArgumentParser(Base):\n    pass\np = ArgumentParser()\n",
            HelpHandler::None,
        ),
        (
            "\"\"\"Pass --help for usage.\n\"\"\"\nrun()\n",
            HelpHandler::None,
        ),
    ];
    for (source, expected) in checks {
        assert_eq!(handler(source), expected, "{source}");
    }
}

#[test]
fn only_imports_inside_the_scripts_folder_are_local() {
    let node = concat!(
        "import { run } from './lib/run.mjs';\n",
        "import fs from 'node:fs';\n",
        "const outside = require('../outside.js');\n",
        "const lazy = await import('./lazy.mjs');\n",
        "// import './commented.mjs';\n",
    );
    assert_eq!(imports(node), vec!["./lib/run.mjs", "./lazy.mjs"]);
    let python = "from helpers import usage\nimport os, tools.cli as cli\nfrom . import nope\n";
    assert_eq!(
        imports(python),
        vec!["./helpers.py", "./os.py", "./tools/cli.py"]
    );
    let ruby = "require_relative 'lib/cmd'\nrequire_relative \"../up\"\n";
    assert_eq!(imports(ruby), vec!["./lib/cmd.rb"]);
}

#[test]
fn help_flags_passed_to_other_programs_are_not_help_checks() {
    for source in [
        "du -h | sort -h\n",
        "size=$(df -h)\n",
        "tool --help >/dev/null\n",
        "HELP=\"--help\"\n",
        "const usage = 'Run tool --help';\n",
        "spawn('ls', ['-h']);\n",
        "if [ -h \"$link\" ]; then echo link; fi\n",
        // A wrapped call's last line outside a shell `case`.
        "run(\"ls\",\n    \"-h\")\n",
    ] {
        assert_eq!(handler(source), HelpHandler::None, "{source}");
    }
}

#[test]
fn ruby_appends_and_shifts_do_not_open_a_heredoc() {
    let ruby = r#"command = ARGV.shift
errors << msg
case command
when "start" then start
end
"#;
    assert_eq!(ids(ruby), vec!["start"]);
    let node = r#"const flags = 1 << shift;
const [command] = process.argv.slice(2);
switch (command) {
  case 'build':
    break;
}
"#;
    assert_eq!(ids(node), vec!["build"]);
    let heredoc = "USAGE = <<~EOS\n  -q, --quiet  Say less\nEOS\n";
    assert_eq!(ids(heredoc), vec!["--quiet", "-q"]);
}

#[test]
fn a_python_case_with_a_trailing_comment_is_read() {
    let script = r#"import sys
match sys.argv[1]:
    case "build":  # Build the site
        build()
"#;
    assert_eq!(ids(script), vec!["build"]);
    assert_eq!(description(script, "build"), "Build the site");
}

#[test]
fn wrapped_parser_calls_and_options_are_read() {
    let argparse = r#"import argparse
parser = argparse.ArgumentParser()
sub = parser.add_subparsers()
sub.add_parser(
    "clear", help="Remove every entry")
"#;
    assert_eq!(ids(argparse), vec!["clear"]);
    let yargs = r#"import yargs from 'yargs';
yargs(process.argv.slice(2))
  .command({
    command: 'serve [port]',
    describe: 'Start the server',
  });
"#;
    assert_eq!(ids(yargs), vec!["serve"]);
    assert_eq!(description(yargs, "serve"), "Start the server");
    let node = r#"const { values } = parseArgs({ options: {
  force: {
    type: 'boolean',
    short: 'f',
  },
} });
"#;
    assert_eq!(ids(node), vec!["--force", "-f"]);
}

#[test]
fn mcp_server_libraries_and_tools_list_handlers_are_evidence() {
    let serves = |source: &str| script_facts(source, &["tool".to_owned()]).mcp_server;
    for source in [
        "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n",
        "const { Server } = require(\"@modelcontextprotocol/sdk/server/index.js\");\n",
        "const sdk = await import('@modelcontextprotocol/sdk/server/stdio.js');\n",
        "import { FastMCP } from 'fastmcp';\n",
        "from mcp.server.fastmcp import FastMCP\n",
        "try:\n    import fastmcp\nexcept ImportError:\n    pass\n",
        "import sys, fastmcp\n",
        "from mcp import FastMCP\n",
        "import { McpServer } from \"@modelcontextprotocol/server\";\n",
        "require 'mcp'\n",
        "require('mcp')\n",
        "if (request.method === 'tools/list') { reply(tools); }\n",
        "if message[\"method\"] == \"tools/list\":\n    send(tools)\n",
        "match method:\n    case \"tools/list\":\n        send(tools)\n",
        "when 'tools/list' then reply(tools)\n",
        "HANDLERS = {\"tools/list\": list_tools}\n",
    ] {
        assert!(serves(source), "{source}");
    }
    for source in [
        "import mcp_helpers\n",
        "from mcpx import run\n",
        "import { deploy } from './mcp.mjs';\n",
        "// import { Server } from '@modelcontextprotocol/sdk';\n",
        "# from mcp.server import Server\n",
        "console.log('ship tools to the list');\n",
        "import sys\nprint(sys.argv)\n",
        "from mcp import ClientSession, StdioServerParameters\n",
        "import mcp\n",
        "const { Client } = require('@modelcontextprotocol/sdk/client/index.js');\n",
        "await session.send({\"method\": \"tools/list\"})\n",
        "client.request({ method: 'tools/list' });\n",
        "print('tools/list')\n",
        "deploy()  # if method == 'tools/list'\n",
        "deploy(); // case 'tools/list':\n",
    ] {
        assert!(!serves(source), "{source}");
    }
}
