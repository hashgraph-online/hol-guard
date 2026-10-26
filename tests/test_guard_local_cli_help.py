"""The probing half of local CLI command discovery.

The parse itself belongs to the resident now
(``rust/crates/guard-runtime/src/local_cli_help.rs``). Its decisions are
recorded in ``tests/fixtures/guard-local-cli-help-parse.v1.json``, which the
Rust suite replays; the tests here stand a resident up from that same fixture
so the probing, nesting and merging around it stay covered without a second
parser in Python.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.local_cli_commands import (
    LocalCliCommand,
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

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/guard-local-cli-help-parse.v1.json"

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


def _recorded() -> dict[tuple[str, str | None, tuple[str, ...]], tuple[dict[str, object], ...]]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-local-cli-help-parse-parity.v1"
    return {
        (case["text"], case["parent_id"], tuple(case["invocation"])): tuple(case["expected"])
        for case in document["cases"]
    }


@pytest.fixture
def recorded_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer the parse op from the decisions the fixture recorded."""

    answers = _recorded()

    def _answer(
        *,
        guard_home: Path,
        text: str,
        parent_id: str | None,
        invocation: Sequence[str],
    ) -> tuple[dict[str, object], ...] | None:
        key = (text, parent_id, tuple(invocation))
        assert key in answers, f"the fixture records no parse for {key[1:]!r}"
        return answers[key]

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_local_cli_help_parse.native_local_cli_help_commands",
        _answer,
    )


def _command(command_id: str, description: str = "", parent_id: str | None = None) -> LocalCliCommand:
    name = command_id.rpartition(".")[2]
    return LocalCliCommand(
        command_id=command_id,
        name=name,
        usage=name,
        description=description,
        parent_id=parent_id,
    )


def test_the_fixture_keeps_recording_the_dialects_rust_replays() -> None:
    names = {case["name"] for case in json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]}
    assert {
        "wrangler-click-style",
        "argparse-choice-set",
        "cobra-available-commands",
        "yargs-groups",
        "yargs-nested-group",
    } <= names


def _identity(name: str = "wrangler") -> UnlistedCliIdentity:
    return UnlistedCliIdentity(
        cli_id=f"local-cli.{name}-00000000",
        name=name,
        kind="executable",
        identity_hash="0" * 64,
        example_label=name,
    )


def _row(name: str) -> dict[str, object]:
    return {
        "command_id": name,
        "name": name,
        "usage": name,
        "description": "",
        "parent_id": None,
    }


def _stand_in_resident(monkeypatch: pytest.MonkeyPatch, answer) -> list[dict[str, object]]:
    """Patch the bridge with ``answer`` and record every call it receives."""

    calls: list[dict[str, object]] = []

    def _answer(**kwargs: object) -> tuple[dict[str, object], ...] | None:
        calls.append(kwargs)
        return answer(**kwargs)

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_local_cli_help_parse.native_local_cli_help_commands",
        _answer,
    )
    return calls


def test_a_resident_that_cannot_answer_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    """``None``, not ``()``: nothing was read, which is not the same as nothing named."""

    _stand_in_resident(monkeypatch, lambda **_: None)
    assert parse_cli_help_text(WRANGLER_HELP) is None


def test_a_resident_that_cannot_answer_is_a_failure_not_an_empty_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The operator is told Guard could not read --help, not that the CLI named nothing."""

    _stand_in_resident(monkeypatch, lambda **_: None)
    commands, status = discover_local_cli_commands(
        _identity(), ("wrangler", "--help"), runner=lambda _: WRANGLER_HELP
    )
    assert status == "failed"
    assert [command.command_id for command in commands] == ["root", "other"]


def test_a_cli_that_names_nothing_is_still_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """A real empty parse keeps its own status, so "failed" stays meaningful."""

    _stand_in_resident(monkeypatch, lambda **_: ())
    _, status = discover_local_cli_commands(
        _identity(), ("wrangler", "--help"), runner=lambda _: WRANGLER_HELP
    )
    assert status == "empty"


def test_blank_help_output_never_reaches_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing was printed, so there is nothing to provision a resident for."""

    calls = _stand_in_resident(monkeypatch, lambda **_: ())
    _, status = discover_local_cli_commands(
        _identity(), ("wrangler", "--help"), runner=lambda _: "   \n"
    )
    assert status == "failed"
    assert calls == []


def test_discovery_parses_through_the_home_it_is_given(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A daemon on an overridden home must not send the parse to the default one."""

    calls = _stand_in_resident(monkeypatch, lambda **_: (_row("docs"),))
    discover_local_cli_commands(
        _identity(),
        ("wrangler", "--help"),
        runner=lambda _: WRANGLER_HELP,
        guard_home=tmp_path,
    )
    assert calls, "the resident was never asked"
    assert {call["guard_home"] for call in calls} == {tmp_path}


def test_a_resident_that_goes_quiet_stops_the_nested_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each remaining child would wait out its own timeout for the same silence."""

    answers: list[tuple[dict[str, object], ...] | None] = [
        (_row("docs"), _row("init"), _row("deploy")),
        None,
    ]

    def _answer(**_: object) -> tuple[dict[str, object], ...] | None:
        return answers.pop(0) if answers else pytest.fail("probed past the silence")

    calls = _stand_in_resident(monkeypatch, _answer)
    commands, status = discover_local_cli_commands(
        _identity(), ("wrangler", "--help"), runner=lambda _: WRANGLER_HELP
    )
    # The top-level parse stands; only the children are given up on.
    assert status == "ok"
    assert {"docs", "init", "deploy"} <= {command.command_id for command in commands}
    assert len(calls) == 2


def test_discover_yargs_help_has_no_program_named_commands(recorded_resident: None) -> None:
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


def test_merge_keeps_root_and_other() -> None:
    discovered = tuple(_command(name) for name in ("docs", "init", "dev", "deploy", "pages"))
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
    catalog = merge_discovered_commands("ship", (_command("pages", "Pages"),))
    assert match_command_id(tokens, catalog) == "pages"
    nested = merge_discovered_commands(
        "ship",
        (_command("pages", "Pages"), _command("pages.deploy", "Deploy", parent_id="pages")),
    )
    assert match_command_id(tokens, nested) == "pages.deploy"


def test_discover_uses_help_runner(tmp_path: Path, recorded_resident: None) -> None:
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
