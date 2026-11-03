"""Grammar for `hol-guard cloud-actions`, replayed from a fixture.

The family must keep three contexts apart: a Guard Cloud workspace, a provider
or connected account, and a local folder. Existing commands keep their
meanings: `--workspace` still names a local folder for them.
"""

from __future__ import annotations

import argparse
import io
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli.commands_dispatch_cloud_actions import (
    CLOUD_ACTIONS_SCHEMA,
    CLOUD_ACTIONS_UNAVAILABLE_EXIT,
    _run_guard_cloud_actions_command,  # pyright: ignore[reportPrivateUsage]
)

FIXTURE = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "guard-cloud-actions-grammar.v1.json").read_text(encoding="utf-8")
)
VALUES: Mapping[str, str] = FIXTURE["values"]
CONTEXT_KEYS = ("cloud_workspace", "provider", "connected_account", "ai_tool")


def _fill(value: str) -> str:
    return VALUES.get(value, value)


def _run(argv: list[str]) -> int:
    try:
        return cli.main(["cloud-actions", *argv])
    except SystemExit as exit_:
        return int(exit_.code or 0)


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[case["id"] for case in FIXTURE["cases"]])
def test_grammar_fixture(case: dict[str, Any], capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    argv = [_fill(arg) for arg in case["argv"]]
    if case.get("guard_home"):
        argv += ["--guard-home", str(tmp_path)]
    exit_code = _run(argv)
    captured = capsys.readouterr()

    assert exit_code == case["exit"], captured.err
    if "stderr" in case:
        assert str(case["stderr"]) in captured.err
        assert captured.out == ""
        return
    payload: object = json.loads(captured.out)
    if "expect" in case:
        assert isinstance(payload, dict)
        assert payload["schema"] == CLOUD_ACTIONS_SCHEMA
        assert payload["command"] == case["command"]
        for key, value in case["expect"].items():
            assert payload[key] == (_fill(value) if isinstance(value, str) else value), key
        return
    context: dict[str, str] = case["context"]
    expected_context: dict[str, str | None] = dict.fromkeys(CONTEXT_KEYS)
    expected_context.update({key: _fill(value) for key, value in context.items()})
    assert payload == {
        "schema": CLOUD_ACTIONS_SCHEMA,
        "command": case["command"],
        "state": "unavailable",
        "reason": "not_available_yet",
        "context": expected_context,
    }


def test_human_output_says_nothing_changed(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = _run(["accounts", "connect", "slack", "--cloud-workspace", VALUES["WS"]])

    assert exit_code == CLOUD_ACTIONS_UNAVAILABLE_EXIT
    expected = "`hol-guard cloud-actions accounts connect` is not available yet. Nothing was changed.\n"
    assert capsys.readouterr().out == expected


def test_output_goes_to_the_given_stream(capsys: pytest.CaptureFixture[str]) -> None:
    stream = io.StringIO()
    args = argparse.Namespace(cloud_actions_command="accounts", cloud_actions_accounts_command="list", json=True)

    exit_code = _run_guard_cloud_actions_command(args, output_stream=stream)

    assert exit_code == CLOUD_ACTIONS_UNAVAILABLE_EXIT
    assert json.loads(stream.getvalue())["command"] == "accounts list"
    assert capsys.readouterr().out == ""


def _help(argv: list[str], capsys: pytest.CaptureFixture[str]) -> str:
    with pytest.raises(SystemExit) as exit_:
        _ = cli.main(argv)
    assert exit_.value.code == 0
    return capsys.readouterr().out


def test_help_separates_cloud_workspace_from_local_folder(capsys: pytest.CaptureFixture[str]) -> None:
    family = _help(["cloud-actions", "--help"], capsys)
    assert "{login,logout,status,workspace,accounts,ai-tools}" in family
    assert "Separate from `connect`, `apps` and `install`" in family

    connect = " ".join(_help(["cloud-actions", "accounts", "connect", "--help"], capsys).split())
    assert "PROVIDER" in connect
    assert "--cloud-workspace ID Guard Cloud workspace ID (not a local folder)" in connect
    assert "--workspace" not in connect.replace("--cloud-workspace", "")

    disconnect = _help(["cloud-actions", "accounts", "disconnect", "--help"], capsys)
    assert "CONNECTED_ACCOUNT_ID" in disconnect

    listing = " ".join(_help(["cloud-actions", "accounts", "list", "--help"], capsys).split())
    assert "defaults to the one chosen with `workspace select`" in listing


def test_family_stays_out_of_top_level_help_until_it_can_act(capsys: pytest.CaptureFixture[str]) -> None:
    assert "cloud-actions" not in _help(["guard", "--help"], capsys)


@pytest.mark.parametrize(
    "argv",
    [
        ["connect", "status", "--workspace", "/tmp/project"],
        ["apps", "--workspace", "/tmp/project", "connect", "codex"],
        ["install", "codex", "--workspace", "/tmp/project"],
    ],
)
def test_existing_commands_keep_local_workspace(argv: list[str]) -> None:
    parser = cli._build_parser("hol-guard", program_mode="combined")  # pyright: ignore[reportPrivateUsage]
    args = parser.parse_args(["guard", *argv])

    assert args.workspace == "/tmp/project"
    assert args.guard_command == argv[0]
