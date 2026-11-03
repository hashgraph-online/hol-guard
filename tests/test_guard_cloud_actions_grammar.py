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
from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_actions as dispatch
from codex_plugin_scanner.guard.cli.commands_dispatch_cloud_actions import (
    CLOUD_ACTIONS_SCHEMA,
    CLOUD_ACTIONS_UNAVAILABLE_EXIT,
    _run_guard_cloud_actions_command,  # pyright: ignore[reportPrivateUsage]
)
from tests.cloud_actions_pairing_support import FakeCloud, pair

FIXTURE = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "guard-cloud-actions-grammar.v1.json").read_text(encoding="utf-8")
)
VALUES: Mapping[str, str] = FIXTURE["values"]
CONTEXT_KEYS = ("cloud_workspace", "provider", "connected_account", "ai_tool")


@pytest.fixture(autouse=True)
def _own_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Commands without --guard-home resolve Guard's home from the user's home.
    monkeypatch.setenv("HOME", str(tmp_path / "user"))


def _fill(value: str) -> str:
    return VALUES.get(value, value)


def _run(argv: list[str]) -> int:
    try:
        return cli.main(["cloud-actions", *argv])
    except SystemExit as exit_:
        return int(exit_.code or 0)


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[case["id"] for case in FIXTURE["cases"]])
def test_grammar_fixture(
    case: dict[str, Any], capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if "paired" in case:
        _ = pair(monkeypatch, FakeCloud(workspace_id=VALUES["WS"], paired=bool(case["paired"])))
    argv = [_fill(arg) for arg in case["argv"]]
    if case.get("guard_home"):
        argv += ["--guard-home", str(tmp_path)]
    if case.get("home"):
        argv += ["--home", str(tmp_path)]
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
    exit_code = _run(["accounts", "disconnect", VALUES["ACCOUNT"], "--cloud-workspace", VALUES["WS"]])

    assert exit_code == CLOUD_ACTIONS_UNAVAILABLE_EXIT
    expected = "`hol-guard cloud-actions accounts disconnect` is not available yet. Nothing was changed.\n"
    assert capsys.readouterr().out == expected


CONNECTED_ACCOUNTS_URL = (
    "https://hol.org/guard/settings?tab=integrations&workspaceId=4f0c2b9e-1d7a-4c3e-9b8a-2e5f6a7b8c9d"
    "#connected-accounts"
)


def _opener(monkeypatch: pytest.MonkeyPatch, *, accepted: bool, origin: str = "https://hol.org") -> list[str]:
    _ = pair(monkeypatch, FakeCloud(workspace_id=VALUES["WS"], origin=origin))
    opened: list[str] = []

    def fake_open(url: str) -> bool:
        opened.append(url)
        return accepted

    monkeypatch.setattr(dispatch, "open_browser_url", fake_open)
    return opened


def test_connect_opens_connected_accounts_in_guard_cloud(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    opened = _opener(monkeypatch, accepted=True)

    exit_code = _run(["accounts", "connect", "slack", "--cloud-workspace", VALUES["WS"]])

    assert exit_code == 0
    assert opened == [CONNECTED_ACCOUNTS_URL]
    assert capsys.readouterr().out == (
        "Opened Guard Cloud in your browser.\n"
        f"{CONNECTED_ACCOUNTS_URL}\n"
        f"To connect a Slack account to workspace {VALUES['WS']}, choose Connect Slack under Connected accounts "
        "and sign in with Slack there.\n"
    )


def test_connect_prints_the_link_when_no_browser_opens(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    opened = _opener(monkeypatch, accepted=False)

    exit_code = _run(["accounts", "connect", "slack", "--cloud-workspace", VALUES["WS"], "--json"])

    assert exit_code == 0
    assert opened == [CONNECTED_ACCOUNTS_URL]
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "link"
    assert payload["opened"] is False
    assert payload["url"] == CONNECTED_ACCOUNTS_URL


def test_connect_no_browser_never_launches_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    opened = _opener(monkeypatch, accepted=True)

    exit_code = _run(["accounts", "connect", "slack", "--cloud-workspace", VALUES["WS"], "--no-browser"])

    assert exit_code == 0
    assert opened == []
    assert capsys.readouterr().out.startswith(
        f"Open this link in a browser where you use Guard Cloud:\n{CONNECTED_ACCOUNTS_URL}\n"
    )


@pytest.mark.parametrize(("provider", "name"), [("github", "GitHub"), ("acme_crm", "Acme Crm"), ("my-tool", "My Tool")])
def test_provider_name_matches_guard_cloud(provider: str, name: str) -> None:
    assert dispatch.provider_name(provider) == name


def test_connect_uses_the_connected_guard_cloud(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _ = _opener(monkeypatch, accepted=False, origin="http://127.0.0.1:3017")

    exit_code = _run(["accounts", "connect", "slack", "--json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["url"].startswith("http://127.0.0.1:3017/guard/settings?")
    assert payload["cloud_workspace"] == VALUES["WS"]


def test_connect_keeps_the_guard_cloud_path_prefix(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("HOL_GUARD_STAGING_ORIGIN", "https://guard-staging.example.test|/points")
    _ = _opener(monkeypatch, accepted=True, origin="https://guard-staging.example.test")

    exit_code = _run(["accounts", "connect", "slack", "--cloud-workspace", VALUES["WS"], "--json"])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["url"].startswith(
        "https://guard-staging.example.test/points/guard/settings?"
    )


def test_connect_no_longer_takes_a_cloud_url(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = _run(["accounts", "connect", "slack", "--cloud-url", "https://example.com"])

    assert exit_code == 2
    assert "unrecognized arguments: --cloud-url" in capsys.readouterr().err


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
    assert "{status,doctor,accounts,ai-tools}" in family
    assert "login" not in family and "logout" not in family
    assert "Separate from `connect`, `apps` and `install`" in family

    connect = " ".join(_help(["cloud-actions", "accounts", "connect", "--help"], capsys).split())
    assert "PROVIDER" in connect
    assert "--cloud-workspace ID Guard Cloud workspace ID (not a local folder)" in connect
    assert "--workspace" not in connect.replace("--cloud-workspace", "")

    disconnect = _help(["cloud-actions", "accounts", "disconnect", "--help"], capsys)
    assert "CONNECTED_ACCOUNT_ID" in disconnect

    listing = " ".join(_help(["cloud-actions", "accounts", "list", "--help"], capsys).split())
    assert "defaults to the one this computer is connected to" in listing


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
