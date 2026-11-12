"""`cloud-actions ai-tools configure` and `doctor` as commands, working from the pairing.

Where the entry's Guard home comes from must agree between configure and
doctor, and the home must stay valid wherever the AI tool starts the bridge.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner import cli
from tests.cloud_actions_pairing_support import URL, WS, FakeCloud, pair


def _configure(home: Path, tool: str, *extra: str) -> int:
    try:
        return cli.main(
            ["cloud-actions", "ai-tools", "configure", tool, "--cloud-workspace", WS, "--home", str(home), *extra]
        )
    except SystemExit as exit_:
        return int(exit_.code or 0)


@pytest.fixture(autouse=True)
def _paired(monkeypatch: pytest.MonkeyPatch) -> FakeCloud:
    return pair(monkeypatch)


def test_unsupported_ai_tool_names_the_supported_ones(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _configure(tmp_path, "windsurf", "--dry-run", "--json") == 3
    payload = json.loads(capsys.readouterr().out)

    assert payload["reason"] == "ai_tool_not_supported"
    assert payload["supported_ai_tools"] == ["claude-code", "codex", "cursor"]


def test_without_a_pairing_configure_points_to_connect_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _ = pair(monkeypatch, FakeCloud(paired=False))

    assert _configure(tmp_path, "cursor", "--apply") == 4
    out = capsys.readouterr().out

    assert "hol-guard connect" in out and "Nothing was changed." in out
    assert not any(tmp_path.iterdir())


def test_another_workspace_than_the_paired_one_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    other = "22222222-2222-4222-8222-222222222222"
    code = cli.main(
        [
            "cloud-actions",
            "ai-tools",
            "configure",
            "codex",
            "--cloud-workspace",
            other,
            "--home",
            str(tmp_path),
            "--dry-run",
            "--json",
        ]
    )

    assert code == 4
    payload = json.loads(capsys.readouterr().out)
    assert payload["reason"] == "workspace_mismatch"
    assert payload["paired_workspace"] == WS
    assert not any(tmp_path.iterdir())


def test_the_workspace_comes_from_the_pairing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["cloud-actions", "ai-tools", "configure", "codex", "--home", str(tmp_path), "--dry-run", "--json"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cloud_workspace"] == WS
    assert payload["url"] == URL


def _codex_bridge_args(home: Path) -> list[str]:
    from codex_plugin_scanner.guard.codex_config import tomllib

    document = tomllib.loads((home / ".codex" / "config.toml").read_text(encoding="utf-8"))
    return document["mcp_servers"]["hol-guard-cloud"]["args"]


def test_doctor_reads_the_entry_configure_wrote_under_home(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import argparse

    from codex_plugin_scanner.guard.cli.commands_dispatch_cloud_actions_status import (
        _ai_tool_states,  # pyright: ignore[reportPrivateUsage]
    )

    assert _configure(tmp_path, "codex", "--apply", "--json") == 0
    _ = capsys.readouterr()

    states = _ai_tool_states(argparse.Namespace(home=str(tmp_path), guard_home=None), URL)

    assert states["codex"]["state"] == "configured"


def test_a_relative_home_is_saved_as_an_absolute_guard_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)

    assert _configure(Path("user"), "codex", "--apply", "--json") == 0
    _ = capsys.readouterr()

    guard_home = Path(_codex_bridge_args(tmp_path / "user")[-1])
    assert guard_home.is_absolute()
    assert guard_home.is_relative_to(tmp_path.resolve()) or guard_home.is_relative_to(tmp_path)


def test_a_failed_end_of_access_leaves_the_settings_for_the_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from codex_plugin_scanner.guard.cli.cloud_actions_access import CloudActionsAccessError

    cloud = pair(monkeypatch)
    settings = tmp_path / ".codex" / "config.toml"
    settings.parent.mkdir()
    settings.write_text('model = "gpt-5"\n', encoding="utf-8")
    before = settings.read_bytes()
    assert _configure(tmp_path, "codex", "--apply", "--json") == 0
    applied = settings.read_bytes()
    cloud.revoke_error = CloudActionsAccessError("cloud_unreachable", "Guard Cloud could not be reached.")
    restore = ["cloud-actions", "ai-tools", "restore", "codex", "--home", str(tmp_path), "--json"]

    assert cli.main(restore) == 3
    assert settings.read_bytes() == applied
    cloud.revoke_error = None
    _ = capsys.readouterr()

    assert cli.main(restore) == 0
    assert json.loads(capsys.readouterr().out)["access_ended"] is True
    assert settings.read_bytes() == before
