from __future__ import annotations

import io
import json
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import _build_parser
from codex_plugin_scanner.guard import workspace_assessment_worker as worker
from codex_plugin_scanner.guard.cli.codebase_commands import default_codebase_root, run_codebases_command
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.workspace_assessment_reads import list_worktrees
from tests.test_guard_workspace_assessment_runner import SNAPSHOT, snapshots

STAT = replace(SNAPSHOT, mode="stat")


def run(store: GuardStore, argv: list[str], *, config: GuardConfig | None = None) -> tuple[int, str]:
    args = _build_parser("hol-guard", program_mode="combined").parse_args(["guard", "codebases", *argv])
    output = io.StringIO()
    code = run_codebases_command(args, store=store, config=config, output_stream=output)
    return code, output.getvalue()


def test_add_admits_the_repository_holding_the_current_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "src").mkdir()
    monkeypatch.chdir(repo / "src")
    snapshots(monkeypatch, worker, STAT)
    store = GuardStore(tmp_path / "home")

    code, output = run(store, ["add", "--json"])

    assert code == 0
    payload = json.loads(output)
    assert payload["added"] is True and payload["run_id"]
    assert payload["root"] == str(repo.resolve())
    [worktree] = list_worktrees(store)
    assert worktree["root"] == str(repo.resolve())
    assert worktree["paused"] is False


def test_add_reports_a_missing_folder_without_admitting_anything(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")

    code, output = run(store, ["add", str(tmp_path / "missing")])

    assert code == 1
    assert output.startswith("Error: That folder does not exist.")
    assert list_worktrees(store) == []


def test_add_warns_when_background_checks_are_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshots(monkeypatch, worker, STAT)
    store = GuardStore(tmp_path / "home")

    config = GuardConfig(guard_home=tmp_path / "home", workspace=None, workspace_assessment_enabled=False)

    code, output = run(store, ["add", str(tmp_path)], config=config)

    assert code == 0
    assert "Background checks are turned off" in output


def test_list_names_each_codebase_and_points_to_add_when_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "home")
    assert "hol-guard codebases add" in run(store, ["list"])[1]

    snapshots(monkeypatch, worker, STAT)
    run(store, ["add", str(tmp_path)])
    code, output = run(store, ["list"])

    assert code == 0
    assert f"{tmp_path.resolve()}  (checking)" in output


def test_add_again_reports_the_codebase_without_queueing_another_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshots(monkeypatch, worker, STAT)
    store = GuardStore(tmp_path / "home")
    run(store, ["add", str(tmp_path)])
    [before] = list_worktrees(store)

    code, output = run(store, ["add", str(tmp_path)])

    assert code == 0
    assert output.startswith(f"Guard already checks {tmp_path.resolve()}.")
    [after] = list_worktrees(store)
    assert after["dirty_generation"] == before["dirty_generation"]


def test_add_reports_the_resolved_folder_it_admitted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshots(monkeypatch, worker, STAT)
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    store = GuardStore(tmp_path / "home")

    payload = json.loads(run(store, ["add", str(tmp_path / "link"), "--json"])[1])

    assert payload["root"] == str(real.resolve()) == list_worktrees(store)[0]["root"]


def test_options_before_the_subcommand_are_kept() -> None:
    parser = _build_parser("hol-guard", program_mode="combined")

    before = parser.parse_args(["guard", "codebases", "--home", "/x", "--json", "add", "/repo"])
    after = parser.parse_args(["guard", "codebases", "list", "--home", "/y", "--json"])
    neither = parser.parse_args(["guard", "codebases", "list"])

    assert (before.home, before.json, before.path) == ("/x", True, "/repo")
    assert (after.home, after.json) == ("/y", True)
    assert (neither.home, neither.json) == (None, False)


def test_list_shows_a_failed_check_as_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshots(monkeypatch, worker, STAT)
    store = GuardStore(tmp_path / "home")
    run(store, ["add", str(tmp_path)])
    with store._connect() as connection:
        connection.execute("update workspace_assessment_runs set state = 'failed', finished_at_ms = created_at_ms")

    payload = json.loads(run(store, ["list", "--json"])[1])

    assert [item["check_state"] for item in payload["codebases"]] == ["last check failed"]
    assert f"{tmp_path.resolve()}  (last check failed)" in run(store, ["list"])[1]


def test_default_root_falls_back_to_the_folder_outside_a_repository(tmp_path: Path) -> None:
    assert default_codebase_root(tmp_path) == tmp_path


def test_there_is_no_command_that_stops_checks() -> None:
    parser = _build_parser("hol-guard", program_mode="combined")
    for command in ("remove", "pause", "disable"):
        with pytest.raises(SystemExit):
            parser.parse_args(["guard", "codebases", command])
