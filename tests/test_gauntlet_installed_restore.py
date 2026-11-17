"""Removing Guard must hand the user's own harness settings back byte for byte."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ci.gauntlet import installed_restore
from ci.gauntlet.installed_registration import load_contract

HARNESSES = ["claude-code", "codex", "muse", "omp", "zcode"]


class _Runtime:
    native_runtime = None


def _drive(tmp_path: Path, monkeypatch, *, uninstall, registered: bool = True) -> dict:
    contract = load_contract()
    saved: dict[Path, bytes] = {}

    def install(runtime, harness, *, home, guard_home, workspace):
        path = home / contract["harnesses"][harness]["config"]
        saved[path] = path.read_bytes()
        if path.suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            data["hooks"] = {"guard": "installed"}
            path.write_text(json.dumps(data), encoding="utf-8")
        else:
            path.write_text(path.read_text(encoding="utf-8") + "\n[hooks]\nguard = true\n", encoding="utf-8")
        return {"harness": harness, "exit_code": 0, "payload": {}, "stderr_tail": ""}

    def remove(runtime, harness, *, home, guard_home, workspace):
        path = home / contract["harnesses"][harness]["config"]
        uninstall(path, saved[path], workspace)
        return {"harness": harness, "exit_code": 0, "stderr_tail": ""}

    monkeypatch.setattr(installed_restore, "install_harness", install)
    monkeypatch.setattr(installed_restore, "uninstall_harness", remove)
    monkeypatch.setattr(installed_restore, "stop_daemon", lambda runtime, *, home, guard_home: 0)
    monkeypatch.setattr(
        installed_restore,
        "assess_harness",
        lambda home, harness, expectation: {"harness": harness, "registered": registered, "failures": []},
    )
    workspace = tmp_path / "restore" / "workspace"
    workspace.mkdir(parents=True)
    return installed_restore.restore_pass(
        _Runtime(), HARNESSES, contract, home=tmp_path / "home-restore", workspace=workspace
    )


def test_an_uninstall_that_restores_every_byte_passes(tmp_path: Path, monkeypatch) -> None:
    result = _drive(tmp_path, monkeypatch, uninstall=lambda path, before, workspace: path.write_bytes(before))
    assert result["passed"] is True
    assert len(result["files"]) == len(HARNESSES) + 1
    assert all(row["bytes_identical"] for row in result["files"])


def test_a_reformatted_file_fails_even_when_its_settings_survive(tmp_path: Path, monkeypatch) -> None:
    def reformat(path: Path, before: bytes, workspace: Path) -> None:
        if path.suffix == ".json":
            path.write_text(json.dumps(json.loads(before)), encoding="utf-8")
        else:
            path.write_bytes(before)

    result = _drive(tmp_path, monkeypatch, uninstall=reformat)
    assert result["passed"] is False
    changed = [row for row in result["files"] if not row["bytes_identical"]]
    assert changed and all(row["parsed_equal"] is True for row in changed)
    assert any("parsed_equal=True" in failure for failure in result["failures"])


def test_an_uninstall_that_drops_a_user_hook_fails(tmp_path: Path, monkeypatch) -> None:
    def drop_hooks(path: Path, before: bytes, workspace: Path) -> None:
        if path.parent.name == ".claude":
            data = json.loads(before)
            data.pop("hooks")
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        else:
            path.write_bytes(before)

    result = _drive(tmp_path, monkeypatch, uninstall=drop_hooks)
    changed = [row for row in result["files"] if not row["bytes_identical"]]
    assert [row["path"] for row in changed] == ["home/.claude/settings.json"]
    assert changed[0]["parsed_equal"] is False


def test_a_workspace_project_file_that_changes_fails(tmp_path: Path, monkeypatch) -> None:
    def touch_project(path: Path, before: bytes, workspace: Path) -> None:
        path.write_bytes(before)
        (workspace / ".claude" / "settings.local.json").write_text("{}\n", encoding="utf-8")

    result = _drive(tmp_path, monkeypatch, uninstall=touch_project)
    assert result["passed"] is False
    assert any(failure.startswith("workspace/.claude/settings.local.json") for failure in result["failures"])


def test_a_failed_uninstall_is_a_failure(tmp_path: Path, monkeypatch) -> None:
    result = _drive(tmp_path, monkeypatch, uninstall=lambda path, before, workspace: path.write_bytes(before))
    assert result["passed"] is True
    monkeypatch.setattr(
        installed_restore,
        "uninstall_harness",
        lambda runtime, harness, *, home, guard_home, workspace: {
            "harness": harness,
            "exit_code": 4,
            "stderr_tail": "boom",
        },
    )
    second = installed_restore.restore_pass(
        _Runtime(), ["muse"], load_contract(), home=tmp_path / "again", workspace=tmp_path / "again-ws"
    )
    assert any("muse: uninstall exited 4" in failure for failure in second["failures"])


def test_an_install_that_registers_nothing_fails(tmp_path: Path, monkeypatch) -> None:
    result = _drive(
        tmp_path, monkeypatch, uninstall=lambda path, before, workspace: path.write_bytes(before), registered=False
    )
    assert result["passed"] is False
    assert any("install exited 0 but Guard is not registered" in failure for failure in result["failures"])


def test_a_hung_uninstall_is_recorded_and_the_daemon_still_stops(tmp_path: Path, monkeypatch) -> None:
    _drive(tmp_path, monkeypatch, uninstall=lambda path, before, workspace: path.write_bytes(before))
    stopped: list[Path] = []

    def hang(runtime, harness, *, home, guard_home, workspace):
        raise subprocess.TimeoutExpired(cmd="uninstall", timeout=300)

    monkeypatch.setattr(installed_restore, "uninstall_harness", hang)
    monkeypatch.setattr(
        installed_restore, "stop_daemon", lambda runtime, *, home, guard_home: stopped.append(home) or 0
    )
    result = installed_restore.restore_pass(
        _Runtime(), ["muse"], load_contract(), home=tmp_path / "hung", workspace=tmp_path / "hung-ws"
    )
    assert stopped == [tmp_path / "hung"]
    assert result["uninstall"][0]["exit_code"] is None
    assert any("muse: uninstall exited None: uninstall timed out" in failure for failure in result["failures"])


def test_a_hung_install_is_recorded_and_the_pass_still_compares(tmp_path: Path, monkeypatch) -> None:
    _drive(tmp_path, monkeypatch, uninstall=lambda path, before, workspace: path.write_bytes(before))

    def hang(runtime, harness, *, home, guard_home, workspace):
        raise subprocess.TimeoutExpired(cmd="install", timeout=600)

    monkeypatch.setattr(installed_restore, "install_harness", hang)
    monkeypatch.setattr(
        installed_restore,
        "uninstall_harness",
        lambda runtime, harness, *, home, guard_home, workspace: {
            "harness": harness,
            "exit_code": 0,
            "stderr_tail": "",
        },
    )
    result = installed_restore.restore_pass(
        _Runtime(), ["muse"], load_contract(), home=tmp_path / "hung", workspace=tmp_path / "hung-ws"
    )
    assert result["install"] == [None]
    assert len(result["uninstall"]) == 1
    assert result["files"]
    assert any("muse: install exited None: install timed out" in failure for failure in result["failures"])


def test_a_project_file_changed_and_put_back_is_still_reported(tmp_path: Path, monkeypatch) -> None:
    contract = load_contract()

    def install(runtime, harness, *, home, guard_home, workspace):
        (workspace / ".claude" / "settings.local.json").write_text("{}", encoding="utf-8")
        return {"harness": harness, "exit_code": 0, "payload": {}, "stderr_tail": ""}

    def remove(runtime, harness, *, home, guard_home, workspace):
        project = workspace / ".claude" / "settings.local.json"
        project.write_text(installed_restore.PROJECT_LOCAL_SETTINGS, encoding="utf-8", newline="\n")
        return {"harness": harness, "exit_code": 0, "stderr_tail": ""}

    monkeypatch.setattr(installed_restore, "install_harness", install)
    monkeypatch.setattr(installed_restore, "uninstall_harness", remove)
    monkeypatch.setattr(installed_restore, "stop_daemon", lambda runtime, *, home, guard_home: 0)
    monkeypatch.setattr(
        installed_restore,
        "assess_harness",
        lambda home, harness, expectation: {"harness": harness, "registered": True, "failures": []},
    )
    workspace = tmp_path / "ws"
    workspace.mkdir()
    result = installed_restore.restore_pass(_Runtime(), ["muse"], contract, home=tmp_path / "h", workspace=workspace)
    project = next(row for row in result["files"] if row["path"] == "workspace/.claude/settings.local.json")
    assert project["bytes_identical"] is True
    assert result["passed"] is False
    assert "workspace/.claude/settings.local.json: changed by muse install" in result["failures"]


def test_a_project_file_change_is_blamed_on_the_one_step_that_made_it(tmp_path: Path, monkeypatch) -> None:
    contract = load_contract()
    harnesses = ["claude-code", "muse"]

    def install(runtime, harness, *, home, guard_home, workspace):
        if harness == "claude-code":
            (workspace / ".claude" / "settings.local.json").write_text("{}", encoding="utf-8")
        return {"harness": harness, "exit_code": 0, "payload": {}, "stderr_tail": ""}

    monkeypatch.setattr(installed_restore, "install_harness", install)
    monkeypatch.setattr(
        installed_restore,
        "uninstall_harness",
        lambda runtime, harness, *, home, guard_home, workspace: {
            "harness": harness,
            "exit_code": 0,
            "stderr_tail": "",
        },
    )
    monkeypatch.setattr(installed_restore, "stop_daemon", lambda runtime, *, home, guard_home: 0)
    monkeypatch.setattr(
        installed_restore,
        "assess_harness",
        lambda home, harness, expectation: {"harness": harness, "registered": True, "failures": []},
    )
    workspace = tmp_path / "ws"
    workspace.mkdir()
    result = installed_restore.restore_pass(_Runtime(), harnesses, contract, home=tmp_path / "h", workspace=workspace)
    blamed = [failure for failure in result["failures"] if "changed by" in failure]
    assert blamed == ["workspace/.claude/settings.local.json: changed by claude-code install"]
