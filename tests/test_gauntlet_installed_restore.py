"""Removing Guard must hand the user's own harness settings back byte for byte."""

from __future__ import annotations

import json
from pathlib import Path

from ci.gauntlet import installed_restore
from ci.gauntlet.installed_registration import load_contract

HARNESSES = ["claude-code", "codex", "muse", "omp", "zcode"]


class _Runtime:
    native_runtime = None


def _drive(tmp_path: Path, monkeypatch, *, uninstall) -> dict:
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
