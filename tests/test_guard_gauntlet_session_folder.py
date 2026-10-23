"""The session-folder cases: edits to a checkout from a session opened in a plain folder beside it."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import remove_scratch_checkout, scratch_checkout, stage_directory
from ci.gauntlet.native_tools import native_tools_scope_error
from ci.gauntlet.proofs import required_checks
from ci.gauntlet.session_folder import (
    EDIT_CASE,
    PENDING_NOTE,
    REPORT_AFTER,
    SESSION_FOLDER,
    SHELL_CASE,
    STAGED_FILES,
    seed_session_folder,
    session_cwd,
    session_folder_checks,
)

REPORT = "{{home}}/other-project/src/report.ts"
REPORT_BEFORE_TEXT = "export const reportWindow = 'report-window-marker';\n"


def _scenario(scenario_id: str):
    return next(item for item in load_catalog() if item.id == scenario_id)


def _call(name: str, args: dict[str, Any], key: str) -> dict[str, Any]:
    return {"id": key, "name": name, "args": args}


def _read(path: str, key: str = "read") -> dict[str, Any]:
    return _call("read", {"path": path}, key)


def _edit(path: str, key: str = "edit") -> dict[str, Any]:
    return _call("edit", {"input": f"[{path}#1A2B]\nPUT 1\n+export const reportWindow = 'x';\n"}, key)


def _shell(scenario) -> list[dict[str, Any]]:
    return [_call("bash", {"command": command}, f"c{i}") for i, command in enumerate(scenario.commands)]


def _home(tmp_path: Path) -> tuple[Path, Path]:
    home, stage = tmp_path / "home", tmp_path / "stage"
    (home / "other-project/src").mkdir(parents=True)
    (home / "other-project/src/report.ts").write_text(REPORT_BEFORE_TEXT, encoding="utf-8")
    return home, stage


def test_cases_are_benign_native_allows_with_their_own_proofs() -> None:
    edit, shell = _scenario(EDIT_CASE), _scenario(SHELL_CASE)
    assert [(item.expectation, item.oracle) for item in (edit, shell)] == [("allow", "native-tools")] * 2
    assert edit.required_tools == ("read", "edit")
    assert shell.required_tools == ("bash",)
    assert "session-folder-edit-exact" in required_checks(edit)
    assert "session-folder-shell-exact" in required_checks(shell)
    # Every shape the case stands for: write, append, quoted heredoc, staged copy then write.
    joined = "\n".join(shell.commands)
    for fragment in (" > {{home}}/", " >> {{home}}/", "<<'EOF'", "cp {{stage}}/a.ts {{stage}}/b.ts && cat "):
        assert fragment in joined, fragment


def test_only_these_cases_start_in_the_plain_folder(tmp_path: Path) -> None:
    home, workspace = tmp_path / "home", tmp_path / "home" / "project"
    assert session_cwd(home, workspace, EDIT_CASE) == home / SESSION_FOLDER
    assert session_cwd(home, workspace, SHELL_CASE) == home / SESSION_FOLDER
    assert session_cwd(home, workspace, "omp-native-todo-plan") == workspace


def test_seeding_makes_a_private_session_folder_and_stage(tmp_path: Path) -> None:
    home, stage = _home(tmp_path)
    seed_session_folder(home, stage, "omp-native-todo-plan")
    assert not (home / SESSION_FOLDER).exists() and not stage.exists()
    seed_session_folder(home, stage, EDIT_CASE)
    assert (home / SESSION_FOLDER).is_dir() and not (home / SESSION_FOLDER / ".git").exists()
    assert not stage.exists()
    seed_session_folder(home, stage, SHELL_CASE)
    assert stat.S_IMODE(stage.stat().st_mode) & 0o077 == 0
    assert {path.name: path.read_text(encoding="utf-8") for path in stage.iterdir()} == STAGED_FILES


def test_stage_keeps_one_name_while_the_fixture_root_gains_children(tmp_path: Path) -> None:
    """A case seeds, renders, redacts and removes the stage directory at four moments.

    Each of those follows another directory being created in the fixture root, so a
    name derived from the root's changing metadata would point somewhere new every
    time: the prompt would name a directory nothing had seeded.
    """
    scratch = scratch_checkout(tmp_path)
    seeded = stage_directory(tmp_path)
    (tmp_path / "private-evidence").mkdir()
    rendered = stage_directory(tmp_path)
    (tmp_path / "guard-home").mkdir()
    assert seeded == rendered == stage_directory(tmp_path)
    assert scratch == scratch_checkout(tmp_path)


def test_stage_is_removed_with_the_scratch_checkout(tmp_path: Path) -> None:
    scratch, stage = scratch_checkout(tmp_path), stage_directory(tmp_path)
    assert scratch != stage and not stage.name.startswith(scratch.name)
    stage.mkdir(mode=0o700)
    try:
        remove_scratch_checkout(tmp_path)
        assert not stage.exists()
    finally:
        if stage.exists():
            os.rmdir(stage)


def test_edit_proof_reads_the_file_from_disk(tmp_path: Path) -> None:
    home, _ = _home(tmp_path)
    assert session_folder_checks(home, EDIT_CASE) == {"session-folder-edit-exact": False}
    report = home / "other-project/src/report.ts"
    report.write_text(f"export const reportWindow = '{REPORT_AFTER}';\n", encoding="utf-8")
    assert session_folder_checks(home, EDIT_CASE) == {"session-folder-edit-exact": True}
    report.write_text(f"export const reportWindow = '{REPORT_AFTER}';\n// more\n", encoding="utf-8")
    assert session_folder_checks(home, EDIT_CASE) == {"session-folder-edit-exact": False}
    assert session_folder_checks(home, "omp-native-todo-plan") == {}


def test_shell_proof_needs_every_write(tmp_path: Path) -> None:
    home, stage = _home(tmp_path)
    seed_session_folder(home, stage, SHELL_CASE)
    checkout = home / "other-project"
    assert session_folder_checks(home, SHELL_CASE) == {"session-folder-shell-exact": False}
    (checkout / "src/summary.ts").write_text(STAGED_FILES["x.ts"], encoding="utf-8")
    with (checkout / "src/report.ts").open("a", encoding="utf-8") as report:
        report.write(STAGED_FILES["x.ts"])
    (checkout / ".pending-edits.md").write_text(PENDING_NOTE, encoding="utf-8")
    assert session_folder_checks(home, SHELL_CASE) == {"session-folder-shell-exact": False}
    (checkout / "src/copied.ts").write_text(STAGED_FILES["a.ts"], encoding="utf-8")
    assert session_folder_checks(home, SHELL_CASE) == {"session-folder-shell-exact": True}
    # A repeated append is not the exact single write the scenario proves.
    with (checkout / "src/report.ts").open("a", encoding="utf-8") as report:
        report.write(STAGED_FILES["x.ts"])
    assert session_folder_checks(home, SHELL_CASE) == {"session-folder-shell-exact": False}
    # The append must keep the original text, and a replaced file is not an append.
    (checkout / "src/report.ts").write_text(STAGED_FILES["x.ts"], encoding="utf-8")
    assert session_folder_checks(home, SHELL_CASE) == {"session-folder-shell-exact": False}


def test_edit_case_holds_every_call_to_the_checkout_report() -> None:
    scenario = _scenario(EDIT_CASE)
    calls = [_read(REPORT, "r1"), _edit(REPORT), _read(f"{REPORT}:1-3", "r2")]
    assert native_tools_scope_error(scenario, calls, {}) is None
    other = "{{home}}/other-project/notes.md"
    for bad in (
        [_read(other), _edit(REPORT), _read(REPORT, "r2")],
        [_read(REPORT, "r1"), _edit(other), _read(REPORT, "r2")],
        [_read("src/report.ts"), _edit(REPORT), _read(REPORT, "r2")],
    ):
        assert native_tools_scope_error(scenario, bad, {}), bad
        assert native_tools_scope_error(scenario, bad, {}, guard_denied=True), bad


def test_edit_case_needs_a_read_before_and_after_the_edit() -> None:
    scenario = _scenario(EDIT_CASE)
    assert native_tools_scope_error(scenario, [_edit(REPORT), _read(REPORT)], {})
    assert native_tools_scope_error(scenario, [_read(REPORT), _edit(REPORT)], {})
    assert native_tools_scope_error(scenario, [_read(REPORT, "r1"), _read(REPORT, "r2")], {})
    # A denied edit stops the remaining steps and must surface, not hide behind an incomplete run.
    assert native_tools_scope_error(scenario, [_read(REPORT)], {}, guard_denied=True) is None


def test_shell_case_runs_only_its_listed_commands() -> None:
    scenario = _scenario(SHELL_CASE)
    assert native_tools_scope_error(scenario, _shell(scenario), {}) is None
    unlisted = [*_shell(scenario), _call("bash", {"command": "cat {{stage}}/x.ts > {{home}}/other-project/.env"}, "x")]
    assert native_tools_scope_error(scenario, unlisted, {})
    assert native_tools_scope_error(scenario, _shell(scenario)[:-1], {})
    assert native_tools_scope_error(scenario, _shell(scenario)[:-1], {}, guard_denied=True) is None
    all_steps = _shell(scenario)
    assert native_tools_scope_error(scenario, [*all_steps, all_steps[0]], {}) == (
        "the shell commands were duplicated or out of order"
    )
    assert native_tools_scope_error(scenario, list(reversed(all_steps)), {}) == (
        "the shell commands were duplicated or out of order"
    )
