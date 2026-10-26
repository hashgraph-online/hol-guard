from __future__ import annotations

import shutil
import tempfile
from functools import partial
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime.contained_command_prefix import _split_command_prefix
from codex_plugin_scanner.guard.runtime.contained_wrapper import anchored_sibling_root, peel_contained_wrapper


def sibling_home(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A home holding the hook workspace, a sibling repository and a plain directory."""
    home = tmp_path / "home"
    workspace = home / "project"
    sibling = home / "sibling"
    for directory in (workspace / ".git", sibling / ".git", sibling / "dashboard", sibling / "scripts", home / "loose"):
        directory.mkdir(parents=True)
    for script in (sibling / "scripts" / "report.py", home / "loose" / "probe.py", workspace / "notes.txt"):
        script.write_text("")
    return home, workspace, sibling


@pytest.fixture(autouse=True)
def _peel_from_the_resident(native_contained_wrapper_runtime: Path) -> None:
    """Every peel here is the classifier's answer, asked of the session resident."""


def test_quiet_or_sequenced_cd_into_a_sibling_repository_is_peeled(tmp_path: Path) -> None:
    home, workspace, sibling = sibling_home(tmp_path)
    dashboard = sibling / "dashboard"
    for command in (f"cd {dashboard} 2>/dev/null; vite build", f"cd {dashboard}; vite build"):
        assert peel_contained_wrapper(command, workspace=workspace, home=home) == (
            "vite build",
            dashboard.resolve(),
            None,
        )
    # Inside the workspace a failed cd would leave the core in the session
    # directory; other redirects are not the silenced cd.
    for command in (
        f"cd {workspace} 2>/dev/null; ls",
        f"cd {workspace}; ls",
        f"cd {dashboard} 2>/tmp/x; ls",
        f"cd {dashboard} 2>/dev/null | ls",
    ):
        with pytest.raises(ValueError):
            peel_contained_wrapper(command, workspace=workspace, home=home)


def test_an_absolute_script_in_a_sibling_repository_anchors_its_root(tmp_path: Path) -> None:
    home, workspace, sibling = sibling_home(tmp_path)
    script = sibling / "scripts" / "report.py"
    for command in (
        f"python3 {script} --top 40",
        f"python3 -m py_compile {script}",
        f"bun {script} --root={sibling / 'dashboard'}",
        # A heap size ahead of the script leaves the script as the program.
        f"node --max-old-space-size=4096 {script} --config jest.config.js",
    ):
        assert anchored_sibling_root(command, workspace=workspace, cwd=workspace, home=home) == sibling.resolve()
    for command in (
        f"python3 {home / 'loose' / 'probe.py'}",
        f"python3 {script} notes.txt",
        f"python3 {script} | wc -l",
        f"python3 {script} && ls",
        f"REPORT=1 python3 {script}",
        f"cd {sibling} && python3 {script}",
        f"python3 {workspace / 'notes.txt'}",
        f"python3 $HOME/{script.relative_to(home)}",
        # A sibling path that is only an operand runs nothing from there.
        f"rm {script}",
        f"cat {script}",
        f"jq . {script}",
        f"rg -n report {sibling}",
        f"python3 -c 1 {script}",
        # Only a bounded numeric heap size is peeled; any other option keeps
        # the script an operand of a program that runs from the session.
        f"node --max-old-space-size=0 {script}",
        f"node --max-old-space-size=4096k {script}",
        f"node --max-old-space-size={'9' * 5000} {script}",
        f"node --require=./hook.js {script}",
        f"node --max-old-space-size=4096 --require=./hook.js {script}",
    ):
        assert anchored_sibling_root(command, workspace=workspace, cwd=workspace, home=home) is None, command
    assert anchored_sibling_root(f"python3 {script}", workspace=workspace, cwd=workspace, home=None) is None


def test_a_temporary_or_enclosing_repository_anchors_no_root(tmp_path: Path) -> None:
    home, workspace, sibling = sibling_home(tmp_path)
    temporary = Path(tempfile.mkdtemp(prefix="guard-anchor-", dir="/tmp")).resolve()
    try:
        # A fresh `git init` in the shared temporary directory, outside home.
        (temporary / "scratch" / ".git").mkdir(parents=True)
        (temporary / "scratch" / "run.py").write_text("")
        # A linked worktree there whose shared `.git` is a checkout in home.
        linked, admin = temporary / "linked", sibling.resolve() / ".git" / "worktrees" / "linked"
        (linked / "scripts").mkdir(parents=True)
        admin.mkdir(parents=True)
        (admin / "commondir").write_text("../..\n")
        (admin / "gitdir").write_text(f"{linked / '.git'}\n")
        (linked / ".git").write_text(f"gitdir: {admin}\n")
        (linked / "scripts" / "run.py").write_text("")
        anchored = partial(anchored_sibling_root, workspace=workspace, cwd=workspace, home=home)
        assert anchored(f"python3 {temporary / 'scratch' / 'run.py'}") is None
        assert anchored(f"python3 {linked / 'scripts' / 'run.py'}") == linked
        # From a subdirectory, the session's own checkout is not a sibling.
        dashboard = sibling / "dashboard"
        script = sibling / "scripts" / "report.py"
        assert anchored_sibling_root(f"python3 {script}", workspace=dashboard, cwd=dashboard, home=home) is None
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def test_sink_runs_an_anchored_script_from_the_sibling_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    home, workspace, sibling = sibling_home(tmp_path)
    runs: list[tuple[Path, Path]] = []
    monkeypatch.setattr(sink, "receipt_matches", lambda receipt: receipt == {"profile": "workspace"})
    monkeypatch.setattr(
        sink,
        "run_workspace_contained",
        lambda payload, **kwargs: runs.append((kwargs["workspace"], kwargs["cwd"])) or 0,
    )
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {"command": f"python3 {sibling / 'scripts' / 'report.py'} --top 40"},
    }
    assert (
        sink.run_authorized_contained_test(
            payload,
            workspace=workspace,
            timeout_seconds=20,
            authorize=lambda _payload: {"profile": "workspace"},
            home_dir=home,
        )
        == 0
    )
    assert runs == [(sibling.resolve(), sibling.resolve())]


def test_plain_data_settings_are_dropped_and_others_stay(monkeypatch: pytest.MonkeyPatch) -> None:
    # No command here stands behind a transparent prefix, and the parser owns
    # that answer; the settings themselves are this module's subject.
    from codex_plugin_scanner.guard import native_restricted_pytest

    monkeypatch.setattr(native_restricted_pytest, "restricted_native", lambda *_args: None)
    assert _split_command_prefix(["REPORT_DIR=/tmp/report", "CI=1", "vitest", "run"], drop_data=True) == (
        ["vitest", "run"],
        {"CI": "1"},
    )
    for command in (
        ["PYTHONPATH=.", "pytest"],
        ["REPORT_DIR=$HOME/x", "pytest"],
        ["REPORT_DIR=-r", "pytest"],
        ["TMPDIR=/tmp/x", "pytest"],
    ):
        assert _split_command_prefix(command, drop_data=True) == (command, {})
