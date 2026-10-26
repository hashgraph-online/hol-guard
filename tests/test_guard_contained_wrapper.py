from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime import restricted_vitest
from codex_plugin_scanner.guard.runtime.contained_wrapper import (
    OutputFilter,
    bounded_output,
    peel_contained_wrapper,
    sibling_project_root,
)
from codex_plugin_scanner.guard.runtime.restricted_node_test import nearest_project_root
from codex_plugin_scanner.guard.runtime.restricted_package_test import resolve_package_test
from codex_plugin_scanner.guard.runtime.restricted_pytest import RestrictedPytestError


def required_profile() -> dict[str, object]:
    return {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_pytest_readonly_containment_required",
        "required_execution_profile": "pytest-readonly-v2",
    }


@pytest.fixture(autouse=True)
def _peel_from_the_resident(native_contained_wrapper_runtime: Path) -> None:
    """Every peel here is the classifier's answer, asked of the session resident."""


def test_peels_verified_cd_and_bounded_filters(tmp_path: Path) -> None:
    web = tmp_path / "web dir"
    web.mkdir()
    resolved = web.resolve()
    assert peel_contained_wrapper(f"cd '{web}' && pytest -q 2>&1 | tail -20", workspace=tmp_path) == (
        "pytest -q",
        resolved,
        OutputFilter("tail", 20, merge_stderr=True),
    )
    assert peel_contained_wrapper("pytest -k 'a b' | head -n 5", workspace=tmp_path) == (
        "pytest -k 'a b'",
        tmp_path,
        OutputFilter("head", 5, merge_stderr=False),
    )
    assert peel_contained_wrapper(f"cd {tmp_path} && pytest -q", workspace=tmp_path) == (
        "pytest -q",
        tmp_path.resolve(),
        None,
    )
    assert peel_contained_wrapper("pytest -q", workspace=tmp_path) is None
    # An inline program's `;` is code: `node -e` runs as one argv in the sandbox.
    assert peel_contained_wrapper(f"cd '{web}' && node -e \"a(); b()\"", workspace=tmp_path) == (
        "node -e 'a(); b()'",
        resolved,
        None,
    )


@pytest.mark.parametrize(
    ("command", "core", "output"),
    [
        (
            'python3 -m unittest -q 2>&1; echo "exit=$?"',
            "python3 -m unittest -q",
            OutputFilter("all", 0, True, "exit="),
        ),
        (
            'pytest -q 2>&1 | tail -5 ; echo "EXIT CODE: $?"',
            "pytest -q",
            OutputFilter("tail", 5, True, "EXIT CODE: "),
        ),
        ("pytest -q; echo $?", "pytest -q", OutputFilter("all", 0, False, "")),
        ("pytest -q 2>&1", "pytest -q", OutputFilter("all", 0, True)),
    ],
)
def test_peels_merged_stderr_and_final_status_echo(
    tmp_path: Path, command: str, core: str, output: OutputFilter
) -> None:
    assert peel_contained_wrapper(command, workspace=tmp_path) == (core, tmp_path, output)


def test_status_echo_reports_the_shell_status() -> None:
    assert OutputFilter("all", 0, True, "exit=").status_line(3) == "exit=3\n"
    # After a pipe, `$?` is the filter's status, not the producer's.
    assert OutputFilter("tail", 5, True, "exit=").status_line(3) == "exit=0\n"
    assert OutputFilter("all", 0, True).status_line(3) is None


@pytest.mark.parametrize(
    "command",
    [
        "cd {web} && pytest -q && rm -rf /",
        "cd {web} && pytest -q; echo 'exit=$?'",
        'cd {web} && pytest -q; echo "exit=$?" > out.txt',
        'cd {web} && pytest -q; echo "$(id)$?"',
        'cd {web} && pytest -q; echo "exit=$?"; rm -rf /',
        'cd {web} && pytest -q; rm -rf /; echo "exit=$?"',
        'cd {web} && pytest -q; echo "exit=$?" "$?"',
        "cd {web} && pytest -q; echo exit is $?",
        "cd {web} && pytest -q; ls",
        "cd {web} && cd .. && pytest -q",
        "cd {outside} && pytest -q",
        "cd {web}/missing && pytest -q",
        "cd web && pytest -q",
        "cd {web}; pytest -q",
        "pytest -q | tail -f",
        "pytest -q | tail -20 notes.txt",
        "pytest -q | tail -n 1234567",
        "pytest -q | sh",
        "pytest -q | tee out.txt",
        "pytest -q | tail -20 | sh",
        "pytest -q 2>/dev/null | tail -20",
        "pytest -q > out.txt | tail -20",
        "pytest -q | tail -20 &",
        "pytest (x) | tail -5",
        "pytest $FOO | tail -5",
        'pytest "$FOO" | tail -5',
        "pytest `id` | tail -5",
        "pytest tests/*.py | tail -5",
        "pytest ~/tests | tail -5",
        "pytest -q # note | tail -5",
        "cd $HOME && pytest -q",
        "pytest -k 'a;b' | tail -5",
        "node -e 'a;b' extra | tail -5",
        "node -p 'a;b' | tail -5",
        "bash -c 'a;b' | tail -5",
        "cd {web} && sh -c 'a;b'",
        'pytest -k "a>b" | tail -5',
        "pytest -q foo2>&1 | tail -5",
        "pytest -q 2>&1 > out.txt | tail -5",
        "pytest 'open | tail -5",
        "pytest -q | 'tail' -5 -5",
    ],
)
def test_rejects_other_wrapper_shapes(tmp_path: Path, command: str) -> None:
    workspace = tmp_path / "project"
    (workspace / "web").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    with pytest.raises((ValueError, OSError)):
        peel_contained_wrapper(command.format(web=workspace / "web", outside=tmp_path / "outside"), workspace=workspace)


@pytest.mark.parametrize("command", ["pytest -q '|' tail -20", "pytest -q |& tail -20", "pytest -q || tail -20"])
def test_other_operators_are_left_to_the_strict_unwrapped_path(tmp_path: Path, command: str) -> None:
    assert peel_contained_wrapper(command, workspace=tmp_path) is None


@pytest.mark.parametrize(
    ("command", "core", "output"),
    [
        ("python3 -c 'print(1)' | tail -20", "python3 -c 'print(1)'", OutputFilter("tail", 20, False)),
        (
            "bunx vitest run --testNamePattern='a b' 2>&1 | tail -5",
            "bunx vitest run '--testNamePattern=a b'",
            OutputFilter("tail", 5, True),
        ),
        ("pytest tests/a\\ b.py | head -3", "pytest 'tests/a b.py'", OutputFilter("head", 3, False)),
        ('pytest -k "a \\"b\\" (c)" | head -n 2', "pytest -k 'a \"b\" (c)'", OutputFilter("head", 2, False)),
        ("pytest -q '|' x | tail -1", "pytest -q x", None),
        (
            'node -e "a(); if (!b) c(1); d()" | tail -3',
            "node -e 'a(); if (!b) c(1); d()'",
            OutputFilter("tail", 3, False),
        ),
        (
            "python3 -c 'import sys; print(1 if sys else 0)' 2>&1 | head -2",
            "python3 -c 'import sys; print(1 if sys else 0)'",
            OutputFilter("head", 2, True),
        ),
    ],
)
def test_quoted_words_are_single_arguments(tmp_path: Path, command: str, core: str, output: OutputFilter) -> None:
    if output is None:
        with pytest.raises(ValueError):
            peel_contained_wrapper(command, workspace=tmp_path)
        return
    assert peel_contained_wrapper(command, workspace=tmp_path) == (core, tmp_path, output)


def test_sandbox_merge_keeps_alternating_writes_in_order(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    script = tmp_path / "alternate.py"
    script.write_text(
        "import sys\n"
        "sys.stdout.write('A\\n')\n"
        "sys.stdout.flush()\n"
        "sys.stderr.write('B\\n')\n"
        "sys.stderr.flush()\n"
        "sys.stdout.write('C\\n')\n"
        "sys.stdout.flush()\n",
        encoding="utf-8",
    )
    import os
    import sys

    from codex_plugin_scanner.guard.runtime.restricted_pytest_sandbox import _run_backend_process

    def run(*, merge_stderr: bool) -> tuple[int, str, str]:
        code = _run_backend_process(
            [sys.executable, str(script)],
            env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"},
            timeout_seconds=30,
            cwd=tmp_path,
            merge_stderr=merge_stderr,
        )
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    assert run(merge_stderr=True) == (0, "A\nB\nC\n", "")
    assert run(merge_stderr=False) == (0, "A\nC\n", "B\n")


def emit() -> None:
    import sys

    for index in range(4):
        print(f"out {index}")
    for index in range(3):
        print(f"err {index}", file=sys.stderr)


def test_output_filter_runs_in_process(capsys: pytest.CaptureFixture[str]) -> None:
    with bounded_output(OutputFilter("tail", 2, merge_stderr=False)):
        emit()
    captured = capsys.readouterr()
    assert captured.out == "out 2\nout 3\n"
    assert captured.err == "err 0\nerr 1\nerr 2\n"
    # In-process writes keep call order. emit() finishes stdout before stderr.
    with bounded_output(OutputFilter("tail", 4, merge_stderr=True)):
        emit()
    assert capsys.readouterr() == ("out 3\nerr 0\nerr 1\nerr 2\n", "")
    with bounded_output(OutputFilter("head", 5, merge_stderr=True)):
        emit()
    assert capsys.readouterr().out == "out 0\nout 1\nout 2\nout 3\nerr 0\n"
    with bounded_output(OutputFilter("tail", 0, merge_stderr=False)):
        emit()
    assert capsys.readouterr().out == ""


def test_sink_reauthorizes_the_core_in_its_resolved_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web = tmp_path / "web"
    web.mkdir()
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(sink, "prepare_restricted_pytest", lambda *args, **kwargs: None)

    def execute(*args, **kwargs):
        calls.append(("execute", (args, kwargs["workspace"], kwargs["cwd"])))
        emit()
        return 0

    def authorize(original):
        calls.append(("authorize", (original["tool_input"]["command"], original.get("cwd"))))
        return required_profile()

    monkeypatch.setattr(sink, "run_restricted_pytest", execute)
    original = {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {"command": f"cd {web} && pytest -q 2>&1 | tail -20"},
        "cwd": str(tmp_path),
    }
    exit_code = sink.run_authorized_contained_test(
        original, workspace=tmp_path, timeout_seconds=20, authorize=authorize
    )
    assert exit_code == 0
    resolved = web.resolve()
    # The approved root stays the workspace; the cd target is only the working directory.
    assert calls == [
        ("authorize", (original["tool_input"]["command"], str(tmp_path))),
        ("authorize", ("pytest -q", str(resolved))),
        ("execute", ((["pytest", "-q"],), tmp_path, resolved)),
    ]
    lines = [f"out {index}\n" for index in range(4)] + [f"err {index}\n" for index in range(3)]
    assert capsys.readouterr() == ("".join(lines), "")


def test_sink_prints_the_status_echo_after_contained_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(sink, "prepare_restricted_pytest", lambda *args, **kwargs: None)

    def execute(*args, **kwargs):
        emit()
        return 1

    def authorize(original):
        calls.append(original["tool_input"]["command"])
        return required_profile()

    monkeypatch.setattr(sink, "run_restricted_pytest", execute)
    original = {"tool_name": "bash", "tool_input": {"command": 'pytest -q 2>&1; echo "exit=$?"'}}
    exit_code = sink.run_authorized_contained_test(
        original, workspace=tmp_path, timeout_seconds=20, authorize=authorize
    )
    assert exit_code == 0
    assert calls == ['pytest -q 2>&1; echo "exit=$?"', "pytest -q"]
    lines = [f"out {index}\n" for index in range(4)] + [f"err {index}\n" for index in range(3)]
    assert capsys.readouterr() == ("".join(lines) + "exit=1\n", "")


@pytest.mark.parametrize("failure", ["allow", "review", "watch", "no-profile"])
def test_sink_needs_a_receipt_for_the_wrapped_original(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    executed = []
    monkeypatch.setattr(sink, "prepare_restricted_pytest", lambda *args, **kwargs: None)
    monkeypatch.setattr(sink, "run_restricted_pytest", lambda *args, **kwargs: executed.append(args) or 0)
    wrapped = required_profile()
    if failure == "allow":
        wrapped.update(decision="allow", policy_action="allow")
    elif failure == "review":
        wrapped["policy_action"] = "review"
    elif failure == "watch":
        wrapped["observe_mode"] = True
    else:
        del wrapped["required_execution_profile"]

    def authorize(original):
        return wrapped if "|" in original["tool_input"]["command"] else required_profile()

    original = {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": "pytest -q | tail -5"}}
    with pytest.raises(RestrictedPytestError):
        sink.run_authorized_contained_test(original, workspace=tmp_path, timeout_seconds=20, authorize=authorize)
    assert executed == []


def test_sink_rejects_unpeelable_wrappers_without_a_workspace_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sink, "run_workspace_contained", lambda *args, **kwargs: pytest.fail("ran"))
    original = {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": "pytest -q | sh"}}
    for receipt in (None, required_profile()):
        seen: list[object] = []
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(
                original,
                workspace=tmp_path,
                timeout_seconds=20,
                authorize=lambda value, receipt=receipt, seen=seen: seen.append(value) or receipt,
            )
        # Only the command as issued is checked; nothing peeled runs.
        assert seen == [original]


def test_subdirectory_runs_resolve_from_the_workspace_root(tmp_path: Path) -> None:
    web = tmp_path / "web"
    (web / "src").mkdir(parents=True)
    (tmp_path / "node_modules" / "vitest").mkdir(parents=True)
    (tmp_path / "node_modules" / "vitest" / "vitest.mjs").write_text("")
    root = tmp_path.resolve()
    # Hoisted dependencies are found from a package directory with no markers of its own.
    assert nearest_project_root(web / "src", tmp_path, "node_modules/vitest/vitest.mjs") == root
    assert nearest_project_root(web, tmp_path, "package.json") == root
    (web / "package.json").write_text('{"scripts": {"test": "node --test"}}')
    (tmp_path / "package.json").write_text('{"scripts": {"test": "vitest run"}}')
    assert nearest_project_root(web / "src", tmp_path, "package.json") == web.resolve()
    assert nearest_project_root(tmp_path.parent, tmp_path, "package.json") == root
    assert resolve_package_test(["npm", "test"], workspace=tmp_path, cwd=web)[:2] == ("node", "--test")
    assert resolve_package_test(["npm", "test"], workspace=tmp_path)[:2] == ("vitest", "run")


def test_bunx_cwd_selects_a_directory_inside_the_workspace(tmp_path: Path) -> None:
    assert restricted_vitest.bun_vitest_invocation(["bunx", "--cwd", "web", "vitest", "run", "x"]) == (
        "web",
        ("run", "x"),
    )
    assert restricted_vitest.bun_vitest_invocation(["bunx", "--cwd=web", "vitest", "run"]) == ("web", ("run",))
    assert restricted_vitest.bun_vitest_invocation(["bunx", "vitest", "run"]) is None
    assert restricted_vitest.bun_vitest_invocation(["bunx", "--cwd", "web", "x", "vitest", "run"]) is None
    workspace = tmp_path / "project"
    workspace.mkdir()
    (tmp_path / "other").mkdir()
    with pytest.raises(RestrictedPytestError, match="working directory"):
        restricted_vitest.prepare_restricted_vitest(
            ["bunx", "--cwd", "../other", "vitest", "run"], workspace=workspace, cwd=workspace
        )


def sibling_home(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A home holding the hook workspace and a sibling linked worktree."""
    home = tmp_path / "home"
    workspace = home / "project"
    sibling = home / "sibling-worktree"
    (workspace / "web").mkdir(parents=True)
    (sibling / "dashboard").mkdir(parents=True)
    (sibling / ".git").write_text("gitdir: /nonexistent\n")
    (home / "loose").mkdir()
    return home, workspace, sibling


def test_cd_into_a_sibling_repository_is_peeled_with_home(tmp_path: Path) -> None:
    home, workspace, sibling = sibling_home(tmp_path)
    dashboard = sibling / "dashboard"
    command = f"cd {dashboard} && ./node_modules/.bin/vite build 2>&1 | tail -15"
    assert peel_contained_wrapper(command, workspace=workspace, home=home) == (
        "./node_modules/.bin/vite build",
        dashboard.resolve(),
        OutputFilter("tail", 15, merge_stderr=True),
    )
    assert sibling_project_root(dashboard, home=home) == sibling.resolve()
    # Without home, or outside any repository below it, the target stays outside the workspace.
    with pytest.raises(ValueError):
        peel_contained_wrapper(command, workspace=workspace)
    for target in (home / "loose", home, tmp_path):
        assert sibling_project_root(target, home=home) is None
        with pytest.raises(ValueError):
            peel_contained_wrapper(f"cd {target} && pytest -q", workspace=workspace, home=home)


def test_home_itself_is_never_a_sibling_repository(tmp_path: Path) -> None:
    home, workspace, _sibling = sibling_home(tmp_path)
    (home / ".git").mkdir()
    assert sibling_project_root(home / "loose", home=home) is None
    with pytest.raises(ValueError):
        peel_contained_wrapper(f"cd {home / 'loose'} && pytest -q", workspace=workspace, home=home)


def test_unquoted_home_cd_expands_from_home(tmp_path: Path) -> None:
    home, workspace, sibling = sibling_home(tmp_path)
    command = "cd ~/sibling-worktree/dashboard && node node_modules/vite/bin/vite.js build 2>&1 | tail -12"
    assert peel_contained_wrapper(command, workspace=workspace, home=home) == (
        "node node_modules/vite/bin/vite.js build",
        (sibling / "dashboard").resolve(),
        OutputFilter("tail", 12, merge_stderr=True),
    )
    assert peel_contained_wrapper("cd ~/project && pytest -q | tail -5", workspace=workspace, home=home)[1] == (
        workspace.resolve()
    )
    # A quoted `~` stays a literal relative directory, and no home means no expansion.
    for rejected in ('cd "~/project" && pytest -q', "cd '~/project' && pytest -q", "cd ~nobody && pytest -q"):
        with pytest.raises((ValueError, OSError)):
            peel_contained_wrapper(rejected, workspace=workspace, home=home)
    with pytest.raises(ValueError):
        peel_contained_wrapper("cd ~/project && pytest -q", workspace=workspace)
    doubled = "cd ~//sibling-worktree/dashboard && node node_modules/vite/bin/vite.js build 2>&1 | tail -12"
    assert peel_contained_wrapper(doubled, workspace=workspace, home=home)[1] == (sibling / "dashboard").resolve()
    for mixed in (
        'cd ~"/sibling-worktree/dashboard" && node node_modules/vite/bin/vite.js build',
        "cd ~'/sibling-worktree/dashboard' && node node_modules/vite/bin/vite.js build",
    ):
        with pytest.raises((ValueError, OSError)):
            peel_contained_wrapper(mixed, workspace=workspace, home=home)


def test_sink_moves_the_approved_root_to_the_sibling_repository(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home, workspace, sibling = sibling_home(tmp_path)
    dashboard = sibling / "dashboard"
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(sink, "prepare_restricted_pytest", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        sink,
        "run_restricted_pytest",
        lambda *args, **kwargs: calls.append(("execute", (kwargs["workspace"], kwargs["cwd"]))) or 0,
    )

    def authorize(original):
        calls.append(("authorize", (original["tool_input"]["command"], original.get("cwd"))))
        return required_profile()

    original = {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {"command": f"cd {dashboard} && pytest -q | tail -5"},
        "cwd": str(workspace),
    }
    assert (
        sink.run_authorized_contained_test(
            original, workspace=workspace, timeout_seconds=20, authorize=authorize, home_dir=home
        )
        == 0
    )
    resolved = dashboard.resolve()
    assert calls == [
        ("authorize", (original["tool_input"]["command"], str(workspace))),
        ("authorize", ("pytest -q", str(resolved))),
        ("execute", (sibling.resolve(), resolved)),
    ]
    # Without a home to bound the sibling, the pytest receipt does not cover it.
    calls.clear()
    with pytest.raises(RestrictedPytestError):
        sink.run_authorized_contained_test(original, workspace=workspace, timeout_seconds=20, authorize=authorize)
    assert calls == [("authorize", (original["tool_input"]["command"], str(workspace)))]
