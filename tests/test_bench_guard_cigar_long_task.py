import json
import subprocess
from pathlib import Path

import pytest

from tests.delivery_scripts import script

# Imported through the helper so scripts/ (which has its own `ci` directory) never stays on sys.path.
bench = script("bench_guard_cigar_long_task")


def _usage(thread: str, input_tokens: int, cached: int) -> str:
    return json.dumps(
        {
            "type": "token_usage_record",
            "payload": {
                "thread_id": thread,
                "usage": {"input_tokens": input_tokens, "cached_input_tokens": cached, "output_tokens": 7},
            },
        }
    )


def _rollout(tmp_path: Path, thread: str, lines: list[str]) -> Path:
    day = tmp_path / "codex" / "sessions" / "2026" / "11" / "05"
    day.mkdir(parents=True)
    path = day / f"rollout-2026-11-05T01-02-03-{thread}.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_rollout_sum_counts_every_request_and_compaction(tmp_path: Path) -> None:
    thread = "0123-thread"
    path = _rollout(
        tmp_path,
        thread,
        [
            json.dumps({"type": "session_meta", "payload": {}}),
            _usage(thread, 15000, 11000),
            json.dumps({"type": "compacted", "payload": {"message": ""}}),
            _usage(thread, 20000, 0),
            "not json",
        ],
    )
    assert bench.rollout_path(tmp_path / "codex", thread) == path
    assert bench.rollout_sum(path) == {
        "input_tokens": 35000,
        "cached_input_tokens": 11000,
        "uncached_input_tokens": 24000,
        "output_tokens": 14,
        "requests": 2,
        "compactions": 1,
    }


def test_rollout_path_is_none_without_sessions(tmp_path: Path) -> None:
    (tmp_path / "sessions").mkdir()
    assert bench.rollout_path(tmp_path, "missing") is None


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("/bin/zsh -lc 'sed -n 1,320p src/click/types.py'", "read"),
        ("/bin/zsh -lc 'python -m pytest -q tests'", "test"),
        ("/bin/zsh -lc 'rg -n Choice src | head'", "search"),
        ("/bin/zsh -lc 'git status'", "git"),
        ("/bin/zsh -lc 'ls -R docs'", "list"),
        ("/bin/zsh -lc 'cd src && cat types.py'", "read"),
        ("/bin/zsh -lc 'python - <<EOF\nprint(1)\nEOF'", "python"),
        ("/bin/zsh -lc 'make docs'", "other"),
        (
            "/bin/zsh -lc \"sed -n '1,360p' src/click/types.py; sed -n '1,100p' CHANGES.rst; rg -n \\\"class\\\" src\"",
            "read",
        ),
        ("/bin/zsh -lc \"git diff --check; git status --short; sed -n '284,340p' src/click/types.py\"", "read"),
        ("/bin/zsh -lc \"rg -n 'Choice' src tests; git diff --stat\"", "search"),
        ("/bin/zsh -lc \"sed -n '1,20p' a.py; python -m pytest -q tests\"", "test"),
        ("/bin/zsh -lc 'cat tox.ini'", "read"),
        ("/bin/zsh -lc 'rg -n pytest setup.cfg'", "search"),
        ("/bin/zsh -lc 'pytest -q tests/test_types.py'", "test"),
        ("/bin/zsh -lc 'python3 -m unittest discover'", "test"),
    ],
)
def test_kind_classifies_agent_commands(command: str, expected: str) -> None:
    assert bench.kind(command) == expected


def test_output_breakdown_counts_chars_by_shape() -> None:
    events = [
        {
            "type": "item.completed",
            "item": {"type": "command_execution", "command": "/bin/zsh -lc 'cat a.py'", "aggregated_output": "x" * 50},
        },
        {
            "type": "item.completed",
            "item": {"type": "command_execution", "command": "/bin/zsh -lc 'cat b.py'", "aggregated_output": "y" * 30},
        },
        {
            "type": "item.completed",
            "item": {"type": "command_execution", "command": "/bin/zsh -lc 'git diff'", "aggregated_output": None},
        },
        {"type": "item.started", "item": {"type": "command_execution", "command": "/bin/zsh -lc 'cat c.py'"}},
        {"type": "item.completed", "item": {"type": "agent_message", "text": "done"}},
    ]
    assert bench.output_breakdown(events) == {"chars": {"read": 80, "git": 0}, "calls": {"read": 2, "git": 1}}


def test_teammate_change_applies_both_edits_once(tmp_path: Path) -> None:
    (tmp_path / "src" / "click").mkdir(parents=True)
    parser = tmp_path / "src" / "click" / "parser.py"
    types = tmp_path / "src" / "click" / "types.py"
    parser.write_text("a\n state.rargs.insert(0, explicit_value)\n", encoding="utf-8")
    types.write_text("x\n        return bound + dir\n\n        return bound + dir\n", encoding="utf-8")
    bench.apply_teammate_change(tmp_path)
    assert "state.rargs.append(explicit_value)" in parser.read_text(encoding="utf-8")
    assert types.read_text(encoding="utf-8").count("return bound - dir") == 1


def test_teammate_change_refuses_a_drifted_fixture(tmp_path: Path) -> None:
    (tmp_path / "src" / "click").mkdir(parents=True)
    (tmp_path / "src" / "click" / "parser.py").write_text("nothing here\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match=r"parser\.py"):
        bench.apply_teammate_change(tmp_path)


def test_check_step_runs_acceptance_tests_from_inside_the_project(tmp_path: Path, monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(bench, "pytest_tail", lambda python, project, *args: calls.append(args) or "1 passed")
    results = bench.check_step(Path("python"), tmp_path)
    assert set(results) == {"suite", *bench.ACCEPTANCE}
    for name in bench.ACCEPTANCE:
        assert (f".bench_accept/{name}_accept.py",) in calls
        assert (tmp_path / ".bench_accept" / f"{name}_accept.py").read_text(encoding="utf-8")


def test_passed_requires_every_check_green() -> None:
    assert bench.passed({"suite": "1041 passed in 3.2s", "t1": "4 passed in 0.1s"})
    assert bench.passed({"suite": "637 passed, 22 skipped, 1 xfailed in 0.50s", "t1": "4 passed in 0.1s"})
    assert not bench.passed({"suite": "1 error in 0.19s", "t1": "4 passed in 0.1s"})
    assert not bench.passed({"suite": "637 passed, 4 errors in 0.19s", "t1": "4 passed in 0.1s"})
    assert not bench.passed({"suite": "1 failed, 1040 passed in 3.2s", "t1": "4 passed in 0.1s"})
    assert not bench.passed({"suite": "1041 passed in 3.2s", "t1": "no output"})


def _row(arm: str, rep: int, input_tokens: int, passed: bool = True) -> dict:
    return {
        "arm": arm,
        "rep": rep,
        "passed": passed,
        "secs": 600,
        "tokens": {
            "input_tokens": input_tokens,
            "cached_input_tokens": input_tokens - 100_000,
            "uncached_input_tokens": 100_000,
            "output_tokens": 1,
            "requests": 80,
            "compactions": 2,
        },
        "tool_output": {"chars": {"read": 300_000}, "calls": {"read": 20}},
    }


def test_report_changes_against_the_base_mean() -> None:
    rows = [
        _row("base", 1, 4_000_000),
        _row("base", 2, 4_300_000),
        _row("cigar", 1, 1_660_000),
        _row("cigar", 2, 1_660_000, passed=False),
    ]
    summary = bench.report(rows, "base", ["cigar"])
    assert summary["arms"]["base"]["mean_input"] == 4_150_000
    assert summary["arms"]["cigar"]["change_vs_base"] == -0.6
    assert summary["arms"]["base"]["all_passed"] is True
    assert summary["arms"]["cigar"]["all_passed"] is False
    table = bench.markdown(summary)
    assert "| cigar | 2 | 0 | NO | 1,660,000 |" in table
    assert "-60.0%" in table


def test_report_leaves_errored_reps_out_of_the_statistics() -> None:
    crashed = _row("cigar", 3, 0, passed=False) | {"error": "step 1: codex exec timed out after 1800s"}
    rows = [_row("base", 1, 4_000_000), _row("cigar", 1, 2_000_000), _row("cigar", 2, 2_000_000), crashed]
    stats = bench.report(rows, "base", ["cigar"])["arms"]["cigar"]
    assert stats["n"] == 2
    assert stats["errored"] == 1
    assert stats["mean_input"] == stats["min_input"] == 2_000_000
    assert stats["all_passed"] is False
    assert "| cigar | 2 | 1 | NO | 2,000,000 |" in bench.markdown(bench.report(rows, "base", ["cigar"]))


def test_report_needs_the_base_arm() -> None:
    with pytest.raises(ValueError, match="base"):
        bench.report([_row("cigar", 1, 1)], "base", ["cigar"])


def test_report_rejects_an_arm_with_no_runs() -> None:
    with pytest.raises(ValueError, match=r"lean.*recorded: base, cigar"):
        bench.report([_row("base", 1, 1), _row("cigar", 1, 1)], "base", ["cigar", "lean"])


def test_passed_rejects_a_timed_out_check() -> None:
    assert not bench.passed({"suite": "timed out after 600s", "t1": "4 passed in 0.1s"})


def test_codex_exec_raises_on_nonzero_exit_and_timeout(tmp_path: Path, monkeypatch) -> None:
    out = tmp_path / "s1.jsonl"
    monkeypatch.setattr(bench.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 2))
    with pytest.raises(bench.StepError, match="exited 2"):
        bench.codex_exec(tmp_path, tmp_path, None, tmp_path / "bin" / "python", "go", None, out)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(bench.subprocess, "run", timeout)
    with pytest.raises(bench.StepError, match="timed out"):
        bench.codex_exec(tmp_path, tmp_path, None, tmp_path / "bin" / "python", "go", None, out)


def test_codex_exec_puts_the_fixture_venv_first_on_path(tmp_path: Path, monkeypatch) -> None:
    seen = {}

    def record(command, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(bench.subprocess, "run", record)
    bench.codex_exec(tmp_path, tmp_path, None, tmp_path / "venv" / "bin" / "python", "go", None, tmp_path / "s.jsonl")
    assert seen["env"]["PATH"].split(bench.os.pathsep)[0] == str(tmp_path / "venv" / "bin")


def test_run_session_refuses_a_rep_that_is_already_recorded(tmp_path: Path) -> None:
    arm = tmp_path / "arms" / "base" / "codex_home"
    arm.mkdir(parents=True)
    (arm / "config.toml").write_text("", encoding="utf-8")
    (tmp_path / "runs").mkdir()
    (tmp_path / "runs" / "results.jsonl").write_text(json.dumps(_row("base", 1, 1)) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="already recorded"):
        bench.run_session(tmp_path, "base", 1)


def test_run_session_reruns_a_rep_that_errored(tmp_path: Path, monkeypatch) -> None:
    arm = tmp_path / "arms" / "base" / "codex_home"
    arm.mkdir(parents=True)
    (arm / "config.toml").write_text("", encoding="utf-8")
    (tmp_path / "runs").mkdir()
    errored = _row("base", 1, 0, passed=False) | {"error": "step 1: codex exec exited 1"}
    (tmp_path / "runs" / "results.jsonl").write_text(json.dumps(errored) + "\n", encoding="utf-8")

    def stop(*args):
        raise RuntimeError("reached the fixture copy")

    monkeypatch.setattr(bench, "fresh_project", stop)
    with pytest.raises(RuntimeError, match="fixture copy"):
        bench.run_session(tmp_path, "base", 1)


def test_checks_run_inside_the_codex_sandbox_without_network(tmp_path: Path, monkeypatch) -> None:
    seen = {}

    def record(command, **kwargs):
        seen.update(kwargs, command=command)
        return subprocess.CompletedProcess(command, 0, "1 passed in 0.1s\n", "")

    project = tmp_path / "projects" / "base-r1"
    project.mkdir(parents=True)
    monkeypatch.setattr(bench.subprocess, "run", record)
    assert bench.pytest_tail(Path("python"), project, "tests") == "1 passed in 0.1s"
    command = seen["command"]
    assert command[:2] == ["codex", "sandbox"]
    assert 'sandbox_mode="workspace-write"' in command
    assert "sandbox_workspace_write.network_access=false" in command
    assert command[command.index("--") + 1 :][:3] == ["python", "-m", "pytest"]
    assert seen["env"]["CODEX_HOME"] == str(tmp_path / "sandbox_home")
    assert seen["cwd"] == project


def _git(path: Path, *args: str) -> str:
    return bench.git(path, *args)


def test_run_session_records_a_failed_step_and_keeps_the_teammate_commit_small(tmp_path: Path, monkeypatch) -> None:
    pristine = tmp_path / "pristine"
    (pristine / "src" / "click").mkdir(parents=True)
    (pristine / "src" / "click" / "parser.py").write_text("state.rargs.insert(0, explicit_value)\n", encoding="utf-8")
    (pristine / "src" / "click" / "types.py").write_text("        return bound + dir\n", encoding="utf-8")
    _git(pristine, "init", "-q")
    bench.commit(pristine, "fixture")
    monkeypatch.setattr(bench, "FIXTURE_TREE", _git(pristine, "rev-parse", "HEAD^{tree}").strip())
    arm = tmp_path / "arms" / "base" / "codex_home"
    arm.mkdir(parents=True)
    (arm / "config.toml").write_text("", encoding="utf-8")
    (tmp_path / "venv" / "bin").mkdir(parents=True)
    calls = []

    def fake_exec(project, codex_home, home, python, prompt, thread, out):
        calls.append(prompt)
        if len(calls) == bench.TEAMMATE_STEP:
            raise bench.StepError("codex exec exited 1")
        (project / "agent.txt").write_text(str(len(calls)), encoding="utf-8")
        out.write_text(json.dumps({"type": "thread.started", "thread_id": "t-1"}) + "\n", encoding="utf-8")

    monkeypatch.setattr(bench, "codex_exec", fake_exec)
    monkeypatch.setattr(bench, "preflight", lambda *args: None)
    monkeypatch.setattr(bench, "check_step", lambda python, project: {"suite": "1 passed in 0.1s"})
    result = bench.run_session(tmp_path, "base", 1)
    assert result["passed"] is False
    assert result["error"] == "step 4: codex exec exited 1"
    assert len(result["steps"]) == 3
    project = tmp_path / "projects" / "base-r1"
    assert _git(project, "log", "--format=%s", "-1").strip() == "teammate change"
    assert _git(project, "show", "--stat", "--format=", "HEAD").count("|") == 2
    assert _git(project, "log", "--format=%s", "-2").splitlines()[1] == "agent work through step 3"
    assert json.loads((tmp_path / "runs" / "results.jsonl").read_text(encoding="utf-8"))["error"]


def test_step_prompts_and_acceptance_tests_ship_with_the_script() -> None:
    for step in range(1, bench.STEPS + 1):
        assert (bench.DATA / "steps" / f"s{step}.txt").read_text(encoding="utf-8").strip()
    for name in bench.ACCEPTANCE:
        assert (bench.DATA / "accept" / f"{name}_accept.py").exists()


def test_report_command_fails_when_a_rep_failed(tmp_path: Path, capsys) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    rows = [_row("base", 1, 4_000_000), _row("cigar", 1, 1_600_000, passed=False)]
    (runs / "results.jsonl").write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    assert bench.main(["--work", str(tmp_path), "report", "--base", "base", "cigar"]) == 1
    assert "| cigar | 1 | 0 | NO |" in capsys.readouterr().out
    rows[1]["passed"] = True
    (runs / "results.jsonl").write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    assert bench.main(["--work", str(tmp_path), "report", "--base", "base", "cigar"]) == 0


@pytest.mark.skipif(not Path("/bin/zsh").exists(), reason="the agent shell under test is zsh")
def test_agent_env_puts_the_venv_first_in_a_login_shell(tmp_path: Path) -> None:
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    python = venv_bin / "python"
    python.write_text("#!/bin/sh\n", encoding="utf-8")
    python.chmod(0o755)
    env = bench.agent_env(tmp_path, tmp_path / "codex", tmp_path / "other-home", python)
    assert env["HOME"] == str(tmp_path / "other-home")
    done = subprocess.run(
        ["/bin/zsh", "-lc", "command -v python"],
        env={**env, "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
    )
    assert done.stdout.strip() == str(python)


def test_preflight_refuses_a_shell_without_the_venv(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(bench, "agent_env", lambda *args: {"PATH": "/usr/bin:/bin", "SHELL": "/bin/sh"})
    with pytest.raises(SystemExit, match="resolves python"):
        bench.preflight(tmp_path, tmp_path, None, tmp_path / "venv" / "bin" / "python")
