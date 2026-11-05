import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import bench_guard_cigar_long_task as bench  # noqa: E402


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
    assert "| cigar | 2 | NO | 1,660,000 |" in table
    assert "-60.0%" in table


def test_report_needs_the_base_arm() -> None:
    with pytest.raises(ValueError, match="base"):
        bench.report([_row("cigar", 1, 1)], "base", ["cigar"])


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
    assert "| cigar | 1 | NO |" in capsys.readouterr().out
    rows[1]["passed"] = True
    (runs / "results.jsonl").write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    assert bench.main(["--work", str(tmp_path), "report", "--base", "base", "cigar"]) == 0
