import json
from pathlib import Path

import pytest

from tests.delivery_scripts import script

bench = script("bench_guard_cigar_long_task")
claude = script("bench_guard_cigar_long_task_claude")
usage = script("bench_guard_cigar_usage")


def _assistant(message_id: str, blocks: list[dict], **counts: int) -> str:
    return json.dumps(
        {
            "type": "assistant",
            "message": {
                "id": message_id,
                "content": blocks,
                "usage": {
                    "input_tokens": counts.get("fresh", 0),
                    "cache_read_input_tokens": counts.get("read", 0),
                    "cache_creation_input_tokens": counts.get("write", 0),
                    "cache_creation": {"ephemeral_5m_input_tokens": counts.get("write_5m", 0)},
                    "output_tokens": counts.get("out", 0),
                },
            },
        }
    )


def _result(tool_use_id: str, text: str) -> str:
    return json.dumps(
        {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": tool_use_id, "content": text}]}}
    )


def _session(tmp_path: Path) -> tuple[Path, str]:
    session = "0b6d-session"
    folder = tmp_path / "projects" / "-tmp-proj"
    (folder / session / "subagents").mkdir(parents=True)
    bash = {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "python -m pytest tests -q"}}
    read = {"type": "tool_use", "id": "t2", "name": "Read", "input": {"file_path": "src/click/parser.py"}}
    (folder / f"{session}.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"type": "queue-operation"}),
                # One response split over two lines repeats its usage; it counts once.
                _assistant("m1", [{"type": "thinking", "thinking": ""}], fresh=10, write=20000, out=40),
                _assistant("m1", [bash], fresh=10, write=20000, out=40),
                _result("t1", "." * 300),
                _assistant("m2", [read], fresh=3, read=20000, write=500, write_5m=500, out=30),
                json.dumps(
                    {
                        "type": "user",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_result",
                                    "tool_use_id": "t2",
                                    "content": [{"type": "text", "text": "x" * 70}],
                                }
                            ]
                        },
                    }
                ),
                json.dumps({"type": "system", "subtype": "compact_boundary"}),
                "not json",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (folder / session / "subagents" / "agent-a.jsonl").write_text(
        _assistant("m3", [{"type": "text", "text": "done"}], fresh=5, read=1000, out=10) + "\n", encoding="utf-8"
    )
    return tmp_path / "projects", session


def test_claude_transcript_counts_each_response_once_with_subagents(tmp_path: Path) -> None:
    projects, session = _session(tmp_path)
    paths = usage.claude_transcripts(projects, session)
    assert [path.name for path in paths] == [f"{session}.jsonl", "agent-a.jsonl"]
    assert usage.claude_transcript(paths) == {
        "input_tokens": 18 + 21000 + 20500,
        "cached_input_tokens": 21000,
        "cache_write_tokens": 20500,
        "cache_write_5m_tokens": 500,
        "uncached_input_tokens": 18,
        "output_tokens": 80,
        "requests": 3,
        "compactions": 1,
    }


def test_claude_transcript_without_a_ledger_says_so(tmp_path: Path) -> None:
    assert usage.claude_transcripts(tmp_path, "missing") == []
    with pytest.raises(usage.NoUsageLedgerError, match="no Claude Code transcript"):
        usage.claude_transcript([])


def test_claude_tool_output_sorts_results_by_tool_shape(tmp_path: Path) -> None:
    projects, session = _session(tmp_path)
    shapes = claude.tool_output(usage.claude_transcripts(projects, session), bench.kind)
    assert shapes == {"chars": {"test": 300, "read": 70}, "calls": {"test": 1, "read": 1}}


def test_cost_prices_cache_reads_and_writes_apart_from_full_price_input() -> None:
    codex = {
        **usage.empty(),
        "uncached_input_tokens": 134_000,
        "cached_input_tokens": 3_784_000,
        "output_tokens": 18_600,
    }
    assert usage.cost(codex, "gpt-6-luna") == {
        "input_usd": 0.05124,
        "output_usd": 0.0093,
        "usd": 0.06054,
        "paid_tokens": 605_400,
    }
    anthropic = {
        **usage.empty(),
        "uncached_input_tokens": 1_000,
        "cached_input_tokens": 1_000_000,
        "cache_write_tokens": 100_000,
        "cache_write_5m_tokens": 40_000,
        "output_tokens": 10_000,
    }
    # 1k fresh at $1, 1M reads at $0.10, 60k 1-hour writes at $2, 40k 5-minute writes at $1.25, 10k out at $5.
    assert usage.cost(anthropic, "claude-haiku-4-5-20251001")["usd"] == pytest.approx(0.001 + 0.1 + 0.12 + 0.05 + 0.05)


def test_cost_refuses_a_model_without_a_recorded_price() -> None:
    with pytest.raises(KeyError, match="no list price"):
        usage.cost(usage.empty(), "unpriced-model")


def test_claude_command_isolates_the_run_from_user_configuration(tmp_path: Path) -> None:
    first = claude.command(tmp_path, "step one", "sid", resume=False)
    later = claude.command(tmp_path, "step two", "sid", resume=True)
    for flag in ("--strict-mcp-config", "--disable-slash-commands"):
        assert flag in first
    assert first[first.index("--setting-sources") + 1] == "project"
    assert first[first.index("--settings") + 1] == str(tmp_path / "claude_settings.json")
    assert first[first.index("--model") + 1] == claude.MODEL
    assert first[-2:] == ["--session-id", "sid"]
    assert later[-2:] == ["--resume", "sid"]
    assert claude.ISOLATION_ENV == {"CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1", "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"}


def test_claude_base_arm_has_the_sandbox_on_and_no_hooks(tmp_path: Path) -> None:
    arm = tmp_path / "arms" / "claude-base"
    settings = json.loads(claude.arm_init_base(arm).read_text(encoding="utf-8"))
    assert bench.harness_of(arm) == "claude-code"
    assert settings["sandbox"]["enabled"] is True
    assert settings["sandbox"]["allowUnsandboxedCommands"] is False
    assert "hooks" not in settings
    assert bench.harness_of(tmp_path / "arms" / "base") == "codex"


@pytest.mark.parametrize(
    ("printed", "message"),
    [
        ("", "no result"),
        (json.dumps({"type": "result", "is_error": True, "result": "Not logged in"}), "Not logged in"),
    ],
)
def test_claude_step_result_fails_a_step_that_did_not_finish(tmp_path: Path, printed: str, message: str) -> None:
    out = tmp_path / "s1.jsonl"
    out.write_text(printed, encoding="utf-8")
    with pytest.raises(RuntimeError, match=message):
        claude.step_result(out)


def test_claude_exec_reports_an_error_result_as_a_failed_step(tmp_path: Path, monkeypatch) -> None:
    def fake_run(command, **kwargs):
        kwargs["stdout"].write(json.dumps({"type": "result", "is_error": True, "result": "Not logged in"}))
        assert kwargs["env"]["CLAUDE_CODE_DISABLE_CLAUDE_MDS"] == "1"
        return type("Done", (), {"returncode": 0})()

    monkeypatch.setattr(bench.subprocess, "run", fake_run)
    venv = tmp_path / "venv" / "bin"
    venv.mkdir(parents=True)
    with pytest.raises(bench.StepError, match="Not logged in"):
        bench.claude_exec(tmp_path, tmp_path, venv / "python", "go", "sid", False, tmp_path / "s1.jsonl")
