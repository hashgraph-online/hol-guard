from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import date, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import context_usage_meter as meter
from codex_plugin_scanner.guard.daemon import context_assistance_http as http
from codex_plugin_scanner.guard.daemon import context_usage_http

NOW = time.time()
TODAY = date.today()
STAMP = datetime.fromtimestamp(NOW).astimezone().isoformat()
OLD_STAMP = datetime.fromtimestamp(NOW - 10 * 86400).astimezone().isoformat()


def _line(record: dict) -> str:
    return json.dumps(record, separators=(",", ":")) + "\n"


def _codex_usage(total: int, cached: int, output: int, stamp: str = STAMP) -> str:
    usage = {
        "input_tokens": total,
        "cached_input_tokens": cached,
        "cache_write_input_tokens": 0,
        "output_tokens": output,
    }
    return _line({"timestamp": stamp, "type": "token_usage_record", "payload": {"usage": usage}})


def _claude(message_id: str, fresh: int, read: int, written: int, output: int, *, model: str = "claude-test") -> str:
    usage = {
        "input_tokens": fresh,
        "cache_read_input_tokens": read,
        "cache_creation_input_tokens": written,
        "output_tokens": output,
    }
    return _line(
        {
            "timestamp": STAMP,
            "type": "assistant",
            "cwd": "/work/alpha",
            "message": {"id": message_id, "model": model, "usage": usage, "content": [{"type": "text"}]},
        }
    )


@pytest.fixture
def homes(tmp_path: Path) -> SimpleNamespace:
    home, guard = tmp_path / "home", tmp_path / "guard"
    rollouts = home / ".codex" / "sessions" / "2026" / "11" / "05"
    projects = home / ".claude" / "projects" / "-work-alpha"
    rollouts.mkdir(parents=True)
    projects.mkdir(parents=True)
    return SimpleNamespace(home=home, guard=guard, rollouts=rollouts, projects=projects)


def _week(files: dict, harness: str) -> dict:
    return next(tool for tool in meter.summarize(files, today=TODAY)["week"] if tool["harness"] == harness)


def test_codex_rollout_counts_requests_compactions_and_the_model(homes: SimpleNamespace) -> None:
    rollout = homes.rollouts / "rollout-a.jsonl"
    rollout.write_text(
        _line({"timestamp": STAMP, "type": "turn_context", "payload": {"model": "gpt-test", "cwd": "/work/beta"}})
        + _line({"timestamp": STAMP, "type": "response_item", "payload": {"text": "token_usage_record"}})
        + _codex_usage(1000, 800, 50)
        + _codex_usage(1200, 1000, 70)
        + _line({"timestamp": STAMP, "type": "compacted", "payload": {}})
    )
    codex = _week(meter.scan(homes.home, homes.guard, {}, now=NOW), "codex")
    assert codex["sessions"] == 1
    assert codex["totals"] == {
        "uncached_input_tokens": 400,
        "cached_input_tokens": 1800,
        "cache_write_tokens": 0,
        "output_tokens": 120,
        "requests": 2,
        "compactions": 1,
    }
    assert codex["recent"][0]["model"] == "gpt-test"
    assert codex["recent"][0]["folder"] == "beta"


def test_claude_code_counts_one_response_once_even_when_it_is_logged_again(homes: SimpleNamespace) -> None:
    transcript = homes.projects / "session-1.jsonl"
    filler = "".join(_line({"type": "user", "message": {"content": "x"}}) for _ in range(300))
    transcript.write_text(
        _claude("msg_one", 3, 100, 10, 7)
        + _claude("msg_one", 3, 100, 10, 7)
        + _claude("msg_two", 5, 200, 0, 9)
        + filler
        + _claude("msg_one", 3, 100, 10, 7)
        + _claude("msg_syn", 0, 0, 0, 0, model="<synthetic>")
        + _line({"timestamp": STAMP, "type": "system", "subtype": "compact_boundary"})
    )
    subagents = homes.projects / "session-1" / "subagents"
    subagents.mkdir(parents=True)
    (subagents / "agent-a.jsonl").write_text(_claude("msg_sub", 1, 10, 0, 2))
    claude = _week(meter.scan(homes.home, homes.guard, {}, now=NOW), "claude-code")
    assert claude["sessions"] == 1
    assert claude["totals"] == {
        "uncached_input_tokens": 9,
        "cached_input_tokens": 310,
        "cache_write_tokens": 10,
        "output_tokens": 18,
        "requests": 4,
        "compactions": 1,
    }
    assert claude["recent"][0]["model"] == "claude-test"
    assert claude["recent"][0]["folder"] == "alpha"


def test_a_later_scan_reads_only_new_lines_and_waits_for_a_half_written_one(homes: SimpleNamespace) -> None:
    rollout = homes.rollouts / "rollout-b.jsonl"
    rollout.write_text(_codex_usage(100, 0, 1))
    first = meter.scan(homes.home, homes.guard, {}, now=NOW)
    assert _week(first, "codex")["totals"]["requests"] == 1
    partial = _codex_usage(200, 0, 2)
    with rollout.open("a") as handle:
        handle.write(partial[:-20])
    assert _week(meter.scan(homes.home, homes.guard, {}, now=NOW), "codex")["totals"]["requests"] == 1
    with rollout.open("a") as handle:
        handle.write(partial[-20:] + _codex_usage(300, 0, 3))
    cache = json.loads((homes.guard / meter.CACHE_NAME).read_text())
    assert next(iter(cache["files"].values()))["offset"] == len(_codex_usage(100, 0, 1))
    totals = _week(meter.scan(homes.home, homes.guard, {}, now=NOW), "codex")["totals"]
    assert totals["requests"] == 3
    assert totals["uncached_input_tokens"] == 600


def test_the_dedupe_window_survives_between_scans(homes: SimpleNamespace) -> None:
    transcript = homes.projects / "session-2.jsonl"
    transcript.write_text(_claude("msg_keep", 1, 1, 1, 1))
    os.utime(transcript, (NOW - 7200, NOW - 7200))
    meter.scan(homes.home, homes.guard, {}, now=NOW)
    with transcript.open("a") as handle:
        handle.write(_claude("msg_keep", 1, 1, 1, 1))
    assert _week(meter.scan(homes.home, homes.guard, {}, now=NOW), "claude-code")["totals"]["requests"] == 1


def test_a_file_that_was_rewritten_shorter_is_counted_again_from_the_start(homes: SimpleNamespace) -> None:
    rollout = homes.rollouts / "rollout-c.jsonl"
    rollout.write_text(_codex_usage(100, 0, 1) + _codex_usage(100, 0, 1))
    meter.scan(homes.home, homes.guard, {}, now=NOW)
    rollout.write_text(_codex_usage(50, 0, 1))
    totals = _week(meter.scan(homes.home, homes.guard, {}, now=NOW), "codex")["totals"]
    assert (totals["requests"], totals["uncached_input_tokens"]) == (1, 50)


def test_today_and_the_week_leave_out_older_days_and_old_files(homes: SimpleNamespace) -> None:
    (homes.rollouts / "rollout-d.jsonl").write_text(_codex_usage(100, 0, 1) + _codex_usage(999, 0, 1, OLD_STAMP))
    stale = homes.rollouts / "rollout-e.jsonl"
    stale.write_text(_codex_usage(5000, 0, 1))
    os.utime(stale, (NOW - 9 * 86400, NOW - 9 * 86400))
    summary = meter.summarize(meter.scan(homes.home, homes.guard, {}, now=NOW), today=TODAY)
    for window in ("today", "week"):
        codex = next(tool for tool in summary[window] if tool["harness"] == "codex")
        assert codex["totals"]["uncached_input_tokens"] == 100
        assert codex["sessions"] == 1
    assert summary["unread"] == ["copilot", "cursor", "gemini", "opencode", "pi"]


def test_tool_homes_follow_their_environment_variables(homes: SimpleNamespace, tmp_path: Path) -> None:
    custom = tmp_path / "custom-codex" / "sessions"
    custom.mkdir(parents=True)
    (custom / "rollout-f.jsonl").write_text(_codex_usage(10, 0, 1))
    (homes.rollouts / "rollout-g.jsonl").write_text(_codex_usage(99, 0, 1))
    files = meter.scan(homes.home, homes.guard, {"CODEX_HOME": str(custom.parent)}, now=NOW)
    assert _week(files, "codex")["totals"]["uncached_input_tokens"] == 10


def test_no_records_reports_zero_sessions_not_an_estimate(homes: SimpleNamespace) -> None:
    summary = meter.summarize(meter.scan(homes.home, homes.guard, {}, now=NOW), today=TODAY)
    assert [(tool["harness"], tool["sessions"], tool["totals"]["requests"]) for tool in summary["week"]] == [
        ("codex", 0, 0),
        ("claude-code", 0, 0),
    ]


def test_the_dashboard_route_answers_counting_then_ready(
    homes: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    (homes.rollouts / "rollout-h.jsonl").write_text(_codex_usage(100, 40, 1))
    usage_meter = meter.UsageMeter()
    monkeypatch.setattr(context_usage_http, "METER", usage_meter)
    monkeypatch.setattr(context_usage_http.Path, "home", staticmethod(lambda: homes.home))
    monkeypatch.setattr(context_usage_http.os, "environ", {})
    assert http.READ_PATHS[context_usage_http.PATH] == context_usage_http.KIND
    assert context_usage_http.PATH not in http.WRITE_PATHS
    calls: list[dict] = []
    handler = SimpleNamespace(
        server=SimpleNamespace(store=SimpleNamespace(guard_home=homes.guard)),
        _write_json=lambda data, status=200, extra_headers=None: calls.append(
            {"data": data, "status": status, "headers": extra_headers}
        ),
    )
    http.respond(handler, context_usage_http.KIND)
    assert calls[0]["data"]["state"] in {"counting", "ready"}
    assert calls[0]["headers"] == {"Cache-Control": "no-store"}
    usage_meter._worker.join(timeout=10)
    http.respond(handler, context_usage_http.KIND)
    ready = calls[-1]["data"]
    assert ready["state"] == "ready"
    codex = next(tool for tool in ready["week"] if tool["harness"] == "codex")
    assert codex["totals"]["cached_input_tokens"] == 40


def test_the_cli_prints_plain_tables_and_json(
    homes: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from codex_plugin_scanner import cli, install_integrity

    (homes.rollouts / "rollout-i.jsonl").write_text(_codex_usage(1000, 600, 5))
    monkeypatch.setenv("HOME", str(homes.home))
    monkeypatch.setenv("USERPROFILE", str(homes.home))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    monkeypatch.setattr(install_integrity, "warn_if_shadowed", lambda: None)
    assert cli.main(["context", "usage", "--guard-home", str(homes.guard)]) == 0
    text = capsys.readouterr().out
    assert "Codex: 1 session\n" in text
    assert "Input at full price" in text
    assert "Copilot, Cursor, Gemini, OpenCode or Pi" in text
    assert "%" not in text
    assert cli.main(["context", "usage", "--guard-home", str(homes.guard), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["schema"] == meter.SCHEMA
    assert next(tool for tool in data["week"] if tool["harness"] == "codex")["totals"]["uncached_input_tokens"] == 400


def test_a_failed_count_is_reported_and_try_again_counts_afresh(
    homes: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_scan = meter.scan
    outcomes = iter([RuntimeError("unexpected"), OSError("unreadable"), None])

    def flaky_scan(*args: object, **kwargs: object) -> dict:
        failure = next(outcomes)
        if failure is not None:
            raise failure
        return real_scan(*args, **kwargs)

    monkeypatch.setattr(meter, "scan", flaky_scan)
    usage_meter = meter.UsageMeter()

    def read() -> str:
        return usage_meter.read(homes.home, homes.guard, {})["state"]

    def settle() -> None:
        usage_meter._worker.join(timeout=10)

    assert read() == "counting"
    settle()
    assert [read(), read()] == ["unavailable", "counting"]
    settle()
    assert [read(), read()] == ["unavailable", "counting"]
    settle()
    assert read() == "ready"


def test_a_failed_refresh_keeps_the_totals_and_waits_before_scanning_again(
    homes: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    (homes.rollouts / "rollout-l.jsonl").write_text(_codex_usage(100, 0, 1))
    usage_meter = meter.UsageMeter(max_age=3600.0)
    usage_meter.read(homes.home, homes.guard, {})
    usage_meter._worker.join(timeout=10)
    scans: list[int] = []

    def failing_scan(*args: object, **kwargs: object) -> dict:
        scans.append(1)
        raise OSError("unreadable")

    monkeypatch.setattr(meter, "scan", failing_scan)
    usage_meter._read_at -= 7200
    usage_meter.read(homes.home, homes.guard, {})
    usage_meter._worker.join(timeout=10)
    for _ in range(3):
        summary = usage_meter.read(homes.home, homes.guard, {})
        assert (summary["state"], summary["refreshing"], _week_of(summary)["totals"]["requests"]) == ("ready", False, 1)
    assert len(scans) == 1


def test_a_refresh_keeps_the_old_totals_and_says_it_is_still_counting(
    homes: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    (homes.rollouts / "rollout-j.jsonl").write_text(_codex_usage(100, 0, 1))
    usage_meter = meter.UsageMeter(max_age=0.0)
    usage_meter.read(homes.home, homes.guard, {})
    usage_meter._worker.join(timeout=10)
    release = threading.Event()
    real_scan = meter.scan

    def slow_scan(*args: object, **kwargs: object) -> dict:
        release.wait(timeout=10)
        return real_scan(*args, **kwargs)

    monkeypatch.setattr(meter, "scan", slow_scan)
    (homes.rollouts / "rollout-k.jsonl").write_text(_codex_usage(200, 0, 1))
    during = usage_meter.read(homes.home, homes.guard, {})
    assert (during["state"], during["refreshing"]) == ("ready", True)
    assert _week_of(during)["totals"]["requests"] == 1
    release.set()
    usage_meter._worker.join(timeout=10)
    usage_meter._max_age = 3600.0
    after = usage_meter.read(homes.home, homes.guard, {})
    assert (after["refreshing"], _week_of(after)["totals"]["requests"]) == (False, 2)


def _week_of(summary: dict) -> dict:
    return next(tool for tool in summary["week"] if tool["harness"] == "codex")
