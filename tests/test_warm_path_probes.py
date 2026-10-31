from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import ClassVar

import pytest

_SCRIPTS = str(Path(__file__).resolve().parents[1] / "scripts")
sys.path.insert(0, _SCRIPTS)
try:
    import summarize_warm_path_latency as summary_module
    import warm_path_probes as probes
    import warm_path_services as services
finally:
    # Other modules on this worker assert the scripts directory stays off the import path.
    sys.path[:] = [entry for entry in sys.path if entry != _SCRIPTS]


@pytest.mark.parametrize(
    ("argv", "role"),
    [
        (["/opt/venv/bin/python", "-m", "codex_plugin_scanner.cli", "guard", "daemon", "--serve"], "daemon"),
        (["/opt/venv/bin/hol-guard", "guard", "daemon", "ensure", "--guard-home", "/g"], "daemon-ensure"),
        (["/opt/venv/bin/hol-guard", "guard", "daemon", "stop", "--json"], "daemon-cli"),
        (["/opt/venv/bin/hol-guard", "guard", "codex-mcp-proxy", "--server", "canary"], "mcp-proxy"),
        (["/opt/venv/bin/hol-guard", "hermes", "mcp-proxy", "--guard-home", "/g"], "mcp-proxy"),
        (["/x/hol-guard-runtime", "mcp-relay", "/opt/venv/bin/hol-guard", "guard", "codex-mcp-proxy"], "mcp-relay"),
        (["/x/hol-guard-runtime", "serve-managed", "--state-dir", "/s", "--generation", "1"], "resident-serve"),
        (["/x/hol-guard-runtime", "serve", "--socket", "/s/sock"], "resident-serve"),
        (["/x/hol-guard-runtime", "supervise-managed", "--state-dir", "/s"], "resident-supervise"),
        (["/x/hol-guard-runtime", "resident-client-stream", "--stdin", "/s"], "resident-client-stream"),
        (["/x/hol-guard-runtime", "hook-client", "--stdin", "/s"], "hook"),
        (["/opt/venv/bin/hol-guard", "guard", "hook", "--harness", "claude-code"], "hook"),
        (["/serve/hol-guard-mcp-proxy/daemon-path/python"], "other"),
        ([], "other"),
    ],
)
def test_process_role_uses_exact_tokens(argv: list[str], role: str) -> None:
    assert services.process_role(argv) == role


def test_service_snapshot_records_roles_without_argv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    rows = {
        11: {
            "pid": 11,
            "name": "python3",
            "role": "daemon",
            "rss_kb": 2048,
            "rss_anon_kb": 1024,
            "pss_kb": 1536,
            "threads": 3,
            "fds": 9,
            "cpu_s": 0.5,
        },
        12: {"pid": 12, "name": "runtime", "role": "mcp-relay", "rss_kb": 1024, "threads": 1, "fds": 4, "cpu_s": 0.1},
        13: {"pid": 13, "name": "python3", "role": "daemon", "rss_kb": 1024, "threads": 2, "fds": 5, "cpu_s": 0.2},
    }
    monkeypatch.setattr(services, "guard_pids", lambda baseline, root: set(rows))
    monkeypatch.setattr(services, "_process_snapshot", rows.get)

    snapshot = services.service_snapshot(set(), tmp_path)

    assert snapshot["processes"] == 3
    assert snapshot["rss_mb"] == 4.0
    assert snapshot["pss_mb"] == 1.5
    assert snapshot["roles"] == {
        "daemon": {"processes": 2, "rss_mb": 3.0, "anon_mb": 1.0, "pss_mb": 1.5, "cpu_s": 0.7},
        "mcp-relay": {"processes": 1, "rss_mb": 1.0, "anon_mb": 0.0, "pss_mb": 0.0, "cpu_s": 0.1},
    }
    assert "argv" not in str(snapshot) and "cmdline" not in str(snapshot)


def test_role_cpu_per_call_counts_new_roles_from_zero() -> None:
    before = {"roles": {"daemon": {"processes": 1, "rss_mb": 1.0, "cpu_s": 2.0}}}
    after = {
        "roles": {
            "daemon": {"processes": 1, "rss_mb": 1.0, "cpu_s": 2.5},
            "mcp-relay": {"processes": 1, "rss_mb": 1.0, "cpu_s": 0.1},
        }
    }

    assert services.role_cpu_ms_per_call(before, after, 100) == {"daemon": 5.0, "mcp-relay": 1.0}


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr", "status"),
    [
        (0, "", "", "ok"),
        (0, "Guard daemon is still starting.\n", "", "still_starting"),
        (2, "", "argument daemon_command: invalid choice: 'ensure'", "unsupported"),
        (1, "", "boom", "exit_1"),
    ],
)
def test_ensure_daemon_records_status_and_never_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, returncode: int, stdout: str, stderr: str, status: str
) -> None:
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        seen.append(argv)
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    monkeypatch.setattr(services.subprocess, "run", fake_run)
    result = services.ensure_daemon(tmp_path / "hol-guard", {}, tmp_path / "h", tmp_path / "g", tmp_path)

    assert result["status"] == status
    assert seen[0][1:4] == ["guard", "daemon", "ensure"]


class _FakeSession:
    events: ClassVar[list[tuple[str, ...]]] = []

    def __init__(self, argv: list[str], env: dict[str, str], cwd: Path, stderr_path: Path) -> None:
        self.server_requests = 0
        self.events.append(("open", stderr_path.name))

    def notify(self, message: dict[str, object]) -> None:
        self.events.append(("notify", str(message["method"])))

    def request(self, message: dict[str, object]) -> tuple[float, dict[str, object]]:
        self.events.append(("request", str(message["method"])))
        if message["method"] == "tools/call":
            return 1.0, {"id": message["id"], "result": {"content": [{"type": "text", "text": "canary:safe_echo"}]}}
        return 1.0, {"id": message["id"], "result": {}}

    def close(self) -> None:
        self.events.append(("close",))


def test_mcp_phase_ensures_daemon_and_warms_up_before_the_timed_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    events: ClassVar[list[tuple[str, ...]]] = []
    _FakeSession.events = events
    monkeypatch.setattr(probes, "_ProxySession", _FakeSession)
    monkeypatch.setattr(probes, "alive_pids", set)
    monkeypatch.setattr(probes, "_run_install", lambda *args: events.append(("install",)))
    monkeypatch.setattr(probes, "_codex_proxy_command", lambda home: (["launcher"], {}))
    monkeypatch.setattr(
        probes, "ensure_daemon", lambda *args: events.append(("ensure",)) or {"status": "ok", "elapsed_ms": 1.0}
    )
    monkeypatch.setattr(
        probes, "service_snapshot", lambda baseline, root: events.append(("snapshot",)) or {"cpu_s": 0.0, "roles": {}}
    )
    monkeypatch.setattr(probes, "stop_services", lambda *args: events.append(("stop",)))

    phase = probes.run_mcp_phase(
        tmp_path / "hol-guard", {}, tmp_path, canary=tmp_path / "canary.py", interpreter="python3", warmup=2, samples=3
    )

    session_open = [("request", "initialize"), ("notify", "notifications/initialized"), ("request", "tools/list")]
    call = ("request", "tools/call")
    assert events == [
        ("install",),
        ("ensure",),
        ("open", "warmup-session.stderr"),
        *session_open,
        call,
        ("close",),
        ("open", "proxy.stderr"),
        *session_open,
        call,
        call,
        ("snapshot",),
        call,
        call,
        call,
        ("snapshot",),
        ("close",),
        ("stop",),
    ]
    assert len(phase["samples_ms"]) == 3 and len(phase["warmup_ms"]) == 2
    assert phase["classes"] == {"ok": 3}
    assert phase["setup"]["daemon_ensure"]["status"] == "ok"
    assert phase["setup"]["warmup_session"]["call_class"] == "ok"


def _round(
    index: int,
    label: str,
    roles: dict[str, dict[str, float]] | None,
    setup: dict[str, object] | None,
    cpu_by_role: dict[str, float] | None = None,
) -> dict:
    service: dict[str, object] = {"rss_mb": 10.0, "processes": 2, "fds": 4}
    if roles is not None:
        service["roles"] = roles
    phase: dict[str, object] = {
        "samples_ms": [1.0, 2.0],
        "stats_ms": {"p50": 1.0, "p95": 2.0, "p99": 2.0},
        "classes": {"ok": 2},
        "non_allow": 0,
        "service_cpu_ms_per_call": 0.5,
        "service": service,
    }
    if setup is not None:
        phase["setup"] = setup
    if cpu_by_role is not None:
        phase["service_cpu_ms_per_call_by_role"] = cpu_by_role
    return {"round": index, "results": {label: {"mcp": phase, "calibration_spawn_ms": {"p50": 1.0}}}}


def test_summary_reports_role_medians_and_setup() -> None:
    setup = {"daemon_ensure": {"status": "ok"}, "warmup_session": {"call_class": "ok"}}
    relay = {"daemon": {"processes": 1, "rss_mb": 60.0}, "mcp-relay": {"processes": 1, "rss_mb": 8.0}}
    rows = [
        {"round": 1, "phase": _round(1, "c", relay, setup)["results"]["c"]["mcp"], "calibration": {"p50": 1.0}},
        {
            "round": 2,
            "phase": _round(2, "c", {"daemon": {"processes": 1, "rss_mb": 62.0}}, setup)["results"]["c"]["mcp"],
            "calibration": {"p50": 1.0},
        },
    ]

    label = summary_module.summarize_label(rows)

    assert label["service_roles"] == {
        "daemon": {"processes": 1.0, "rss_mb": 61.0, "anon_mb": 0.0, "pss_mb": 0.0},
        "mcp-relay": {"processes": 0.5, "rss_mb": 4.0, "anon_mb": 0.0, "pss_mb": 0.0},
    }
    assert label["setup"] == {"daemon_ensure=ok": 2, "warmup_call=ok": 2}


def test_summary_markdown_tolerates_rounds_without_roles() -> None:
    document = {
        "runner": {"platform": "linux", "cpu_model": "x", "logical_cpus": 2, "image_os": "u", "image_version": "1"},
        "config": {"rounds": 1, "paths": ["mcp"]},
        "targets": [
            {"label": "b", "sha": "1", "wheel_version": "3.15.2"},
            {"label": "c", "sha": "2", "wheel_version": "4"},
        ],
        "rounds": [
            {
                "round": 1,
                "results": {
                    **_round(1, "b", None, None)["results"],
                    **_round(
                        1,
                        "c",
                        {"daemon": {"processes": 1, "rss_mb": 50.0, "anon_mb": 20.0, "pss_mb": 30.0}},
                        None,
                        {"daemon": 3.25},
                    )["results"],
                },
            }
        ],
    }

    markdown = summary_module.render_markdown(document, summary_module.build_summary(document, "b", "c"))

    assert "Service by role (median), `b`: none recorded." in markdown
    assert "Service by role (median), `c`: daemon 1x 50.0 MB (anon 20.0, PSS 30.0) 3.25 CPU ms/call." in markdown


def test_mcp_failure_detail_separates_refusals_sharing_one_code() -> None:
    no_decision = {
        "error": {"code": -32001, "message": "HOL Guard could not obtain a native decision for this tool call."}
    }
    timed_out = {"error": {"code": -32001, "message": "review deadline", "data": {"guard_timeout": True}}}

    assert probes.classify_mcp_response(no_decision) == probes.classify_mcp_response(timed_out) == "error_-32001"
    assert probes.describe_mcp_failure(no_decision) == (
        "HOL Guard could not obtain a native decision for this tool call."
    )
    assert probes.describe_mcp_failure(timed_out) == "review deadline [data:guard_timeout]"


def test_non_ok_summary_keeps_position_and_bounded_distinct_reasons() -> None:
    observed = [
        (1.0, "ok", ""),
        (2.0, "error_-32001", "no native decision"),
        (3.0, "error_-32001", "no native decision"),
        (4.0, "ok", ""),
        (5.0, "error_-32001", "sync failed"),
    ]

    detail = probes.summarize_non_ok(observed, allow_classes=frozenset({"ok"}))

    assert detail["count"] == 3
    assert detail["first_index"] == 1
    # Two bursts, not three scattered refusals: 1-2 then 4.
    assert detail["runs"] == [[1, 2], [4, 4]]
    assert detail["runs_truncated"] is False
    assert detail["reasons"] == [
        {"index": 1, "class": "error_-32001", "detail": "no native decision"},
        {"index": 4, "class": "error_-32001", "detail": "sync failed"},
    ]


def test_non_ok_summary_bounds_reason_count_and_run_count() -> None:
    observed = [(1.0, "error_-32001", probes.bounded_detail("x" * 1000))] + [
        (1.0, "ok" if index % 2 else "error_-32001", "") for index in range(1, 80)
    ]

    detail = probes.summarize_non_ok(observed, allow_classes=frozenset({"ok"}))

    assert len(detail["reasons"]) <= probes._NON_OK_DETAIL_SAMPLES
    assert len(detail["reasons"][0]["detail"]) == probes._NON_OK_DETAIL_CHARS
    assert len(detail["runs"]) == probes._NON_OK_RUN_LIMIT
    assert detail["runs_truncated"] is True


def test_summary_markdown_names_why_samples_were_refused() -> None:
    def refused(label: str) -> dict:
        entry = _round(1, label, None, None)
        phase = entry["results"][label]["mcp"]
        phase["classes"] = {"ok": 1, "error_-32001": 1}
        phase["non_allow"] = 1
        phase["non_ok"] = {
            "count": 1,
            "first_index": 1,
            "runs": [[1, 1]],
            "runs_truncated": False,
            "reasons": [{"index": 1, "class": "error_-32001", "detail": "no native decision"}],
        }
        return entry

    document = {
        "runner": {"platform": "linux", "cpu_model": "x", "logical_cpus": 2, "image_os": "u", "image_version": "1"},
        "config": {"rounds": 1, "paths": ["mcp"]},
        "targets": [
            {"label": "b", "sha": "1", "wheel_version": "3.15.2"},
            {"label": "c", "sha": "2", "wheel_version": "4"},
        ],
        "rounds": [{"round": 1, "results": {**_round(1, "b", None, None)["results"], **refused("c")["results"]}}],
    }

    markdown = summary_module.render_markdown(document, summary_module.build_summary(document, "b", "c"))

    assert (
        "Non-allow samples, `c`: 1 (round 1 x1). Sample runs: round 1 1-1. "
        "Reasons: `error_-32001` at round 1 sample 1: no native decision." in markdown
    )
    assert "Non-allow samples, `b`" not in markdown


def test_hook_failure_detail_is_one_bounded_line() -> None:
    traceback = 'Traceback (most recent call last):\n  File "x", line 1\n' + "pad " * 200

    detail = probes.describe_hook_failure(2, "", traceback)

    assert "\n" not in detail
    assert detail.startswith('exit=2 Traceback (most recent call last): File "x", line 1 pad')
    assert len(detail) == probes._NON_OK_DETAIL_CHARS


def test_mcp_failure_detail_is_bounded_where_it_is_produced() -> None:
    response = {"error": {"code": -32001, "message": "review\ndeadline " + "x" * 1000}}

    detail = probes.describe_mcp_failure(response)

    assert detail.startswith("review deadline xxx")
    assert len(detail) == probes._NON_OK_DETAIL_CHARS


def test_reasons_differing_past_the_bound_do_not_crowd_out_a_distinct_one() -> None:
    shared = "guard refused: " + "x" * probes._NON_OK_DETAIL_CHARS
    observed = [(1.0, "error_-32001", probes.bounded_detail(f"{shared}{suffix}")) for suffix in "abcde"]
    observed.append((1.0, "error_-32001", "sync failed"))

    detail = probes.summarize_non_ok(observed, allow_classes=frozenset({"ok"}))

    assert [reason["index"] for reason in detail["reasons"]] == [0, 5]
    assert detail["reasons"][1]["detail"] == "sync failed"


def _refused_round(index: int, label: str, non_ok: dict) -> dict:
    entry = _round(index, label, None, None)
    phase = entry["results"][label]["mcp"]
    phase["classes"] = {"ok": 1, "error_-32001": int(non_ok["count"])}
    phase["non_allow"] = int(non_ok["count"])
    phase["non_ok"] = non_ok
    return entry


def _refusal_markdown(rounds: list[dict]) -> str:
    document = {
        "runner": {"platform": "linux", "cpu_model": "x", "logical_cpus": 2, "image_os": "u", "image_version": "1"},
        "config": {"rounds": len(rounds), "paths": ["mcp"]},
        "targets": [
            {"label": "b", "sha": "1", "wheel_version": "3.15.2"},
            {"label": "c", "sha": "2", "wheel_version": "4"},
        ],
        "rounds": rounds,
    }
    return summary_module.render_markdown(document, summary_module.build_summary(document, "b", "c"))


def test_summary_markdown_orders_ten_rounds_by_number() -> None:
    rounds = []
    for index in range(1, 11):
        non_ok = {
            "count": index,
            "first_index": 0,
            "runs": [[0, index - 1]],
            "runs_truncated": False,
            "reasons": [],
        }
        rounds.append(
            {
                "round": index,
                "results": {
                    **_round(index, "b", None, None)["results"],
                    **_refused_round(index, "c", non_ok)["results"],
                },
            }
        )

    markdown = _refusal_markdown(rounds)

    assert "(round 1 x1, round 2 x2, round 3 x3" in markdown
    assert "round 9 x9, round 10 x10)" in markdown
    assert "Sample runs: round 1 0-0, round 2 0-1" in markdown
    assert "round 9 0-8, round 10 0-9." in markdown


def test_summary_markdown_marks_rounds_whose_runs_were_cut_short() -> None:
    non_ok = {
        "count": 60,
        "first_index": 0,
        "runs": [[0, 0], [2, 2]],
        "runs_truncated": True,
        "reasons": [],
    }
    rounds = [
        {
            "round": 1,
            "results": {
                **_round(1, "b", None, None)["results"],
                **_refused_round(1, "c", non_ok)["results"],
            },
        }
    ]

    markdown = _refusal_markdown(rounds)

    assert "Sample runs: round 1 0-0,2-2 and later positions not recorded." in markdown


def test_summary_markdown_keeps_refusal_text_from_reshaping_the_report() -> None:
    non_ok = {
        "count": 1,
        "first_index": 0,
        "runs": [[0, 0]],
        "runs_truncated": False,
        "reasons": [{"index": 0, "class": "error_-32001", "detail": "# heading\n| cell | `code` [link](x) *bold*"}],
    }
    rounds = [
        {
            "round": 1,
            "results": {
                **_round(1, "b", None, None)["results"],
                **_refused_round(1, "c", non_ok)["results"],
            },
        }
    ]

    markdown = _refusal_markdown(rounds)

    reason_line = next(line for line in markdown.splitlines() if "Non-allow samples, `c`" in line)
    assert reason_line.endswith(
        "Reasons: `error_-32001` at round 1 sample 0: \\# heading \\| cell \\| \\`code\\` \\[link\\](x) \\*bold\\*."
    )


def test_hook_refusal_detail_reports_the_reason_not_the_envelope() -> None:
    stdout = json.dumps(
        {
            "systemMessage": "HOL Guard reviewed this call.",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "install of pkg needs approval",
            },
        }
    )

    assert probes.describe_hook_failure(0, stdout, "") == "exit=0 install of pkg needs approval"


def test_hook_refusal_detail_drops_an_answer_it_cannot_read() -> None:
    # Without a reason to quote the line says only how the sample ended, rather
    # than the first 240 characters of someone else's JSON.
    assert probes.describe_hook_failure(0, '{"hookSpecificOutput": {"hookEventName": "PreToolUse"}}', "") == "exit=0"
    assert probes.describe_hook_failure(1, "not json at all", "") == "exit=1"


def test_hook_class_is_a_bounded_token() -> None:
    wild = json.dumps({"hookSpecificOutput": {"permissionDecision": "deny`\n# heading " + "x" * 200}})

    classification = probes.classify_hook_output(0, wild)

    assert classification.startswith("permission_deny_")
    assert "`" not in classification and "\n" not in classification
    assert len(classification) <= len("permission_") + probes._CLASS_TOKEN_CHARS


def test_mcp_refusal_detail_keeps_only_known_data_markers() -> None:
    response = {
        "error": {
            "code": -32001,
            "message": "review deadline",
            "data": {"guard_timeout": True, "user@example.com": "queued"},
        }
    }

    assert probes.describe_mcp_failure(response) == "review deadline [data:guard_timeout]"


def test_summary_markdown_keeps_a_decision_class_from_reshaping_the_report() -> None:
    non_ok = {
        "count": 1,
        "first_index": 0,
        "runs": [[0, 0]],
        "runs_truncated": False,
        "reasons": [{"index": 0, "class": "permission_deny`\n# heading", "detail": ""}],
    }
    rounds = [
        {
            "round": 1,
            "results": {
                **_round(1, "b", None, None)["results"],
                **_refused_round(1, "c", non_ok)["results"],
            },
        }
    ]

    markdown = _refusal_markdown(rounds)

    reason_line = next(line for line in markdown.splitlines() if "Non-allow samples, `c`" in line)
    assert "Reasons: `permission_deny_heading` at round 1 sample 0." in reason_line
    classes_line = next(line for line in markdown.splitlines() if line.startswith("Decision classes"))
    assert classes_line == "Decision classes baseline `ok` x2, candidate `error_-32001` x1, `ok` x1."
