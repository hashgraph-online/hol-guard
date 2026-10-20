"""A safe-alternative block resumes the Oh My Pi agent after the user approves."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters._modules.pi.pi_extension_tool_resume_source import TOOL_APPROVAL_RESUME_SOURCE
from codex_plugin_scanner.guard.adapters.pi_extension_previous_source import previous_managed_extension_source
from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from tests.pi_continuation_support import _decode_json_object, _node_executable, _run_child


def _source(tmp_path: Path, harness: str, *, previous: bool = False) -> str:
    render = previous_managed_extension_source if previous else managed_extension_source
    return render(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness=harness,
        display_name="fixture",
    )


def test_only_the_active_omp_extension_resumes_after_a_safe_alternative_approval(tmp_path: Path) -> None:
    active = _source(tmp_path, "omp")
    assert "function scheduleToolApprovalResume" in active
    assert active.count("scheduleToolApprovalResume(response, ctx, snapshot);") == 1
    # The user's own prompt ends a pending resume; the turn a resume starts does not.
    assert active.count("    invalidateInputApprovalResumes();\n    invalidateToolApprovalResumes();\n") == 1
    assert "invalidateToolApprovalResumes" not in active[active.index('pi.on("agent_start"') :].split("});")[0]
    for source in (
        _source(tmp_path, "pi"),
        _source(tmp_path, "omp", previous=True),
        _source(tmp_path, "pi", previous=True),
    ):
        assert "scheduleToolApprovalResume" not in source


def test_an_approval_starts_one_turn_that_asks_for_the_identical_call(tmp_path: Path) -> None:
    node = _node_executable()
    if node is None:
        pytest.skip("Node is required to execute the generated helper")
    script = (
        """
const sent = [];
const notices = [];
const handlers = new Map<string, Array<() => void>>();
const pi = {
  on: (event: string, handler: () => void) => handlers.set(event, [...(handlers.get(event) ?? []), handler]),
  sendMessage: (...args) => sent.push(args),
};
const fire = (event: string) => { for (const handler of handlers.get(event) ?? []) handler(); };
let pollQueue = [];
let polls = 0;
type GuardResponse = Record<string, unknown>;
function canonicalJson(value: unknown): string | null { return JSON.stringify(value); }
function ompInteractiveContext(ctx: any): boolean { return ctx.mode === 'tui'; }
function contextSessionId(ctx: any): string | null { return ctx.sessionId; }
function contextCwd(ctx: any): string | null { return ctx.cwd; }
let daemonState: string | null = 'daemon-a';
function loadGuardDaemonConnection() { return daemonState === null ? null : { stateId: daemonState }; }
async function pollApprovalResolution(_id: string, _path: string, _signal: unknown, isActive: () => boolean) {
  polls += 1;
  await new Promise((resolve) => setTimeout(resolve, 5));
  if (!isActive()) return 'aborted';
  return pollQueue.shift() ?? 'timeout';
}
"""
        + TOOL_APPROVAL_RESUME_SOURCE
        + """
const ctx = (mode = 'tui') => ({
  mode,
  sessionId: 's1',
  cwd: '/w',
  ui: { notify: (m: string, k: string) => notices.push([k, m]) },
});
const snapshot = (input: unknown) => ({ payload: { tool_name: 'learn', tool_input: input } });
const blocked = (id: string) => ({
  decision: 'deny',
  approval_resume: { request_id: id, poll_path: `/v1/requests/${id}` },
});
const settle = () => new Promise((resolve) => setTimeout(resolve, 40));
const results: Record<string, unknown> = {};
async function run() {
  pollQueue = ['allow'];
  scheduleToolApprovalResume(blocked('a'), ctx(), snapshot({ memory: 'tests run with uv', context: 'repo' }));
  scheduleToolApprovalResume(blocked('a'), ctx(), snapshot({ memory: 'tests run with uv', context: 'repo' }));
  await settle();
  results.approved = { sent: sent.splice(0), polls, notices: notices.splice(0) };
  polls = 0; pollQueue = ['block'];
  scheduleToolApprovalResume(blocked('b'), ctx(), snapshot({ memory: 'x' }));
  await settle();
  results.kept_blocked = { sent: sent.splice(0), notices: notices.splice(0) };
  polls = 0; pollQueue = ['allow'];
  scheduleToolApprovalResume({ decision: 'deny' }, ctx(), snapshot({ memory: 'x' }));
  scheduleToolApprovalResume(blocked('c'), ctx('print'), snapshot({ memory: 'x' }));
  await settle();
  results.not_scheduled = { sent: sent.splice(0), polls };
  polls = 0; pollQueue = ['allow'];
  scheduleToolApprovalResume(blocked('d'), ctx(), snapshot({ memory: 'x' }));
  invalidateToolApprovalResumes();
  await settle();
  results.moved_on = { sent: sent.splice(0) };
  pollQueue = ['allow'];
  scheduleToolApprovalResume(blocked('e'), ctx(), snapshot({ memory: 'y'.repeat(9000) }));
  await settle();
  results.oversized = { sent: sent.splice(0) };
  notices.splice(0);
  polls = 0; pollQueue = ['allow'];
  scheduleToolApprovalResume(blocked('a'), ctx(), snapshot({ memory: 'tests run with uv', context: 'repo' }));
  scheduleToolApprovalResume(blocked('b'), ctx(), snapshot({ memory: 'x' }));
  await settle();
  results.settled_again = { sent: sent.splice(0), polls };
  polls = 0; pollQueue = [];
  for (const id of ['c1', 'c2', 'c3', 'c4', 'c5']) {
    scheduleToolApprovalResume(blocked(id), ctx(), snapshot({ memory: id }));
  }
  const cappedNotices = notices.splice(0);
  invalidateToolApprovalResumes();
  scheduleToolApprovalResume(blocked('c6'), ctx(), snapshot({ memory: 'c6' }));
  await settle();
  results.capped = { polls, notices: cappedNotices, after_moving_on: notices.splice(0) };
  sent.splice(0); notices.splice(0);
  const sessionEvents: Record<string, number> = {};
  for (const event of ['session_start', 'session_switch', 'session_branch', 'session_tree', 'session_shutdown']) {
    pollQueue = ['allow'];
    scheduleToolApprovalResume(blocked(`event-${event}`), ctx(), snapshot({ memory: event }));
    fire(event);
    await settle();
    sessionEvents[event] = sent.splice(0).length;
  }
  pollQueue = ['allow'];
  scheduleToolApprovalResume(blocked('event-compact'), ctx(), snapshot({ memory: 'compact' }));
  fire('session_compact');
  await settle();
  sessionEvents.session_compact = sent.splice(0).length;
  results.session_events = sessionEvents;
  polls = 0; pollQueue = ['allow'];
  scheduleToolApprovalResume(blocked('r'), ctx(), snapshot({ memory: 'r' }));
  invalidateToolApprovalResumes();
  scheduleToolApprovalResume(blocked('r'), ctx(), snapshot({ memory: 'r' }));
  await settle();
  results.reissued = { sent: sent.splice(0).map(([message]) => message.details.requestId), polls };
  polls = 0; pollQueue = ['allow', 'allow']; notices.splice(0);
  const currentNotices = [];
  const currentView = {
    ...ctx(),
    sessionId: 's2',
    ui: { notify: (m: string, k: string) => currentNotices.push([k, m]) },
  };
  scheduleToolApprovalResume(blocked('q'), ctx(), snapshot({ memory: 'q' }));
  scheduleToolApprovalResume(blocked('q'), currentView, snapshot({ memory: 'q' }));
  await settle();
  results.two_views = {
    sent: sent.splice(0).length,
    polls,
    stale: notices.splice(0).length,
    current: currentNotices.length,
  };
  sent.splice(0); notices.splice(0);
  for (const outcome of ['timeout', 'transport']) {
    pollQueue = [outcome];
    scheduleToolApprovalResume(blocked(`stopped-${outcome}`), ctx(), snapshot({ memory: outcome }));
    await settle();
  }
  const stoppedNotices = notices.splice(0);
  pollQueue = ['timeout'];
  scheduleToolApprovalResume(blocked('stopped-moved-on'), ctx(), snapshot({ memory: 'moved on' }));
  invalidateToolApprovalResumes();
  await settle();
  results.stopped = { notices: stoppedNotices, moved_on: notices.splice(0), sent: sent.splice(0).length };
  pollQueue = ['allow'];
  scheduleToolApprovalResume(blocked('stopped-timeout'), ctx(), snapshot({ memory: 'timeout' }));
  await settle();
  results.rewatched = sent.splice(0).length;
  notices.splice(0);
  for (const state of [null, 'daemon-b']) {
    pollQueue = ['allow'];
    scheduleToolApprovalResume(blocked(`daemon-${state}`), ctx(), snapshot({ memory: String(state) }));
    daemonState = state;
    await settle();
    daemonState = 'daemon-a';
  }
  results.daemon_changed = { notices: notices.splice(0), sent: sent.splice(0).length };
  console.log(JSON.stringify(results));
}
run();
"""
    )
    harness = tmp_path / "resume.mts"
    harness.write_text(script, encoding="utf-8")
    completed = _run_child([node, "--experimental-strip-types", str(harness)], timeout=30)
    results = _decode_json_object(completed.stdout)

    approved = results["approved"]
    assert isinstance(approved, dict)
    assert approved["polls"] == 1, "the same request is only watched once"
    ((message, options),) = approved["sent"]
    assert options == {"triggerTurn": True, "deliverAs": "nextTurn"}
    assert message["customType"] == "hol_guard_approval_resume"
    assert message["details"] == {"requestId": "a", "toolName": "learn"}
    content = message["content"]
    assert "approved the learn call" in content
    assert json.dumps({"memory": "tests run with uv", "context": "repo"}, separators=(",", ":")) in content
    assert "with exactly these arguments, unchanged" in content
    assert approved["notices"] == [["info", "HOL Guard approved this request. Oh My Pi is running it again."]]

    kept_blocked = results["kept_blocked"]
    assert isinstance(kept_blocked, dict)
    assert kept_blocked["sent"] == []
    assert kept_blocked["notices"] == [["warning", "HOL Guard kept this request blocked. Oh My Pi will not run it."]]

    assert results["not_scheduled"] == {"sent": [], "polls": 0}
    assert results["moved_on"] == {"sent": []}, "the user's own input drops the pending resume"

    oversized = results["oversized"]
    assert isinstance(oversized, dict)
    ((oversized_message, _),) = oversized["sent"]
    assert "with exactly the same arguments, unchanged" in oversized_message["content"]
    assert "y" * 100 not in oversized_message["content"]

    assert results["settled_again"] == {"sent": [], "polls": 0}, "a settled request is never watched again"
    capped = results["capped"]
    assert isinstance(capped, dict)
    assert capped["polls"] == 5, "four watched at once, then a fifth once the user moved on from them"
    ((kind, message),) = capped["notices"]
    assert kind == "warning" and "will not rerun this one on its own" in message
    assert not any("already watching" in message for _, message in capped["after_moving_on"]), (
        "a watcher the user moved on from no longer holds a slot"
    )

    assert results["session_events"] == {
        "session_start": 0,
        "session_switch": 0,
        "session_branch": 0,
        "session_tree": 0,
        "session_shutdown": 0,
        "session_compact": 1,
    }, "moving to another session, or to another point in this one, drops a pending resume; compaction does not"
    assert results["reissued"] == {"sent": ["r"], "polls": 2}, (
        "the same request blocked again after the user moved on is watched afresh"
    )
    stopped = results["stopped"]
    assert isinstance(stopped, dict)
    assert stopped["sent"] == 0
    assert [kind for kind, _ in stopped["notices"]] == ["warning", "warning"]
    assert all("will not rerun it on its own" in message for _, message in stopped["notices"])
    assert stopped["moved_on"] == [], "a watcher the user moved on from ends silently"
    assert results["rewatched"] == 1, "a request whose watcher stopped is watched again"
    daemon_changed = results["daemon_changed"]
    assert isinstance(daemon_changed, dict)
    assert daemon_changed["sent"] == 0, "an approval read from a lost or replaced daemon never resumes"
    assert [kind for kind, _ in daemon_changed["notices"]] == ["warning", "warning"], (
        "losing or replacing the daemon is reported, not silent"
    )
    assert results["two_views"] == {"sent": 1, "polls": 2, "stale": 0, "current": 1}, (
        "only a request's current watcher may act on it"
    )
