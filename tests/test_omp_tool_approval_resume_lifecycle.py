"""Block, approve and resume through the whole generated Oh My Pi extension.

The extension runs under Node against a loopback daemon. Its hook route is the
real review worker in safe-alternative mode, with the native edge stubbed to
review, and its request route reads the real approval store. Approvals go
through `apply_approval_resolution`, one request at a time. The fake host
starts an agent turn whenever a message triggers one, as Oh My Pi does, so a
resume's own `agent_start` is part of every scenario.
"""

from __future__ import annotations

import json
import re
import shutil
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.daemon.manager import GUARD_DAEMON_COMPATIBILITY_VERSION
from tests.pi_continuation_support import _decode_json_object, _node_executable, _run_child
from tests.test_native_review_approval_coordination import _edge, _worker

_TOKEN = "fixture-token"
_POLL_INTERVAL = "const GUARD_APPROVAL_RESUME_POLL_INTERVAL_MS = 2_000;"


class _Daemon:
    """The daemon routes the extension uses, plus fixture controls for the user's clicks."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.worker, self.store = _worker(tmp_path, monkeypatch, _edge("omp"), ask=False)
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.queued: list[str] = []
        self.polls: dict[str, int] = {}
        self.replay: dict[str, object] | None = None
        self.last_response: dict[str, object] | None = None
        daemon = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - the base class's name
                del format, args

            def _reply(self, body: object, status: int = 200) -> None:
                encoded = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def do_GET(self) -> None:
                parts = urlparse(self.path).path.split("/")
                if self.headers.get("X-Guard-Token") != _TOKEN or parts[1:3] != ["v1", "requests"]:
                    self._reply({"error": "forbidden"}, 403)
                    return
                request_id = unquote(parts[3])
                daemon.polls[request_id] = daemon.polls.get(request_id, 0) + 1
                row = daemon.store.get_approval_request(request_id)
                self._reply(row if row is not None else {"error": "not_found"}, 200 if row else 404)

            def do_POST(self) -> None:
                parsed = urlparse(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                if parsed.path.startswith("/fixture/"):
                    try:
                        self._reply(daemon.fixture(parsed.path.split("/")[2:], body))
                    except Exception as error:  # surfaced to the harness, which fails the test
                        self._reply({"error": repr(error)}, 500)
                    return
                if self.headers.get("X-Guard-Token") != _TOKEN:
                    self._reply({"error": "forbidden"}, 403)
                elif parsed.path == "/v1/hooks/omp/readiness":
                    self._reply({"ready": True})
                elif parsed.path == "/v1/hooks/omp":
                    self._reply(daemon.hook(body, parse_qs(parsed.query)))
                else:
                    self._reply({"error": "not_found"}, 404)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def hook(self, payload: dict[str, object], params: dict[str, list[str]]) -> dict[str, object]:
        if payload.get("hook_event_name") == "UserPromptSubmit":
            return {"decision": "allow"}
        if self.replay is not None:
            replayed, self.replay = self.replay, None
            return replayed
        workspace = params.get("workspace", [None])[-1]
        response = self.worker.review_http_payload(
            payload=payload,
            params=params,
            default_harness="omp",
            home_dir=self.home,
            guard_home=self.store.guard_home,
            workspace=Path(workspace) if workspace else None,
        )
        resume = response.get("approval_resume")
        if isinstance(resume, dict):
            self.queued.append(str(resume["request_id"]))
        self.last_response = response
        return response

    def fixture(self, command: list[str], body: dict[str, object]) -> object:
        if command == ["queued"]:
            return {"queued": self.queued}
        if command == ["polls"]:
            return {"polls": self.polls}
        if command == ["replay"]:
            self.replay = self.last_response
            return {"replay": self.replay is not None}
        if command == ["resolve"]:
            # One row at a time, as "Allow just this once" on that request.
            apply_approval_resolution(
                store=self.store,
                request_id=str(body["request_id"]),
                action=str(body["action"]),
                scope="artifact",
                workspace=None,
                reason=None,
                resolve_scope_matches=False,
            )
            return {"resolved": body["request_id"]}
        raise AssertionError(f"unknown fixture command {command}")


@pytest.fixture
def daemon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Daemon]:
    running = _Daemon(tmp_path, monkeypatch)
    running.thread.start()
    try:
        yield running
    finally:
        running.server.shutdown()
        running.server.server_close()
        running.worker.close()


def _extension(tmp_path: Path, port: int) -> Path:
    guard_home = tmp_path / "extension-guard-home"
    guard_home.mkdir()
    state = {"compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION, "port": port, "state_id": "daemon-a"}
    (guard_home / "daemon-state.json").write_text(json.dumps(state), encoding="utf-8")
    (guard_home / "daemon-auth-token").write_text(_TOKEN, encoding="utf-8")
    source = managed_extension_source(
        guard_home=guard_home,
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="fixture",
    )
    assert source.count(_POLL_INTERVAL) == 1
    source = source.replace(_POLL_INTERVAL, "const GUARD_APPROVAL_RESUME_POLL_INTERVAL_MS = 20;")
    # A test must never start or ask a real Guard.
    never = json.dumps(shutil.which("false") or "/bin/false")
    for name in ("GUARD_DAEMON_RECOVERY_COMMAND", "GUARD_CLI_WRAPPER_COMMAND"):
        source, count = re.subn(rf"const {name} = .*?;", f"const {name} = {never};", source, count=1)
        assert count == 1
    path = tmp_path / "hol-guard-omp.ts"
    path.write_text(source, encoding="utf-8")
    return path


_HARNESS = r"""
import { pathToFileURL } from 'node:url';
import { writeFileSync } from 'node:fs';

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const timeouts = [];
async function waitFor(label, predicate, timeout = 3_000) {
  const startedAt = Date.now();
  while (!(await predicate())) {
    if (Date.now() - startedAt > timeout) {
      timeouts.push(label);
      return;
    }
    await delay(5);
  }
}
async function fixture(command, body = {}) {
  const response = await fetch(`${DAEMON}/fixture/${command}`, { method: 'POST', body: JSON.stringify(body) });
  const reply = await response.json();
  if (!response.ok) throw new Error(`fixture ${command} failed: ${JSON.stringify(reply)}`);
  return reply;
}

let instance = 0;
async function host() {
  instance += 1;
  const { default: installGuard } = await import(`${pathToFileURL(EXTENSION).href}?instance=${instance}`);
  const handlers = new Map();
  const sent = [];
  const notices = [];
  const session = { id: `session-${instance}`, cwd: WORKSPACE };
  const sessionManager = { getSessionId: () => session.id, getCwd: () => session.cwd };
  const ctx = {
    mode: 'tui', cwd: WORKSPACE, hasUI: true, sessionManager,
    ui: { notify: (message, kind) => notices.push([kind ?? 'info', message]), custom: async () => undefined },
  };
  const emit = async (event, payload) => {
    const results = [];
    for (const handler of handlers.get(event) ?? []) results.push(await handler(payload, ctx));
    return results;
  };
  installGuard({
    on: (event, handler) => handlers.set(event, [...(handlers.get(event) ?? []), handler]),
    // Oh My Pi starts an agent turn for a message that triggers one.
    sendMessage: (message, options) => {
      sent.push({ message, options });
      if (options?.triggerTurn) void emit('agent_start', {});
    },
    sendUserMessage: () => {},
  });
  await emit('session_start', {});
  let calls = 0;
  const block = async (input) => {
    const before = (await fixture('queued')).queued.length;
    const results = await emit('tool_call', { toolCallId: `call-${++calls}`, toolName: 'learn', input });
    if (!results.some((result) => result?.block === true)) throw new Error(`not blocked: ${JSON.stringify(results)}`);
    const queued = (await fixture('queued')).queued;
    return queued.length > before ? queued[queued.length - 1] : null;
  };
  return { sent, notices, emit, block, session };
}
const allow = (requestId) => fixture('resolve', { request_id: requestId, action: 'allow' });
const resumedIds = (sent) => sent.map(({ message }) => message.details?.requestId);

const results = {};

// [P2] A resume's own agent turn must not cancel a sibling approval.
{
  const omp = await host();
  const first = await omp.block({ memory: 'first lesson' });
  const second = await omp.block({ memory: 'second lesson' });
  await allow(first);
  await waitFor('siblings: first resume', () => omp.sent.length === 1);
  await delay(100);
  await allow(second);
  await waitFor('siblings: second resume', () => omp.sent.length === 2);
  results.siblings = { ids: [first, second], resumed: resumedIds(omp.sent), sent: omp.sent };
}

// [P2] One approval starts one turn, even when its response comes back again.
{
  const omp = await host();
  const requestId = await omp.block({ memory: 'replayed lesson' });
  await allow(requestId);
  await waitFor('replay: first resume', () => omp.sent.length === 1);
  await delay(100);
  await fixture('replay');
  await omp.block({ memory: 'replayed lesson' });
  await delay(300);
  results.replay = { requestId, resumed: resumedIds(omp.sent) };
}

// [P2] A burst of reviewed calls is watched by a bounded number of pollers.
{
  const omp = await host();
  const pollsBefore = (await fixture('polls')).polls;
  const ids = [];
  for (let index = 0; index < 10; index += 1) ids.push(await omp.block({ memory: `burst lesson ${index}` }));
  await delay(300);
  const polls = (await fixture('polls')).polls;
  const polled = ids.filter((id) => (polls[id] ?? 0) > (pollsBefore[id] ?? 0));
  await allow(ids[9]);
  await allow(ids[0]);
  await waitFor('burst: resume', () => omp.sent.length >= 1);
  await delay(300);
  results.burst = { ids, polled, resumed: resumedIds(omp.sent), notices: omp.notices };
}

// A new prompt from the user, a session switch or a replaced daemon ends a pending resume.
{
  const omp = await host();
  const prompted = await omp.block({ memory: 'before a new prompt' });
  await omp.emit('input', { text: 'do something else', source: 'interactive' });
  await allow(prompted);
  const extensionInput = await omp.block({ memory: 'before an extension message' });
  await omp.emit('input', { text: 'from an extension', source: 'extension' });
  await allow(extensionInput);
  await waitFor('cancelled: extension message resume', () => omp.sent.length === 1);
  const switched = await omp.block({ memory: 'before a session switch' });
  omp.session.id = 'another-session';
  await omp.emit('session_switch', { reason: 'new' });
  await allow(switched);
  await delay(300);
  results.cancelled = { prompted, extensionInput, switched, resumed: resumedIds(omp.sent) };
}
{
  const omp = await host();
  const requestId = await omp.block({ memory: 'before a daemon restart' });
  writeFileSync(DAEMON_STATE, JSON.stringify({ ...JSON.parse(DAEMON_STATE_JSON), state_id: 'daemon-b' }));
  await allow(requestId);
  await delay(300);
  writeFileSync(DAEMON_STATE, DAEMON_STATE_JSON);
  results.replaced = { resumed: resumedIds(omp.sent) };
}

// The identical call blocked again right after the user's prompt is the same
// queued row; it must be watched again, not mistaken for the stale watcher.
{
  const omp = await host();
  const before = await omp.block({ memory: 'asked for again' });
  await omp.emit('input', { text: 'please try that again', source: 'interactive' });
  const again = await omp.block({ memory: 'asked for again' });
  await allow(again);
  await waitFor('reissued: resume', () => omp.sent.length === 1);
  results.reissued = { same: before !== null && before === again, again, resumed: resumedIds(omp.sent) };
}

results.timeouts = timeouts;
console.log(JSON.stringify(results));
process.exit(0);
"""


def test_the_generated_omp_extension_resumes_each_approval_once(tmp_path: Path, daemon: _Daemon) -> None:
    node = _node_executable()
    if node is None:
        pytest.skip("Node is required to run the generated extension")
    port = daemon.server.server_address[1]
    extension = _extension(tmp_path, port)
    state_path = extension.parent / "extension-guard-home" / "daemon-state.json"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    constants = {
        "EXTENSION": str(extension),
        "DAEMON": f"http://127.0.0.1:{port}",
        "WORKSPACE": str(workspace),
        "DAEMON_STATE": str(state_path),
        "DAEMON_STATE_JSON": state_path.read_text(encoding="utf-8"),
    }
    prelude = "".join(f"const {name} = {json.dumps(value)};\n" for name, value in constants.items())
    harness = tmp_path / "lifecycle.mts"
    harness.write_text(prelude + _HARNESS, encoding="utf-8")
    completed = _run_child([node, "--experimental-strip-types", str(harness)], timeout=60)
    results = _decode_json_object(completed.stdout)

    siblings = results["siblings"]
    assert isinstance(siblings, dict)
    assert all(siblings["ids"]), "both calls queue a bound review"
    assert siblings["resumed"] == siblings["ids"], "the first resume's agent turn must not cancel the second"
    (_, second_resume) = siblings["sent"]
    assert second_resume["options"] == {"triggerTurn": True, "deliverAs": "nextTurn"}
    assert json.dumps({"memory": "second lesson"}, separators=(",", ":")) in second_resume["message"]["content"]

    replay = results["replay"]
    assert isinstance(replay, dict)
    assert replay["resumed"] == [replay["requestId"]], "a replayed response for a settled approval starts no turn"

    burst = results["burst"]
    assert isinstance(burst, dict)
    ids = burst["ids"]
    assert isinstance(ids, list) and len(set(ids)) == 10
    assert burst["polled"] == ids[:4], "only the first four reviewed calls are watched"
    assert burst["resumed"] == [ids[0]], "an approval past the cap is left to the user"
    capped = [message for _, message in burst["notices"] if "will not rerun this one" in message]
    assert len(capped) == 6

    cancelled = results["cancelled"]
    assert isinstance(cancelled, dict)
    assert cancelled["resumed"] == [cancelled["extensionInput"]], (
        "only the user's own prompt or a session switch ends a pending resume"
    )
    assert results["replaced"] == {"resumed": []}, "a replaced daemon's approvals never resume"

    reissued = results["reissued"]
    assert isinstance(reissued, dict)
    assert reissued["same"] is True, "the store hands the identical call its pending row again"
    assert reissued["resumed"] == [reissued["again"]], "a call blocked again after the user's prompt is watched again"
    assert results["timeouts"] == []
