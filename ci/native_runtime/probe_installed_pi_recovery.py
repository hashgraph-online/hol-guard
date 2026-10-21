"""Verify a live generated extension survives replacement of its scoped daemon."""

from __future__ import annotations

import json
import select
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from ci.native_runtime import probe_installed_pi_output as probe

RUNNER = r"""
import {pathToFileURL} from 'node:url';
import {readFileSync} from 'node:fs';
import {createInterface} from 'node:readline';
const [extension, cwd] = process.argv.slice(2);
const lines = createInterface({input: process.stdin})[Symbol.asyncIterator]();
const handlers = new Map(), requests = [];
const originalFetch = globalThis.fetch;
globalThis.fetch = async (url, options) => {
  const response = await originalFetch(url, options);
  const body = await response.clone().json().catch(() => ({}));
  requests.push({route: new URL(String(url)).pathname, status: response.status,
    decision: body.decision, reason_code: body.reason_code, native_route: body.native_route});
  return response;
};
(await import(pathToFileURL(extension).href)).default({on(name, fn) {handlers.set(name, fn);}});
const ctx = {cwd, sessionManager: {getSessionId() {return 'restart-fixture';}, getCwd() {return cwd;}},
  ui: {notify() {}}, signal: new AbortController().signal};
await handlers.get('session_start')({}, ctx);
console.log(JSON.stringify({phase: 'prepared'}));
await lines.next();
const input = {path: cwd + '/ordinary.ts'};
const event = {toolCallId: 'read-after-restart', toolName: 'read', input};
const preserved = JSON.stringify(event);
const result = await handlers.get('tool_call')(event, ctx);
if (result?.block) throw Error('ordinary read blocked after daemon restart: ' + JSON.stringify({
  requests, reason_codes: result.reason?.match(/\b(?:daemon|native)_[a-z0-9_]+\b/g),
  snapshot_failed: result.reason?.includes('immutable tool-call snapshot'),
  context_changed: result.reason?.includes('context changed'),
}));
const content = readFileSync(input.path, 'utf8');
if (content !== 'export const ordinary = 42;\n') throw Error('source bytes mismatch');
const output = await handlers.get('tool_result')({
  ...event, content: [{type: 'text', text: content}], isError: false, details: {},
}, ctx);
if (output?.isError) throw Error('ordinary output blocked after daemon restart');
console.log(JSON.stringify({phase: 'ordinary-verified'}));
await lines.next();
const negative = await handlers.get('tool_call')({
  toolCallId: 'secret-after-restart', toolName: 'read', input: {path: cwd + '/.env'},
}, ctx);
if (negative?.block !== true) throw Error('secret read was not blocked');
if (JSON.stringify(event) !== preserved) throw Error('tool bytes changed');
console.log(JSON.stringify({phase: 'verified', ordinary_allowed: true, secret_blocked: true,
  tool_bytes_unchanged: true, requests}));
process.exit(0);
"""


def main() -> int:
    probe._installed_package_path(probe._REPO_ROOT)
    status, identity, _capabilities = probe._probe_native_identity()
    root = Path(tempfile.mkdtemp(prefix="guard-pi-restart-", dir="/tmp"))
    guard_home = root / "home" / ".hol-guard"
    daemon = None
    child = None
    try:
        home = root / "home"
        workspace = home / "workspace"
        workspace.mkdir(parents=True)
        (workspace / "ordinary.ts").write_text("export const ordinary = 42;\n")
        (workspace / ".env").write_text("SYNTHETIC_SECRET=do-not-read\n")
        daemon = probe._start_installed_daemon(
            guard_home=guard_home,
            home=home,
            workspace=workspace,
            identity=identity,
        )
        probe._prepare_installed_daemon_workspace(daemon, workspace)
        extension = root / "extension.ts"
        probe._generate_extension(extension, guard_home=guard_home, home=home, settings_path=root / "settings.json")
        runner = root / "runner.mjs"
        runner.write_text(RUNNER)
        environment = probe._isolated_env(home=home, python_path=Path(sys.executable))
        child = subprocess.Popen(
            [*probe._node_command(), str(runner), str(extension), str(workspace)],
            cwd=workspace,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert child.stdout is not None and child.stdin is not None
        if not select.select([child.stdout], [], [], 45)[0]:
            raise probe.ProbeError("initial extension setup exceeded its bounded deadline")
        first = json.loads(child.stdout.readline())
        assert first == {"phase": "prepared"}
        probe._cleanup_installed_daemon(daemon)
        daemon = None
        daemon = probe._start_installed_daemon(
            guard_home=guard_home,
            home=home,
            workspace=workspace,
            identity=identity,
        )
        # Do not warm the replacement from Python: the same loaded extension
        # must authenticate and publish its workspace before admitting the read.
        child.stdin.write("replacement-ready\n")
        child.stdin.flush()
        if not select.select([child.stdout], [], [], 90)[0]:
            raise probe.ProbeError("replacement extension review exceeded its bounded deadline")
        ordinary = child.stdout.readline()
        if not ordinary or json.loads(ordinary) != {"phase": "ordinary-verified"}:
            _rest, error = child.communicate(timeout=10)
            raise probe.ProbeError(f"ordinary review did not complete before the negative probe: {probe._short(error)}")
        with sqlite3.connect(f"file:{guard_home / 'guard.db'}?mode=ro", uri=True) as database:
            ordinary_approvals = database.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0]
        assert ordinary_approvals == 0
        output, error = child.communicate("negative-ready\n", timeout=90)
        if child.returncode:
            raise probe.ProbeError(f"restart runner failed: {probe._short(error)}")
        result = json.loads(output)
        assert result["phase"] == "verified"
        assert sum(item["route"].endswith("/readiness") for item in result["requests"]) == 2
        assert all(item["status"] == 200 for item in result["requests"] if item["route"].endswith("/readiness"))
        result["native_reason"] = status.reason
        result["native_routes"] = probe._wait_for_native_route_metrics(daemon, 3)
        with sqlite3.connect(f"file:{guard_home / 'guard.db'}?mode=ro", uri=True) as database:
            result["approval_count"] = database.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0]
        result["ordinary_approval_count"] = ordinary_approvals
        assert result["approval_count"] <= 1  # A protected read may legitimately require fresh approval.
        Path(sys.argv[1]).write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({key: result[key] for key in ["ordinary_allowed", "secret_blocked", "tool_bytes_unchanged"]}))
        return 0
    finally:
        failure = None
        try:
            if child is not None and child.poll() is None:
                child.terminate()
                child.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired) as error:
            failure = probe.ProbeCleanupUnsafeError(f"probe runner containment failed: {type(error).__name__}")
        if daemon is not None:
            try:
                probe._cleanup_installed_daemon(daemon)
            except probe.ProbeError as error:
                if failure is None or isinstance(error, probe.ProbeCleanupUnsafeError):
                    failure = error
        if not isinstance(failure, probe.ProbeCleanupUnsafeError):
            try:
                probe._cleanup_native(identity, guard_home)
            except probe.ProbeError as error:
                if failure is None or isinstance(error, probe.ProbeCleanupUnsafeError):
                    failure = error
        if failure is not None:
            if isinstance(failure, probe.ProbeCleanupUnsafeError):
                probe._retain_unsafe_cleanup_marker(root, failure)
            else:
                probe._retain_cleanup_receipt(root, failure)
            raise failure from sys.exception()
        probe._remove_probe_root(root)


if __name__ == "__main__":
    raise SystemExit(main())
