"""Verify a live generated extension survives replacement of its scoped daemon."""

from __future__ import annotations

import json
import select
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
  requests.push({route: new URL(String(url)).pathname, status: response.status});
  return response;
};
(await import(pathToFileURL(extension).href)).default({on(name, fn) {handlers.set(name, fn);}});
const ctx = {cwd, sessionManager: {getSessionId() {return 'restart-fixture';}},
  ui: {notify() {}}, signal: new AbortController().signal};
await handlers.get('session_start')({}, ctx);
console.log(JSON.stringify({phase: 'prepared'}));
await lines.next();
const input = {path: cwd + '/ordinary.ts'};
const event = {toolCallId: 'read-after-restart', toolName: 'read', input};
const preserved = JSON.stringify(event);
const result = await handlers.get('tool_call')(event, ctx);
if (result?.block) throw Error('ordinary read blocked after daemon restart');
const content = readFileSync(input.path, 'utf8');
if (content !== 'export const ordinary = 42;\n') throw Error('source bytes mismatch');
const output = await handlers.get('tool_result')({
  ...event, content: [{type: 'text', text: content}], isError: false, details: {},
}, ctx);
if (output?.isError) throw Error('ordinary output blocked after daemon restart');
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
    daemon = None
    child = None
    try:
        home = root / "home"
        workspace = home / "workspace"
        guard_home = home / ".hol-guard"
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
        daemon = probe._start_installed_daemon(
            guard_home=guard_home,
            home=home,
            workspace=workspace,
            identity=identity,
        )
        # Do not warm the replacement from Python: the same loaded extension
        # must authenticate and publish its workspace before admitting the read.
        output, error = child.communicate("replacement-ready\n", timeout=90)
        if child.returncode:
            raise probe.ProbeError(f"restart runner failed: {probe._short(error)}")
        result = json.loads(output)
        assert result["phase"] == "verified"
        assert sum(item["route"].endswith("/readiness") for item in result["requests"]) == 2
        assert all(item["status"] == 200 for item in result["requests"] if item["route"].endswith("/readiness"))
        result["native_reason"] = status.reason
        Path(sys.argv[1]).write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({key: result[key] for key in ["ordinary_allowed", "secret_blocked", "tool_bytes_unchanged"]}))
        return 0
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            child.wait(timeout=10)
        if daemon is not None:
            probe._cleanup_installed_daemon(daemon)
        probe._cleanup_native(identity, guard_home)
        probe._remove_probe_root(root)


if __name__ == "__main__":
    raise SystemExit(main())
