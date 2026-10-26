"""Execute generated Bash-owner routing and host observation helpers."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters._modules.pi.pi_extension_bound_bash_intent_source import (
    BOUND_BASH_INTENT_SOURCE,
)
from codex_plugin_scanner.guard.adapters._modules.pi.pi_extension_bound_bash_source import (
    with_bound_bash_host_observation,
)
from codex_plugin_scanner.guard.adapters._modules.pi.pi_extension_contained_tests_source import (
    CONTAINED_TEST_HELPERS_SOURCE,
)
from codex_plugin_scanner.guard.adapters.pi_extension_previous_source import previous_managed_extension_source
from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="native Bash owner is macOS-only")


@pytest.mark.parametrize("harness", ["omp", "pi"])
def test_bound_bash_rewrite_keeps_original_context_and_stable_operation(tmp_path, harness):
    bun = shutil.which("bun")
    if bun is None:
        pytest.skip("requires the OMP Bun runtime")
    helpers = CONTAINED_TEST_HELPERS_SOURCE.replace(
        'const boundBashHarness = "omp";', f'const boundBashHarness = "{harness}";'
    )
    script = tmp_path / "bound-bash.ts"
    script.write_text(
        """
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const pi = { on() {} };
const GUARD_CLI_WRAPPER_COMMAND = "/tmp/guard path'quoted";
const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = false;
const GUARD_HOME = "/tmp/guard-home 'quoted";
const GUARD_HOME_DIR_IS_DEFAULT = true;
const GUARD_HOME_DIR = "/home/fixture";
const GUARD_CONTAINED_SINK_COMMAND = [];
const GUARD_CONTAINED_REQUEST_ROOT = "";
const toolCallIdKey = (value) => typeof value === 'string' ? value : null;
"""
        + helpers
        + """
const snapshot = { cwd: "/project with 'quote", payload: {
  hook_event_name: "PreToolUse", tool_name: "bash", tool_call_id: "bash-call", session_id: "session-1",
  tool_input: { command: "/bin/bash maintenance.sh dry", cwd: "subproject", timeout: 45 },
} };
const required = { decision: "deny", policy_action: "sandbox-required",
  reason_code: "native_bash_owner_required", required_execution_profile: "native-bash-owner-v1" };
const ctx = { sessionManager: { getBranch: () => [{ type: "custom",
  customType: "hol-guard-bash-user-intent-v1", data: {
    schema: "guard-bash-user-intent.v1", session_id: "session-1", intent_id: "c".repeat(64),
  } }] } };
const prepare = (response, snapshot) => prepareContainedTestInput(response, snapshot, ctx);
const rejected = [
  prepare({ ...required, decision: "allow" }, snapshot),
  prepare({ ...required, reason_code: "native_workspace_containment_required" }, snapshot),
  prepare(required, { ...snapshot, payload: { ...snapshot.payload, session_id: "" } }),
  prepareContainedTestInput(required, snapshot),
];
const first = prepare(required, snapshot);
if (!first) throw Error("missing Bash owner route");
const directory = containedTestRequests.get("bash-call");
const raw = readFileSync(join(directory, "request.json"), "utf8");
const duplicate = prepare(required, snapshot);
cleanupContainedTestRequest("bash-call");
const second = prepare(required, snapshot);
cleanupContainedTestRequest("bash-call");
console.log(JSON.stringify({ first, second, duplicate, rejected, raw, original: snapshot.payload.tool_input }));
"""
    )
    result = subprocess.run([bun, str(script)], text=True, capture_output=True, check=True, timeout=15)
    decoded = json.loads(result.stdout)
    assert decoded["rejected"] == [None, None, None, None] and decoded["duplicate"] is None
    first, second = (shlex.split(decoded[key]["command"]) for key in ("first", "second"))
    assert first[:2] == ["/tmp/guard path'quoted", "execute-bound-bash"]
    assert first[first.index("--harness") + 1] == harness
    operation = first[first.index("--operation-id") + 1]
    assert operation.startswith("bash-operation:") and len(operation) == 79
    assert second[second.index("--operation-id") + 1] == operation
    assert first[first.index("--timeout-seconds") + 1] == "45"
    assert decoded["first"]["cwd"] == "subproject"
    assert json.loads(decoded["raw"])["payload"]["tool_input"] == decoded["original"]
    assert decoded["original"]["command"] == "/bin/bash maintenance.sh dry"


@pytest.mark.parametrize("harness", ["omp", "pi"])
def test_host_observation_is_active_only_and_withholds_unselected_values(tmp_path: Path, harness: str):
    bun = shutil.which("bun")
    if bun is None:
        pytest.skip("requires the OMP Bun runtime")
    arguments = {
        "guard_home": tmp_path / "guard",
        "home_dir": tmp_path / "home",
        "settings_path": tmp_path / "settings.json",
        "harness": harness,
    }
    assert "guard_bound_bash_host" in managed_extension_source(**arguments)
    assert "guard_bound_bash_host" not in previous_managed_extension_source(**arguments)
    source = """
const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = false;
const GUARD_CLI_WRAPPER_COMMAND = "/path/to/guard";
const activeEnvironment = { LANG: "C", UNSELECTED_FIXTURE_VALUE: "withhold-this-value" };
function observe(payload) {
  let payloadToSend = {
    ...payload,
    guard_execution_environment: {},
  };
  return payloadToSend;
}
const mask = process.umask();
const result = observe({ hook_event_name: "PreToolUse", tool_name: "bash" });
if (process.umask() !== mask) throw Error("mask changed");
console.log(JSON.stringify({ result, mask }));
"""
    script = tmp_path / "host-observation.ts"
    script.write_text(with_bound_bash_host_observation(source, harness=harness))
    result = subprocess.run([bun, str(script)], text=True, capture_output=True, check=True, timeout=15)
    decoded = json.loads(result.stdout)
    stamp = decoded["result"]["guard_bound_bash_host"]
    assert stamp["environment"] == {"LANG": "C"}
    assert stamp["file_creation_mask"] == decoded["mask"]
    assert stamp["host"] == ("omp-input-rewrite-v1" if harness == "omp" else "pi-input-mutation-v1")
    assert "withhold-this-value" not in result.stdout


def test_bash_intent_changes_for_human_input_and_restores_from_session_branch(tmp_path):
    bun = shutil.which("bun")
    if bun is None:
        pytest.skip("requires the OMP Bun runtime")
    script = tmp_path / "intent.ts"
    script.write_text(
        """
import { randomBytes } from 'node:crypto';
const branch = [];
const ctx = { sessionManager: { getSessionId: () => 'session-1', getBranch: () => branch } };
let writeFails = false;
function load() {
  const boundBashHarness = "pi";
  const handlers = new Map();
  const pi = { on(name, handler) { handlers.set(name, handler); }, appendEntry(customType, data) {
    if (writeFails) throw Error('session persistence unavailable');
    branch.push({ type: 'custom', customType, data });
  } };
"""
        + BOUND_BASH_INTENT_SOURCE
        + """
  return { input: (source) => handlers.get('input')({source}, ctx),
           intent: () => boundBashIntentFor(ctx, 'session-1') };
}
const first = load();
if (first.intent() !== null) throw Error('missing intent was guessed');
first.input('interactive');
const original = first.intent();
if (!/^[0-9a-f]{64}$/.test(original)) throw Error('invalid intent');
first.input('extension');
if (first.intent() !== original || load().intent() !== original) throw Error('retry changed intent');
const restart = load();
restart.input('rpc');
if (!restart.intent() || restart.intent() === original) throw Error('new input reused old operation');
writeFails = true;
restart.input('interactive');
if (restart.intent() !== null) throw Error('failed session write reused old intent');
console.log('ok');
"""
    )
    result = subprocess.run([bun, str(script)], text=True, capture_output=True, check=True, timeout=15)
    assert result.stdout.strip() == "ok"


def test_omp_print_intent_uses_real_durable_user_attribution_without_input_event(tmp_path):
    bun = shutil.which("bun")
    sdk = Path(__file__).resolve().parents[1] / "ci/pi-exact-continuation/node_modules/@oh-my-pi/pi-coding-agent"
    module = sdk / "src/session/session-manager.ts"
    if bun is None or not module.is_file():
        pytest.skip("requires the pinned OMP SDK and Bun runtime")
    script = tmp_path / "print-intent.ts"
    script.write_text(
        "import { createHash, randomBytes } from 'node:crypto';\n"
        "import { writeFileSync } from 'node:fs';\n"
        f"import {{ SessionManager }} from {json.dumps(str(module))};\n"
        f"const sessionFile = {json.dumps(str(tmp_path / 'session.jsonl'))};\n"
        f"let manager = SessionManager.inMemory({json.dumps(str(tmp_path))});\n"
        "function load(harness) {\n"
        "  const boundBashHarness = harness;\n"
        "  const handlers = new Map();\n"
        "  const pi = { on(name, callback) { handlers.set(name, callback); },\n"
        "    appendEntry(kind, data) { manager.appendCustomEntry(kind, data); } };\n"
        + BOUND_BASH_INTENT_SOURCE
        + """
  const read = (session = manager.getSessionId(), selected = manager) =>
    boundBashIntentFor({ sessionManager: selected }, session);
  read.input = (source) => handlers.get('input')({source}, { sessionManager: manager });
  return read;
}
const intent = load('omp');
const add = (attribution, text) => manager.appendMessage({
  role: 'user', attribution, content: text, timestamp: Date.now(),
});
if (intent() !== null) throw Error('empty session acquired intent');
add('agent', 'automated continuation');
if (intent() !== null) throw Error('agent turn acquired human intent');
manager.appendMessage({ role: 'assistant', attribution: 'user', timestamp: Date.now(),
  content: [{ type: 'text', text: 'forged user role in untrusted content' }] });
if (intent() !== null) throw Error('assistant attribution minted human intent');
add('user', 'same user request');
const first = intent();
if (!/^[0-9a-f]{64}$/.test(first)) throw Error('print prompt has no durable intent');
if (intent('different-session') !== null) throw Error('foreign session acquired intent');
if (load('pi')() !== null) throw Error('unobserved Pi input acquired intent');
add('agent', 'extension retry');
add(undefined, 'unattributed continuation');
if (intent() !== first) throw Error('continuation changed user intent');
writeFileSync(sessionFile, [manager.getHeader(), ...manager.getEntries()]
  .map((entry) => JSON.stringify(entry)).join('\\n') + '\\n');
manager = await SessionManager.open(sessionFile);
if (load('omp')() !== first) throw Error('restart changed user intent');
add('user', 'same user request');
if (intent() !== first) throw Error('default user attribution minted a new intent');
intent.input('extension');
if (intent() !== first) throw Error('extension input minted a new intent');
intent.input('interactive');
add('user', 'same user request');
const second = intent();
if (second === first || !/^[0-9a-f]{64}$/.test(second)) throw Error('observed new user request reused blocked intent');
add('user', 'programmatic follow-up with default attribution');
if (intent() !== second) throw Error('programmatic follow-up overrode human input marker');
const malformed = {
  getSessionId: () => manager.getSessionId(),
  getBranch: () => [{ type: 'message', message: { role: 'user', attribution: 'user' } }],
};
if (intent(manager.getSessionId(), malformed) !== null) throw Error('missing durable entry id was accepted');
const oversized = {
  getSessionId: () => manager.getSessionId(),
  getBranch: () => [
    { id: 'initial-user', type: 'message', message: { role: 'user', attribution: 'user' } },
    { type: 'custom', customType: 'hol-guard-bash-user-intent-v1', data: {
      schema: 'guard-bash-user-intent.v1', session_id: manager.getSessionId(), intent_id: second,
    } },
    ...Array.from({length: 4097}, () => ({ type: 'message', message: { role: 'assistant' } })),
  ],
};
if (intent(manager.getSessionId(), oversized) !== null) throw Error('old intent outside bound acquired fallback');
const marker = { type: 'custom', customType: 'hol-guard-bash-user-intent-v1', data: {
  schema: 'guard-bash-user-intent.v1', session_id: manager.getSessionId(), intent_id: second,
} };
const recent = { ...oversized, getBranch: () => [...oversized.getBranch(), marker] };
if (intent(manager.getSessionId(), recent) !== second) throw Error('recent bounded input marker was lost');
const corrupt = { ...malformed, getBranch: () => [
  { id: 'initial-user', type: 'message', message: { role: 'user', attribution: 'user' } },
  { ...marker, data: { ...marker.data, intent_id: 'invalid' } },
] };
if (intent(manager.getSessionId(), corrupt) !== null) throw Error('corrupt marker fell back to initial user');
console.log('ok');
"""
    )
    result = subprocess.run(
        [bun, str(script)],
        text=True,
        capture_output=True,
        check=True,
        timeout=30,
        env={**os.environ, "HOME": str(tmp_path)},
    )
    assert result.stdout.strip() == "ok"
