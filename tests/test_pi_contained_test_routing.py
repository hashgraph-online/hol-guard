"""Exercise the actual generated routing helper, including quoting and cleanup."""

from __future__ import annotations

import hashlib
import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_contained_tests_source import CONTAINED_TEST_HELPERS_SOURCE
from codex_plugin_scanner.guard.adapters.pi_extension_previous_source import previous_managed_extension_source
from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source


def test_routing_is_active_for_pi_and_omp_and_does_not_change_frozen_previous(tmp_path: Path) -> None:
    arguments = {
        "guard_home": tmp_path / "guard",
        "home_dir": tmp_path / "home",
        "settings_path": tmp_path / "settings.json",
        "harness": "omp",
        "display_name": "Oh My Pi",
    }
    active = managed_extension_source(**arguments)
    assert "prepareContainedTestInput(response, snapshot)" in active
    assert "cleanupContainedTestRequest(event.toolCallId, event.details)" in active
    assert "      return { input };\n" in active
    assert '"--harness", "pi"' not in active
    assert "prepareContainedTestInput" not in previous_managed_extension_source(**arguments)
    arguments.update(harness="pi", display_name="Pi")
    pi_source = managed_extension_source(**arguments)
    assert "prepareContainedTestInput" not in previous_managed_extension_source(**arguments)
    assert "prepareContainedTestInput(response, snapshot)" in pi_source
    assert "cleanupContainedTestRequest(event.toolCallId, event.details)" in pi_source
    # Pi ignores a returned input; only an in-place mutation reaches the tool.
    assert "return { input };" not in pi_source
    assert pi_source.count("Object.assign(event.input, input);") == 1
    # The sink re-checks authority under Pi's own harness policy, not OMP's default.
    assert pi_source.count('"execute-contained-test", "--harness", "pi", "--guard-home"') == 1
    # Pi has no session_stop event, so shutdown releases unconsumed request files.
    assert "for (const key of containedTestRequests.keys()) cleanupContainedTestRequest(key);\n  });" in pi_source


@pytest.mark.skipif(sys.platform != "darwin", reason="active profile is macOS-only until Linux enforcement exists")
def test_generated_helper_keeps_original_snapshot_and_quotes_every_argv(tmp_path: Path) -> None:
    bun = shutil.which("bun")
    if bun is None:
        pytest.skip("requires the OMP Bun runtime")
    script = tmp_path / "contained-routing.ts"
    script.write_text(
        """
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const handlers = {};
const pi = { on(name, callback) { handlers[name] = callback; } };
const GUARD_CLI_WRAPPER_COMMAND = "/tmp/guard path'quoted";
const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = false;
const GUARD_HOME = "/tmp/guard-home 'quoted";
const GUARD_HOME_DIR_IS_DEFAULT = true;
const GUARD_HOME_DIR = "/tmp/home";
const GUARD_CONTAINED_SINK_COMMAND = [];
const GUARD_CONTAINED_REQUEST_ROOT = "";
const toolCallIdKey = (value) => typeof value === 'string' ? value : null;
"""
        + CONTAINED_TEST_HELPERS_SOURCE
        + """
const snapshot = {
  cwd: "/project with 'quote",
  payload: { hook_event_name: 'PreToolUse', tool_name: 'bash', tool_call_id: 'test-call',
    tool_input: { command: 'python3 -m pytest -q', timeout: 45 } },
};
const required = { decision: 'deny', policy_action: 'sandbox-required',
  reason_code: 'native_pytest_readonly_containment_required', required_execution_profile: 'pytest-readonly-v2' };
const rejected = [
  prepareContainedTestInput({ ...required, decision: 'allow' }, snapshot),
  prepareContainedTestInput({ ...required, policy_action: 'block' }, snapshot),
  prepareContainedTestInput({ ...required, required_execution_profile: 'pytest-restricted-v1' }, snapshot),
];
const input = prepareContainedTestInput(required, snapshot);
if (!input) throw new Error('protected rewrite not produced');
const duplicate = prepareContainedTestInput(required, snapshot);
const directory = containedTestRequests.get('test-call');
const file = join(directory, 'request.json');
const raw = readFileSync(file, 'utf8');
const output = { rejected, duplicate, input, raw, snapshot,
  directoryMode: statSync(directory).mode & 0o777, fileMode: statSync(file).mode & 0o777 };
const assistant = { role: 'assistant', content: [{type:'toolCall', id:'test-call', name:'bash', arguments:input}] };
const details = handlers.tool_result({toolCallId:'test-call', details:{ordinary:true}}).details;
output.projected = handlers.context({messages:[assistant]}).messages[0].content[0].arguments.command;
output.storedTransportUnchanged = assistant.content[0].arguments.command === input.command;
containedTestPresentations.clear();
const resumedContext = handlers.context({messages:[assistant, {role:'toolResult', toolCallId:'test-call', details}]});
output.resumed = resumedContext.messages[0].content[0].arguments.command;
const mismatchedResult = {role:'toolResult', toolCallId:'different-call', details};
output.mismatched = handlers.context({messages:[assistant, mismatchedResult]}) === undefined;
handlers.session_stop();
output.cleaned = containedTestRequests.size === 0;
try { statSync(directory); output.cleaned = false; } catch {}
// A backgrounded call settles before its job reads the request: keep the file
// for the sink, and release it only at shutdown.
const exists = (path) => { try { statSync(path); return true; } catch { return false; } };
const background = { ...snapshot, payload: { ...snapshot.payload, tool_call_id: 'background-call' } };
if (!prepareContainedTestInput(required, background)) throw new Error('background rewrite not produced');
const backgroundDirectory = containedTestRequests.get('background-call');
cleanupContainedTestRequest('background-call', { async: { state: 'running', jobId: 'job-1', type: 'bash' } });
output.backgroundKept = exists(join(backgroundDirectory, 'request.json'))
  && !containedTestRequests.has('background-call');
handlers.session_stop();
output.backgroundSurvivesStop = exists(backgroundDirectory);
handlers.session_shutdown();
output.backgroundReleased = !exists(backgroundDirectory);
const finished = { ...snapshot, payload: { ...snapshot.payload, tool_call_id: 'finished-call' } };
if (!prepareContainedTestInput(required, finished)) throw new Error('finished rewrite not produced');
const finishedDirectory = containedTestRequests.get('finished-call');
cleanupContainedTestRequest('finished-call', { async: { state: 'completed', jobId: 'job-2', type: 'bash' } });
output.finishedRemoved = !exists(finishedDirectory);
console.log(JSON.stringify(output));
""",
        encoding="utf-8",
    )
    completed = subprocess.run([bun, str(script)], text=True, capture_output=True, timeout=30, check=False)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["rejected"] == [None, None, None]
    assert result["duplicate"] is None
    assert result["cleaned"] is True
    assert result["backgroundKept"] is True
    assert result["backgroundSurvivesStop"] is True
    assert result["backgroundReleased"] is True
    assert result["finishedRemoved"] is True
    assert result["projected"] == "python3 -m pytest -q"
    assert result["resumed"] == "python3 -m pytest -q"
    assert result["storedTransportUnchanged"] is True
    assert result["mismatched"] is True
    assert result["directoryMode"] == 0o700
    assert result["fileMode"] == 0o600
    assert result["input"]["timeout"] == 45
    argv = shlex.split(result["input"]["command"])
    assert argv[0] == "/tmp/guard path'quoted"
    assert argv[1] == "execute-contained-test"
    assert argv[argv.index("--guard-home") + 1] == "/tmp/guard-home 'quoted"
    assert argv[argv.index("--workspace") + 1] == "/project with 'quote"
    assert argv[argv.index("--request-sha256") + 1] == hashlib.sha256(result["raw"].encode()).hexdigest()
    assert json.loads(result["raw"])["payload"] == result["snapshot"]["payload"]
    assert result["snapshot"]["payload"]["tool_input"]["command"] == "python3 -m pytest -q"


def test_windows_routes_only_python_through_the_fixed_sink_and_profile_temp(tmp_path: Path) -> None:
    bun = shutil.which("bun")
    if bun is None:
        pytest.skip("requires the OMP Bun runtime")
    request_root = tmp_path / "profile temp"
    request_root.mkdir()
    script = tmp_path / "contained-routing-windows.ts"
    script.write_text(
        """
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
Object.defineProperty(process, 'platform', { value: 'win32' });
const handlers = {};
const pi = { on(name, callback) { handlers[name] = callback; } };
const GUARD_CLI_WRAPPER_COMMAND = "C:\\\\Python312\\\\python.exe";
const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = true;
const GUARD_HOME = "C:\\\\Users\\\\tester\\\\.hol-guard";
const GUARD_HOME_DIR_IS_DEFAULT = true;
const GUARD_HOME_DIR = "C:\\\\Users\\\\tester";
const GUARD_CONTAINED_SINK_COMMAND = [
  "C:\\\\Program Files\\\\Python312\\\\python.exe", "-I", "-c", "import sys; print('x')", "guard",
];
const GUARD_CONTAINED_REQUEST_ROOT = process.argv[2];
const toolCallIdKey = (value) => typeof value === 'string' ? value : null;
"""
        + CONTAINED_TEST_HELPERS_SOURCE
        + """
const snapshot = (id, command) => ({
  cwd: "C:\\\\Users\\\\tester\\\\project",
  payload: { hook_event_name: 'PreToolUse', tool_name: 'bash', tool_call_id: id, tool_input: { command } },
});
const python = { decision: 'deny', policy_action: 'sandbox-required',
  reason_code: 'native_python_eval_readonly_containment_required',
  required_execution_profile: 'python-eval-readonly-v1' };
const pytest = { decision: 'deny', policy_action: 'sandbox-required',
  reason_code: 'native_pytest_readonly_containment_required', required_execution_profile: 'pytest-readonly-v2' };
const input = prepareContainedTestInput(python, snapshot('python-call', 'python3 test_calc.py'));
const directory = containedTestRequests.get('python-call');
const raw = directory ? readFileSync(join(directory, 'request.json'), 'utf8') : null;
const rejected = prepareContainedTestInput(pytest, snapshot('pytest-call', 'python3 -m pytest'));
// A request root removed after install denies the route instead of throwing.
rmSync(process.argv[2], { recursive: true, force: true });
const gone = prepareContainedTestInput(python, snapshot('gone-call', 'python3 test_calc.py'));
console.log(JSON.stringify({ input, directory, raw, rejected, gone }));
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [bun, str(script), str(request_root)], text=True, capture_output=True, timeout=30, check=False
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["rejected"] is None
    assert result["gone"] is None
    assert Path(result["directory"]).parent == request_root
    argv = shlex.split(result["input"]["command"])
    assert argv[:5] == ["C:\\Program Files\\Python312\\python.exe", "-I", "-c", "import sys; print('x')", "guard"]
    assert argv[5] == "execute-contained-test"
    assert argv[argv.index("--request-file") + 1] == str(Path(result["directory"]) / "request.json")
    assert argv[argv.index("--request-sha256") + 1] == hashlib.sha256(result["raw"].encode()).hexdigest()
