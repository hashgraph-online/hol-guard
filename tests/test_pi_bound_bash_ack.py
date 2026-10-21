"""SDK result observations never substitute for native completion authority."""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from codex_plugin_scanner.guard.adapters._modules.pi.pi_extension_contained_tests_source import (
    CONTAINED_TEST_HELPERS_SOURCE,
)


@pytest.mark.parametrize("harness", ["omp", "pi"])
def test_result_acknowledgement_waits_for_reviewed_matching_final_context(tmp_path, harness):
    bun = shutil.which("bun")
    if bun is None:
        pytest.skip("requires the pinned SDK's Bun runtime")
    samples = [
        ({"isError": False}, 0),
        ({"isError": False, "content": []}, 0),
        ({"isError": False, "content": [{"type": "image", "data": "fixture-image"}]}, None),
        (
            {
                "isError": False,
                "content": [{"type": "text", "text": "ordinary"}, {"type": "image", "data": "fixture-image"}],
            },
            None,
        ),
        ({"isError": True, "details": {"exitCode": 7}}, 7),
        (
            {"isError": True, "content": [{"type": "text", "text": "output\n\nCommand exited with code 7"}]},
            7 if harness == "pi" else None,
        ),
        (
            {"isError": True, "content": [{"type": "text", "text": "Command exited with code 255"}]},
            255 if harness == "pi" else None,
        ),
        ({"isError": True, "details": {"exitCode": 1.5}}, None),
        ({"isError": True, "details": {"exitCode": 7, "async": {"state": "running"}}}, None),
        ({"toolName": "read", "isError": False}, None),
    ]
    for text in (
        "Command aborted",
        "Command timed out after 45 seconds",
        "native_bash_execution_reply_unavailable",
        "output Command exited with code 7",
        "Command exited with code 0",
        "Command exited with code 256",
        "Command exited with code 7\n",
        "Command exited with code 7\n\nCommand aborted",
        "Command exited with code 999999",
        "Command exited with code -1",
    ):
        samples.append(({"isError": True, "content": [{"type": "text", "text": text}]}, None))
    script = tmp_path / "ack-observations.ts"
    script.write_text(
        """
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const handlers = new Map();
const calls = [];
let acknowledgementCode = 0;
const pi = { on(name, callback) {
  const list = handlers.get(name) ?? []; list.push(callback); handlers.set(name, list);
}, async exec(command, args) { calls.push({command, args}); return {code:acknowledgementCode}; } };
const toolCallIdKey = value => typeof value === 'string' ? value : null;
const GUARD_CLI_WRAPPER_COMMAND = '/fixture/guard-cli';
const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = false;
const GUARD_HOME = '/fixture/guard';
const GUARD_HOME_DIR_IS_DEFAULT = true;
const GUARD_HOME_DIR = '/fixture/home';
const GUARD_CONTAINED_SINK_COMMAND = [];
const GUARD_CONTAINED_REQUEST_ROOT = '';
"""
        + CONTAINED_TEST_HELPERS_SOURCE.replace(
            'const boundBashHarness = "omp";', f'const boundBashHarness = "{harness}";'
        )
        + f"\nconst samples = {json.dumps([event for event, _ in samples])};\n"
        + """
const observed = [];
for (const [index, sample] of samples.entries()) {
  calls.length = 0;
  const key = 'sdk-call-'+index;
  const event = {toolCallId:key, toolName:'bash', content:[{type:'text',text:'status'}], ...sample};
  boundBashInvocations.set(key, {operationId:'bash-operation:'+'a'.repeat(64), cwd:'/fixture/project'});
  await handlers.get('tool_result')[0](event);
  if (calls.length) throw Error('tool_result acknowledged before post review');
  const message = {role:'toolResult', ...event};
  await handlers.get('context')[0]({messages:[message]});
  if (calls.length) throw Error('unreviewed result acknowledged');
  const digest = boundBashContextDigest(event.content);
  const details = markBoundBashResultDelivery(event, digest);
  if (details) {
    await handlers.get('context')[0]({messages:[{...message,details,content:[{type:'text',text:'withheld'}]}]});
    if (calls.length) throw Error('withheld result acknowledged');
    await handlers.get('context')[0]({messages:[{...message,details,isError:!event.isError}]});
    if (calls.length) throw Error('changed result status acknowledged');
    await handlers.get('context')[0]({messages:[{...message,details:{...details,exitCode:254}}]});
    if (calls.length) throw Error('changed exit status acknowledged');
    await handlers.get('context')[0]({messages:[{...message,details:{...details,async:{state:'running'}}}]});
    if (calls.length) throw Error('unfinished background result acknowledged');
    await handlers.get('context')[0]({messages:[{...message,details}]});
    const count = calls.length;
    await handlers.get('context')[0]({messages:[{...message,details}]});
    if (calls.length !== count) throw Error('delivered result acknowledgement repeated');
  }
  observed.push(calls.map(call => ({ command:call.command, action:call.args[0],
    exit:call.args[call.args.indexOf('--exit-code')+1] })));
}
const history = [];
for (const key of ['stored-older', 'stored-latest']) {
  boundBashInvocations.set(key, {operationId:'bash-operation:'+'b'.repeat(64), cwd:'/fixture/project'});
  const event = {toolCallId:key, toolName:'bash', isError:false, content:[{type:'text',text:key}]};
  history.push({role:'toolResult', ...event,
    details:markBoundBashResultDelivery(event, boundBashContextDigest(event.content))});
}
calls.length = 0;
await handlers.get('context')[0]({messages:history});
if (calls.length !== 1 || calls[0].args[calls[0].args.indexOf('--tool-call-id')+1] !== 'stored-latest') {
  throw Error('stored context retried superseded invocation acknowledgements');
}
await handlers.get('context')[0]({messages:history});
if (calls.length !== 1) throw Error('stored latest acknowledgement repeated');
acknowledgedBoundBashResults.clear();
calls.length = 0;
acknowledgementCode = 125;
await handlers.get('context')[0]({messages:history});
acknowledgementCode = 0;
await handlers.get('context')[0]({messages:history});
await handlers.get('context')[0]({messages:history});
if (calls.length !== 2) throw Error('failed acknowledgement was cached or successful acknowledgement retried');
console.log(JSON.stringify(observed));
"""
    )
    completed = subprocess.run([bun, str(script)], text=True, capture_output=True, check=True, timeout=15)
    assert json.loads(completed.stdout) == [
        [] if code is None else [{"command": "/fixture/guard-cli", "action": "ack-bound-bash", "exit": str(code)}]
        for _, code in samples
    ]
