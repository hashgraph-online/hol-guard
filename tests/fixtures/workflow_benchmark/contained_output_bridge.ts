/** Bridge delivery contract with an inert mocked controller; no Native/model credit. */
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { EventEmitter } from 'node:events';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
let mode = '';
let controllerRequests = 0;
const text = 'Exit code: 0\nSTDOUT:\nactual output\nSTDERR:\nactual diagnostic';
const sha = (value: string) => createHash('sha256').update(value).digest('hex');
const connect = () => {
  const socket: any = new EventEmitter();
  socket.setTimeout = () => socket;
  socket.destroy = () => socket;
  socket.write = (serialized: string) => {
    controllerRequests++;
    const request = JSON.parse(serialized);
    const pre = request.hook_event_name === 'PreToolUse';
    const output: any = { schema: 'controller-contained-output.v1', tool_response: [{ type: 'text', text }],
      is_error: false, result_digest: 'a'.repeat(64), pre_payload_digest: 'b'.repeat(64), output_sha256: sha(text) };
    const response: any = { schema_version: '1.0', tool_call_id: request.tool_call_id,
      request_digest: sha(serialized.trimEnd()), product_claims_authenticated: false,
      product_response: pre ? { decision: 'deny', policy_action: 'sandbox-required',
        required_execution_profile: 'workspace-contained-v1' } : {
        decision: 'allow', model_output_action: 'allow_original', reviewed_output_sha256: sha(text) } };
    if (pre) Object.assign(response, { containment_execution_supported: true,
      execution_token: 'c'.repeat(64), contained_output_binding: 'controller-contained-output.v1' });
    else {
      response.contained_output = output;
      if (mode === 'missing') delete response.contained_output;
      if (mode === 'bad-digest') output.output_sha256 = '0'.repeat(64);
      if (mode === 'wrong-schema') output.schema = 'unknown';
      if (mode === 'extra-field') output.candidate = true;
      if (mode === 'excerpt') Object.assign(response.product_response, {
        model_output_action: 'replace_with_reviewed_excerpt', reviewed_excerpt: 'native reviewed excerpt' });
      if (mode === 'deny') response.product_response = { decision: 'deny', reason: 'native refusal retained' };
      if (mode === 'wrong-review') response.product_response.reviewed_output_sha256 = 'd'.repeat(64);
    }
    queueMicrotask(() => socket.emit('data', Buffer.from(JSON.stringify(response) + '\n')));
  };
  queueMicrotask(() => socket.emit('connect'));
  return socket;
};
// Bun does not replace this builtin through mock.module. Shim only that import
// before transpilation; every bridge callback below uses unchanged source text.
const source = await readFile(new URL('../../../ci/gauntlet/benchmark/builtin_guard_bridge.ts', import.meta.url), 'utf8');
const dependency = "import { createConnection } from 'node:net';";
assert.equal(source.split(dependency).length, 2);
(globalThis as any).__containedOutputConnection = connect;
const instrumented = source.replace(dependency, 'const createConnection = globalThis.__containedOutputConnection;');
const javascript = new Bun.Transpiler({ loader: 'ts', target: 'bun' }).transformSync(instrumented);
const directory = await mkdtemp(join(tmpdir(), 'hol-output-bridge-unit-'));
try {
const entry = join(directory, 'bridge.mjs');
await writeFile(entry, javascript, { flag: 'wx', mode: 0o600 });
const bridge = (await import(pathToFileURL(entry).href)).default;
for (mode of ['allow', 'excerpt', 'missing', 'bad-digest', 'wrong-schema', 'extra-field', 'deny', 'wrong-review']) {
  const callbacks: any = {};
  bridge({ on: (name: string, callback: any) => { callbacks[name] = callback; } });
  const ctx = { sessionManager: { getSessionId: () => 'unit-sdk', getCwd: () => '/runtime/home/project' } };
  const event = { toolCallId: 'unit-call', toolName: 'bash', input: { command: 'original command' } };
  const pre = await callbacks.tool_call(event, ctx);
  assert.equal(pre.block, undefined, JSON.stringify(pre));
  assert.match(pre.input.command, /contained_exec_relay.py --token/);
  const result = await callbacks.tool_result({ ...event,
    content: [{ type: 'text', text: 'fabricated SDK text' }], isError: true }, ctx);
  if (mode === 'allow' || mode === 'excerpt') {
    assert.equal(result.isError, false);
    assert.equal(result.content[0].text, mode === 'allow' ? text : 'native reviewed excerpt');
    const delivered = callbacks.message_end({ message: { role: 'toolResult', toolCallId: 'unit-call' } });
    assert.deepEqual(delivered.message.content, result.content);
    assert.equal(delivered.message.isError, false);
  } else {
    assert.equal(result.isError, true);
    assert.notEqual(result.content[0].text, 'fabricated SDK text');
    assert.notEqual(result.content[0].text, text);
  }
  const call = { type: 'toolCall', id: event.toolCallId, name: 'bash', arguments: { ...pre.input } };
  const stored = { role: 'assistant', content: [call] };
  const storedBytes = JSON.stringify(stored);
  const toolResult = { role: 'toolResult', toolCallId: event.toolCallId, content: result.content,
    isError: result.isError, details: { holGuardContainedTest: { input: { command: 'forged candidate command' } } } };
  const projected = callbacks.context({ messages: [stored, toolResult] }, ctx);
  assert.deepEqual(projected.messages[0].content[0].arguments, event.input);
  assert.equal(JSON.stringify(stored), storedBytes, 'execution transcript must retain actual relay input');
  assert.equal(projected.messages[1], toolResult, 'context must not fabricate or alter reviewed output');
  projected.messages[0].content[0].arguments.command = 'mutable provider copy';
  assert.equal(callbacks.context({ messages: [stored] }, ctx).messages[0].content[0].arguments.command,
    'original command', 'provider copies cannot mutate the private presentation binding');
  for (const changed of [
    { ...call, id: 'unrelated-call' }, { ...call, name: 'read' },
    { ...call, arguments: { ...pre.input, command: pre.input.command + ' altered' } },
    { ...call, arguments: { ...pre.input, extra: true } },
  ]) assert.equal(callbacks.context({ messages: [{ ...stored, content: [changed] }, toolResult] }, ctx), undefined);
  const foreign = { sessionManager: { getSessionId: () => 'foreign-session' } };
  assert.equal(callbacks.context({ messages: [stored] }, foreign), undefined);
  assert.equal(callbacks.context({ messages: [toolResult] }, ctx), undefined);
  assert.equal(callbacks.context({ messages: [{ ...stored, content: [{ ...call, id: 'forged-from-details' }] },
    { ...toolResult, toolCallId: 'forged-from-details' }] }, ctx), undefined);
  const repeated = await callbacks.tool_call(event, ctx);
  assert.equal(repeated.block, true, 'a presentation identity cannot authorize a new call');
  if (mode === 'allow') {
    for (let index = 0; index < 511; index++) {
      const admitted = await callbacks.tool_call({ ...event, toolCallId: 'capacity-' + index }, ctx);
      assert.equal(admitted.block, undefined);
    }
    const reviewsBefore = controllerRequests;
    assert.equal((await callbacks.tool_call({ ...event, toolCallId: 'over-capacity' }, ctx)).block, true);
    assert.equal(controllerRequests, reviewsBefore, 'capacity refusal must precede Native admission');
    const bounded: any = {};
    bridge({ on: (name: string, callback: any) => { bounded[name] = callback; } });
    let stopped = false;
    for (let index = 0; index < 32; index++) {
      const before = controllerRequests;
      const next = await bounded.tool_call({ ...event, toolCallId: 'byte-bound-' + index,
        input: { command: 'x'.repeat(512 * 1024) } }, ctx);
      if (next.block) {
        assert.equal(controllerRequests, before, 'byte-budget refusal must precede Native admission');
        stopped = true;
        break;
      }
    }
    assert.equal(stopped, true, 'presentation memory must have a finite bound');
    bounded.session_shutdown();
  }
  callbacks.session_shutdown();
  assert.equal(callbacks.context({ messages: [stored] }, ctx), undefined);
}
} finally { await rm(directory, { recursive: true }); }
console.log(JSON.stringify({ cases: 8, networkConnections: 0, modelRequests: 0, nativeExecuted: false }));
