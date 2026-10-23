/** Synthetic protocol controls, with no model, service or task-success credit. */
import assert from 'node:assert/strict';
import { missingToolCall, PROTOCOL_RECOVERY_PROMPT, runBusinessPrompt } from './business_protocol_recovery';

const malformed = { role: 'assistant', stopReason: 'toolUse', content: [{ type: 'text', text: 'Preparing drafts.' }] };
const complete = { role: 'assistant', stopReason: 'stop', content: [{ type: 'text', text: 'Complete.' }] };
const selected = { ...malformed, content: [{ type: 'toolCall', name: 'service.create', arguments: {} }] };
assert(missingToolCall(malformed));
for (const value of [null, {}, { ...malformed, role: 'user' }, complete, selected,
  { ...malformed, stopReason: 'aborted' }, { ...malformed, content: null }]) {
  assert(!missingToolCall(value));
}

async function scenario(replies: any[], stopAfter = Infinity) {
  let last: unknown;
  const prompts: string[] = [], events: unknown[] = [];
  const outcome = await runBusinessPrompt({
    initialPrompt: 'Original delegated task',
    prompt: async text => { prompts.push(text); last = replies[prompts.length - 1]; },
    lastAssistant: () => last, stopped: () => prompts.length >= stopAfter,
    emit: event => events.push(event),
  });
  return { prompts, events, outcome };
}

const ordinary = await scenario([complete]);
assert.deepEqual(ordinary.outcome, { recoveries: 0, unresolved: false });
assert.equal(ordinary.prompts.length, 1);
assert.equal(ordinary.events.length, 0);
const recovered = await scenario([malformed, complete]);
assert.deepEqual(recovered.outcome, { recoveries: 1, unresolved: false });
assert.deepEqual(recovered.prompts, ['Original delegated task', PROTOCOL_RECOVERY_PROMPT]);
const exhausted = await scenario([malformed, malformed, malformed, complete]);
assert.deepEqual(exhausted.outcome, { recoveries: 2, unresolved: true });
assert.equal(exhausted.prompts.length, 3);
assert.equal((exhausted.events[2] as any).type, 'model_protocol_unresolved');
for (const stopAfter of [1, 2]) {
  const stopped = await scenario([malformed, malformed, complete], stopAfter);
  assert.equal(stopped.prompts.length, stopAfter);
  assert.equal(stopped.outcome.recoveries, stopAfter - 1);
  assert.equal(stopped.outcome.unresolved, false);
}
const validCall = await scenario([selected]);
assert.equal(validCall.prompts.length, 1); // Never replay an executable call.
const noReply = await scenario([undefined]);
assert.equal(noReply.prompts.length, 1);
await assert.rejects(runBusinessPrompt({
  initialPrompt: 'Task', prompt: async () => { throw new Error('transport failed'); },
  lastAssistant: () => malformed, stopped: () => false, emit: () => {},
}), /transport failed/);
console.log(JSON.stringify({ schema: 'business-protocol-conformance.v1', passed: true,
  controls: 9, actualModelEpisode: false, qualificationEligible: false }));
