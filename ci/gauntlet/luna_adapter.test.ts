import { test, expect } from 'bun:test';
import { authorized, convertMessages, finishReason, requirePromptable, eventDelta, setModel, WireArguments,
  requireTransportSelection, thinkingLevel, promptCacheKey, usageChunk,
  REQUEST_MODEL, THINKING_LEVELS } from './luna_adapter';

test('native streaming tool argument bytes are preserved across arbitrary splits', () => {
  const indices = new Map<number, number>();
  const start = eventDelta({ type: 'toolcall_start', contentIndex: 2,
    partial: { content: [null, null, { type: 'toolCall', id: 'call_native', name: 'bash' }] } }, indices);
  expect(start.tool_calls[0].function.name).toBe('bash');
  const raw = '{ "command" : "printf \\\"雪\\\"", "timeout":120 }';
  const splits = [raw.slice(0, 8), raw.slice(8, 24), raw.slice(24)];
  const delivered = splits.map(delta => eventDelta({ type: 'toolcall_delta',
    contentIndex: 2, delta }, indices).tool_calls[0].function.arguments).join('');
  expect(Buffer.from(delivered)).toEqual(Buffer.from(raw));
});
test('missing tool identity or uncorrelated argument chunks fail closed', () => {
  expect(() => eventDelta({ type: 'toolcall_delta', contentIndex: 1, delta: '{}' }, new Map())).toThrow();
  expect(() => eventDelta({ type: 'toolcall_start', contentIndex: 0,
    partial: { content: [{ type: 'toolCall', name: 'read' }] } }, new Map())).toThrow();
});
test('complete native argument strings without deltas are forwarded without re-encoding', () => {
  const wire = new WireArguments(); const indices = new Map<number, number>();
  const raw = '{  "path": "雪.txt"  }';
  wire.capture({ data: JSON.stringify({ type: 'response.function_call_arguments.done',
    item_id: 'fc_native', arguments: raw }) });
  eventDelta({ type: 'toolcall_start', contentIndex: 1, partial: { content: [null,
    { type: 'toolCall', id: 'call_native|fc_native', name: 'read' }] } }, indices, wire);
  const result = eventDelta({ type: 'toolcall_end', contentIndex: 1,
    toolCall: { id: 'call_native|fc_native', arguments: { path: '雪.txt' } } }, indices, wire);
  expect(result.tool_calls[0].function.arguments).toBe(raw);
});
test('completion emits only missing bytes and rejects disagreement with delivered deltas', () => {
  const wire = new WireArguments(); const indices = new Map([[0, 0]]);
  wire.full.set('fc_native', '{ "path": "a" }');
  eventDelta({ type: 'toolcall_delta', contentIndex: 0, delta: '{ "path":' }, indices, wire);
  expect(eventDelta({ type: 'toolcall_end', contentIndex: 0,
    toolCall: { id: 'call_native|fc_native' } }, indices, wire).tool_calls[0].function.arguments).toBe(' "a" }');
  wire.streamed.set(0, '{"wrong":');
  expect(() => wire.remaining({ contentIndex: 0, toolCall: { id: 'call_native|fc_native' } })).toThrow();
});

test('conversation conversion drops system text, keeps call ids and rejects orphan results', () => {
  setModel({ api: 'openai-codex-responses', provider: 'openai-codex', id: 'gpt-5.6-luna' });
  const converted = convertMessages([
    { role: 'system', content: 'ignored here' },
    { role: 'user', content: 'go' },
    { role: 'assistant', content: '', tool_calls: [{ id: 'call_1', type: 'function',
      function: { name: 'read', arguments: '{"path":"a"}' } }] },
    { role: 'tool', tool_call_id: 'call_1', content: 'ok' },
  ]);
  expect(converted.map(m => m.role)).toEqual(['user', 'assistant', 'toolResult']);
  expect(converted[1].stopReason).toBe('toolUse');
  expect(converted[2].toolName).toBe('read');
  expect(() => convertMessages([{ role: 'tool', tool_call_id: 'x', content: '' }])).toThrow();
  expect(() => convertMessages([{ role: 'function', content: '' }])).toThrow();
});

test('only the per-run bearer token is authorized', () => {
  const token = 'a'.repeat(32);
  expect(authorized(`Bearer ${token}`, token)).toBe(true);
  for (const header of [null, '', token, `Bearer ${'b'.repeat(32)}`, `Bearer ${token} `, 'Bearer '])
    expect(authorized(header, token)).toBe(false);
  expect(authorized('Bearer ', '')).toBe(false);
});

test('only medium, high or opt-in low thinking levels are accepted', () => {
  expect(thinkingLevel('medium')).toBe('medium');
  expect(thinkingLevel('high')).toBe('high');
  expect(thinkingLevel('low')).toBe('low');
  for (const value of [undefined, '', 'xhigh', 'Medium', ' low'])
    expect(() => thinkingLevel(value)).toThrow('Unsupported Luna thinking level');
});
test('requests must select the adapter model, streaming and the configured effort', () => {
  for (const thinking of THINKING_LEVELS) {
    const body = { model: REQUEST_MODEL, stream: true, reasoning_effort: thinking };
    expect(() => requireTransportSelection(body, thinking)).not.toThrow();
    const other = thinking === 'medium' ? 'high' : 'medium';
    for (const bad of [{ ...body, reasoning_effort: other }, { ...body, reasoning_effort: undefined },
      { ...body, model: 'gpt-5.6-luna' }, { ...body, stream: false }, null])
      expect(() => requireTransportSelection(bad, thinking)).toThrow('Unexpected transport selection');
  }
});
test('finish reasons map without nesting', () => {
  expect(finishReason('toolUse')).toBe('tool_calls');
  expect(finishReason('length')).toBe('length');
  expect(finishReason('stop')).toBe('stop');
});

test('only a session UUID becomes a prompt cache key', () => {
  const session = '123e4567-e89b-42d3-a456-426614174000';
  expect(promptCacheKey(session)).toBe(session);
  for (const header of [null, '', 'not-a-uuid', session.toUpperCase(), ` ${session}`, `${session}x`])
    expect(promptCacheKey(header)).toBeUndefined();
});

test('pi-ai usage folds cached tokens back into prompt_tokens', () => {
  expect(usageChunk({ input: 100, output: 20, cacheRead: 40, cacheWrite: 10, totalTokens: 170,
    reasoningTokens: 5, cost: { total: 0.01 } })).toEqual({
    prompt_tokens: 150, completion_tokens: 20, total_tokens: 170,
    prompt_tokens_details: { cached_tokens: 40 },
    completion_tokens_details: { reasoning_tokens: 5 } });
  expect(usageChunk({ input: 1, output: 2, cacheRead: 0, cacheWrite: 0, totalTokens: 3 }))
    .toEqual({ prompt_tokens: 1, completion_tokens: 2, total_tokens: 3,
      prompt_tokens_details: { cached_tokens: 0 },
      completion_tokens_details: { reasoning_tokens: 0 } });
});
test('usage without the full counter set is not emitted', () => {
  for (const usage of [undefined, null, 'x', { input: 1 }, { input: 1, output: 2, cacheRead: 0,
    cacheWrite: 0, totalTokens: '3' }, { input: -1, output: 0, cacheRead: 0, cacheWrite: 0,
    totalTokens: 0 }, { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2,
    reasoningTokens: -1 }])
    expect(usageChunk(usage)).toBeUndefined();
});

// Needs the pinned SDK; CI does not install it, so this runs only when pointed at one.
test.skipIf(!process.env.GUARD_GAUNTLET_SDK_ROOT)('pinned SDK exposes the Luna model and agent hooks', async () => {
  const root = process.env.GUARD_GAUNTLET_SDK_ROOT!;
  const load = (name: string) => import(Bun.resolveSync(name, root));
  const { Agent } = await load('@oh-my-pi/pi-agent-core');
  const { discoverAuthStorage, ModelRegistry } = await load('@oh-my-pi/pi-coding-agent');
  const registry = new ModelRegistry(await discoverAuthStorage());
  const model = registry.find('openai-codex', 'gpt-5.6-luna');
  expect(model?.id).toBe('gpt-5.6-luna');
  const seen: unknown[] = [];
  for (const thinkingLevel of THINKING_LEVELS) {
    const agent = new Agent({ initialState: { model, thinkingLevel, systemPrompt: '', tools: [], messages: [] },
      onSseEvent: (event: unknown) => seen.push(event) });
    expect(agent.state.thinkingLevel).toBe(thinkingLevel);
    expect(typeof agent.prompt).toBe('function');
    expect(typeof agent.abort).toBe('function');
  }
  expect(typeof registry.resolver).toBe('function');
});

test('a conversation must end with a user or tool message', () => {
  setModel({ api: 'openai-codex-responses', provider: 'openai-codex', id: 'gpt-5.6-luna' });
  expect(() => requirePromptable(convertMessages([{ role: 'system', content: 's' }]))).toThrow();
  expect(() => requirePromptable(convertMessages([{ role: 'user', content: 'u' },
    { role: 'assistant', content: 'a' }]))).toThrow();
  expect(requirePromptable(convertMessages([{ role: 'user', content: 'u' }])).length).toBe(1);
});
