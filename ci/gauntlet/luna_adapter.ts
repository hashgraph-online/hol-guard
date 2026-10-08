import { timingSafeEqual } from 'node:crypto';
import { isAbsolute } from 'node:path';

// Outer transport only. The Gauntlet agent still executes every selected tool
// through its installed Guard extension. No tool executes in this adapter.
// The pinned SDK is imported lazily from the SDK root named on the command line,
// so the pure helpers below can be unit tested without installing it.
export const ADAPTER_ID = 'pinned-omp-native-luna-stream-v2';
export const REQUEST_MODEL = 'native-luna-high';
export const BACKEND_PROVIDER = 'openai-codex';
export const BACKEND_MODEL = 'gpt-5.6-luna';
let model: any;
export function setModel(value: any) { model = value; }
const zeroUsage = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0,
  totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } };

export function convertMessages(messages: any[]) {
  const converted: any[] = [];
  const toolNames = new Map<string, string>();
  for (const message of messages) {
    if (message.role === 'system' || message.role === 'developer') continue;
    if (message.role === 'user') {
      converted.push({ role: 'user', content: message.content, timestamp: Date.now() });
    } else if (message.role === 'assistant') {
      const content: any[] = [];
      if (message.content) content.push({ type: 'text', text: message.content });
      for (const call of message.tool_calls ?? []) {
        toolNames.set(call.id, call.function.name);
        content.push({ type: 'toolCall', id: call.id, name: call.function.name,
          arguments: JSON.parse(call.function.arguments) });
      }
      converted.push({ role: 'assistant', content, api: model!.api,
        provider: model!.provider, model: model!.id, usage: zeroUsage,
        stopReason: content.some(item => item.type === 'toolCall') ? 'toolUse' : 'stop',
        timestamp: Date.now() });
    } else if (message.role === 'tool') {
      const name = toolNames.get(message.tool_call_id);
      if (!name) throw new Error('Unmatched tool result');
      converted.push({ role: 'toolResult', toolCallId: message.tool_call_id,
        toolName: name, content: [{ type: 'text', text: message.content ?? '' }],
        isError: false, timestamp: Date.now() });
    } else throw new Error('Unsupported message role');
  }
  return converted;
}

// The final message is the prompt; it must be a user or tool message.
export function requirePromptable(converted: any[]) {
  const last = converted[converted.length - 1];
  if (!last || (last.role !== 'user' && last.role !== 'toolResult'))
    throw new Error('Conversation must end with a user or tool message');
  return converted;
}

export function finishReason(stopReason: string) {
  if (stopReason === 'toolUse') return 'tool_calls';
  if (stopReason === 'length') return 'length';
  return 'stop';
}

// The relay presents a per-run bearer token, so no other local process can use
// the adapter's ChatGPT login. The token is never a provider credential.
export function authorized(header: string | null, token: string) {
  if (!token || !header) return false;
  const expected = Buffer.from(`Bearer ${token}`);
  const given = Buffer.from(header);
  return expected.length === given.length && timingSafeEqual(expected, given);
}

export class WireArguments {
  full = new Map<string, string>();
  streamed = new Map<number, string>();
  capture(event: any) {
    let data: any;
    try { data = typeof event.data === 'string' ? JSON.parse(event.data) : event.data; }
    catch { return; }
    if (!data || typeof data !== 'object') return;
    if (data.type === 'response.function_call_arguments.done' && typeof data.arguments === 'string')
      this.full.set(data.item_id, data.arguments);
    if (data.type === 'response.output_item.added' || data.type === 'response.output_item.done') {
      if (data.item?.type === 'function_call' && typeof data.item.arguments === 'string')
        this.full.set(data.item.id, data.item.arguments);
    }
  }
  remaining(event: any) {
    const id = event.toolCall.id.split('|')[1];
    const original = this.full.get(id);
    const delivered = this.streamed.get(event.contentIndex) ?? '';
    if (original === undefined || !original.startsWith(delivered))
      throw new Error('Cannot bind original native argument bytes');
    this.streamed.set(event.contentIndex, original);
    return original.slice(delivered.length);
  }
}
export function eventDelta(event: any, indices: Map<number, number>, wire?: WireArguments) {
  if (event.type === 'text_delta') return { content: event.delta };
  if (event.type === 'toolcall_start') {
    const tool = event.partial.content[event.contentIndex];
    if (tool.type !== 'toolCall' || !tool.id || !tool.name) throw new Error('Missing native tool identity');
    const index = indices.size;
    indices.set(event.contentIndex, index);
    return { tool_calls: [{ index, id: tool.id, type: 'function',
      function: { name: tool.name, arguments: '' } }] };
  }
  if (event.type === 'toolcall_delta') {
    const index = indices.get(event.contentIndex);
    if (index === undefined) throw new Error('Missing native tool start');
    // Forward the original streaming argument string, never parsed/re-encoded.
    if (wire) wire.streamed.set(event.contentIndex,
      (wire.streamed.get(event.contentIndex) ?? '') + event.delta);
    return { tool_calls: [{ index, function: { arguments: event.delta } }] };
  }
  if (event.type === 'toolcall_end' && wire) {
    const index = indices.get(event.contentIndex);
    if (index === undefined) throw new Error('Missing native tool start');
    const remaining = wire.remaining(event);
    if (remaining) return { tool_calls: [{ index, function: { arguments: remaining } }] };
  }
  return undefined;
}


async function main() {

const token = process.env.GUARD_GAUNTLET_ROUTE_TOKEN ?? '';
delete process.env.GUARD_GAUNTLET_ROUTE_TOKEN;
if (token.length < 32) throw new Error('Missing per-run route token');
const sdkRoot = process.argv[2];
if (!sdkRoot || !isAbsolute(sdkRoot)) throw new Error('Usage: luna_adapter.ts ABSOLUTE_SDK_ROOT');
const load = (name: string) => import(Bun.resolveSync(name, sdkRoot));
const { Agent } = await load('@oh-my-pi/pi-agent-core');
const { discoverAuthStorage, ModelRegistry } = await load('@oh-my-pi/pi-coding-agent');
const auth = await discoverAuthStorage();
const registry = new ModelRegistry(auth);
model = registry.find(BACKEND_PROVIDER, BACKEND_MODEL);
setModel(model);
if (!model) throw new Error('Pinned native Luna model unavailable');
const active = new Set<any>();
const server = Bun.serve({ hostname: '127.0.0.1', port: 0, idleTimeout: 255,
  async fetch(request) {
    if (!authorized(request.headers.get('authorization'), token))
      return new Response('Unauthorized', { status: 401 });
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/v1/chat/completions')
      return new Response('Not found', { status: 404 });
    const text = await request.text();
    if (Buffer.byteLength(text) > 1_000_000) return new Response('Too large', { status: 413 });
    let body: any;
    try {
      body = JSON.parse(text);
      if (body.model !== REQUEST_MODEL || body.stream !== true || body.reasoning_effort !== 'high')
        throw new Error('Unexpected transport selection');
      requirePromptable(convertMessages(body.messages));
    } catch { return new Response('Invalid transport request', { status: 400 }); }
    const controller = new AbortController();
    const wire = new WireArguments();
    const agent = new Agent({
      initialState: { model, thinkingLevel: 'high', systemPrompt:
        body.messages.filter((m: any) => m.role === 'system' || m.role === 'developer')
          .map((m: any) => m.content).join('\n\n'),
        tools: (body.tools ?? []).map((t: any) => ({ name: t.function.name,
          label: t.function.name, description: t.function.description ?? '',
          parameters: t.function.parameters, execute: async () => {
            throw new Error('Transport adapter cannot execute tools');
          } })), messages: [] },
      // The same normal authentication resolver used by native OMP sessions.
      // Credentials stay inside the pinned SDK; none are exported or logged.
      getApiKey: requestModel => registry.resolver(requestModel, 'guard-gauntlet-native-luna'),
      onSseEvent: event => wire.capture(event),
    });
    active.add(agent);
    const timer = setTimeout(() => agent.abort(), 240_000);
    const stream = new ReadableStream<Uint8Array>({
      start(sink) {
        let finished = false;
        let bytes = 0;
        const indices = new Map<number, number>();
        const send = (delta: any, finish_reason: string | null = null) => {
          const data = `data: ${JSON.stringify({ id: 'native-luna', object: 'chat.completion.chunk',
            // The real backend identity, recorded by the relay as the response model.
            model: `${BACKEND_PROVIDER}/${BACKEND_MODEL}`, choices: [{ index: 0, delta, finish_reason }] })}\n\n`;
          bytes += Buffer.byteLength(data);
          if (bytes > 4_000_000) throw new Error('Transport response limit');
          sink.enqueue(new TextEncoder().encode(data));
        };
        const unsubscribe = agent.subscribe(event => {
          if (finished) return;
          try {
            if (event.type === 'message_update') {
              const delta = eventDelta(event.assistantMessageEvent, indices, wire);
              if (delta) send(delta);
            } else if (event.type === 'message_end' && event.message.role === 'assistant') {
              if (event.message.provider !== model.provider || event.message.model !== model.id)
                throw new Error('Backend identity changed');
              if (event.message.stopReason === 'error' || event.message.stopReason === 'aborted')
                throw new Error('Native inference incomplete');
              send({}, finishReason(event.message.stopReason));
              sink.enqueue(new TextEncoder().encode('data: [DONE]\n\n'));
              finished = true;
              sink.close();
              // Stop the outer SDK before tool dispatch. The real Gauntlet
              // agent receives the untouched selection and owns execution.
              agent.abort();
            }
          } catch {
            finished = true;
            sink.error(new Error('Native transport failed'));
            agent.abort();
          }
        });
        const messages = convertMessages(body.messages);
        agent.replaceMessages(messages.slice(0, -1));
        Promise.resolve(agent.prompt(messages.slice(-1))).catch(() => {
          if (!finished) sink.error(new Error('Native inference failed'));
        }).finally(() => {
          if (!finished) sink.error(new Error('Native inference ended without completion'));
          unsubscribe(); clearTimeout(timer); active.delete(agent);
        });
      },
      cancel() { agent.abort(); controller.abort(); },
    });
    request.signal.addEventListener('abort', () => agent.abort(), { once: true });
    return new Response(stream, { headers: { 'Content-Type': 'text/event-stream' } });
  },
});
console.log(JSON.stringify({ pid: process.pid, port: server.port, adapter: ADAPTER_ID,
  provider: model.provider, model: model.id, thinking: 'high' }));
const shutdown = () => {
  for (const agent of active) agent.abort();
  server.stop(true);
  process.exit(0);
};
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) process.on(signal, shutdown);
// The runner holds our stdin. If it dies without cleanup, the pipe closes and we stop.
void (async () => {
  for await (const _chunk of Bun.stdin.stream()) { /* discard */ }
  shutdown();
})();
}
if (import.meta.main) {
  try { await main(); }
  catch (error) {
    // One bounded line so the runner can report why startup failed.
    console.log(JSON.stringify({ error: String((error as Error)?.message ?? error).slice(0, 200) }));
    process.exit(1);
  }
}
