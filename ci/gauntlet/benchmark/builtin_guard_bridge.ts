/** Public readonly OMP extension: actual SDK tool_call -> controller UDS -> NativeHook.
 * No native package, Guard keys, signing authority, approvals, or policy lives here.
 * The controller must authenticate this exact SDK PID, not just UID10001.
 */
import { createHash } from 'node:crypto';
import { createConnection } from 'node:net';

const SOCKET = '/runtime/guard-hook/hook.sock';
const LIMIT = 1024 * 1024;
const BUILTINS = new Set(['read', 'write', 'edit', 'bash']);
const REVIEW_TIMEOUT_MS = 35_000;
// A bash PreToolUse review may execute a contained command for up to 300s.
// Keep the transport deadline below OMP's configured 380s handler deadline.
const CONTAINED_REVIEW_TIMEOUT_MS = 360_000;

function canonical(value: any): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  }
  throw new Error('SDK hook snapshot is not bounded inert JSON');
}

function capture(event: any, ctx: any, hookEvent = 'PreToolUse', originalInput?: any) {
  const input = originalInput ?? event.input ?? event.toolInput ?? event.arguments;
  const sessionId = ctx.sessionManager?.getSessionId?.();
  const cwd = ctx.sessionManager?.getCwd?.();
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || typeof event.toolName !== 'string' || typeof event.toolCallId !== 'string'
      || typeof sessionId !== 'string' || typeof cwd !== 'string') {
    throw new Error('actual SDK tool-call identity/input/context unavailable');
  }
  const active = Object.fromEntries(Object.entries(process.env).filter(([, value]) =>
    typeof value === 'string' && value.length > 0));
  const environmentNames = [...new Set([...Object.keys(active),
    ...['GIT_PAGER', 'PAGER'].filter(name => typeof process.env[name] === 'string')])].sort();
  const serializedEnvironment = canonical(active).replace(/[^\x00-\x7f]/g, char =>
    '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0'));
  const request: any = { schema_version: '1.0', hook_event_name: hookEvent, session_id: sessionId,
    tool_call_id: event.toolCallId, tool_name: event.toolName, tool_input: input, cwd,
    execution_environment: { path: process.env.PATH ?? '', environment_names: environmentNames,
      environment_digest: createHash('sha256').update(serializedEnvironment).digest('hex'),
      home: process.env.HOME ?? null, xdg_config_home: process.env.XDG_CONFIG_HOME || null,
      git_config_no_system: ['1', 'true', 'yes', 'on'].includes((process.env.GIT_CONFIG_NOSYSTEM ?? '').toLowerCase()),
      git_pager_disabled: typeof process.env.GIT_PAGER === 'string'
        && /^(?:cat|less(?: -[ABCEFGIJKLMNQRSUVWXacdefgimnqrsuw~]+)*)?$/.test(process.env.GIT_PAGER),
      pager_disabled: typeof process.env.PAGER === 'string'
        && /^(?:cat|less(?: -[ABCEFGIJKLMNQRSUVWXacdefgimnqrsuw~]+)*)?$/.test(process.env.PAGER),
      library_search_paths: Object.fromEntries(['LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH',
        'DYLD_FALLBACK_LIBRARY_PATH', 'DYLD_FRAMEWORK_PATH'].filter(name => process.env[name])
        .map(name => [name, process.env[name]])) } };
  if (hookEvent === 'PostToolUse') {
    if (!Array.isArray(event.content) || event.content.some((item: any) =>
      !item || item.type !== 'text' || typeof item.text !== 'string')) {
      throw new Error('Actual NativeHook bridge supports text output only; structured output withheld.');
    }
    request.tool_response = event.content.map((item: any) => ({ type: 'text', text: item.text }));
    request.is_error = event.isError === true;
  }
  const serialized = canonical(request);
  if (Buffer.byteLength(serialized) > LIMIT) throw new Error('actual SDK hook snapshot exceeds byte budget');
  return { serialized, requestDigest: createHash('sha256').update(serialized).digest('hex') };
}

function relay(serialized: string, signal?: AbortSignal, timeoutMs = REVIEW_TIMEOUT_MS): Promise<any> {
  return new Promise((resolve, reject) => {
    let bytes = Buffer.alloc(0), settled = false;
    const socket = createConnection({ path: SOCKET });
    const finish = (error?: Error, value?: any) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', aborted);
      socket.destroy();
      error ? reject(error) : resolve(value);
    };
    const aborted = () => finish(new Error('actual SDK hook cancelled before execution'));
    signal?.addEventListener('abort', aborted, { once: true });
    if (signal?.aborted) return aborted();
    socket.setTimeout(timeoutMs, () => finish(new Error('controller NativeHook deadline exceeded')));
    socket.on('error', error => finish(error));
    socket.on('connect', () => socket.write(serialized + '\n'));
    socket.on('data', chunk => {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length > LIMIT) return finish(new Error('controller NativeHook response exceeds byte budget'));
      const newline = bytes.indexOf(10);
      if (newline < 0) return;
      if (newline !== bytes.length - 1) return finish(new Error('ambiguous NativeHook response frames'));
      try { finish(undefined, JSON.parse(bytes.subarray(0, newline).toString('utf8'))); }
      catch (error) { finish(error as Error); }
    });
    socket.on('end', () => { if (!settled) finish(new Error('controller NativeHook response truncated')); });
  });
}

export default function (api: any) {
  const originalInputs = new Map<string, any>();
  const boundContainedCalls = new Set<string>();
  const replacedResults = new Map<string, { text: string, isError: boolean }>();
  // Provider presentation only. Stored SDK execution inputs remain unchanged.
  // Nothing from candidate output/details can create or alter these bindings.
  const presentations = new Map<string, { sessionId: string, inputJson: string, transportJson: string }>();
  let presentationBytes = 0;
  api.on('tool_call', async (event: any, ctx: any) => {
    if (!BUILTINS.has(event.toolName)) return undefined;
    try {
      const snapshot = capture(event, ctx);
      const request = JSON.parse(snapshot.serialized);
      const inputJson = canonical(request.tool_input);
      if (event.toolName === 'bash' && (presentations.has(event.toolCallId)
          || presentations.size >= 512 || presentationBytes + Buffer.byteLength(inputJson) * 2 + 512 > 8 * LIMIT)) {
        return { block: true, reason: 'Contained command presentation capacity or call identity exhausted before review.' };
      }
      const response = await relay(snapshot.serialized, ctx.signal,
        event.toolName === 'bash' ? CONTAINED_REVIEW_TIMEOUT_MS : REVIEW_TIMEOUT_MS);
      if (ctx.signal?.aborted || capture(event, ctx).serialized !== snapshot.serialized) {
        return { block: true, reason: 'Actual SDK input/context changed while NativeHook reviewed it.' };
      }
      if (response?.schema_version !== '1.0' || response.tool_call_id !== event.toolCallId
          || response.request_digest !== snapshot.requestDigest || response.product_claims_authenticated !== false) {
        return { block: true, reason: 'Controller NativeHook response was not bound to this actual SDK call.' };
      }
      const product = response.product_response;
      if (!product || !['allow', 'deny', 'block'].includes(product.decision)) {
        return { block: true, reason: 'Actual NativeHook decision is unavailable.' };
      }
      if (product.required_execution_profile !== undefined || product.policy_action === 'sandbox-required') {
        if (product.decision === 'deny' && response.containment_execution_supported === true
            && typeof response.execution_token === 'string' && /^[0-9a-f]{64}$/.test(response.execution_token)
            && event.toolName === 'bash') {
          if (response.contained_output_binding !== undefined) {
            if (response.contained_output_binding !== 'controller-contained-output.v1') {
              return { block: true, reason: 'Unknown controller contained output binding.' };
            }
            boundContainedCalls.add(event.toolCallId);
          }
          const input = JSON.parse(snapshot.serialized).tool_input;
          originalInputs.set(event.toolCallId, input);
          // The native sink may use its full 300s budget plus capture time.
          // Keep OMP's own Bash deadline beyond that bounded relay window.
          const transport = { ...input, command: '/usr/bin/python3 /runtime/public/contained_exec_relay.py --token '
            + response.execution_token, timeout: 360 };
          const transportJson = canonical(transport);
          presentations.set(event.toolCallId, { sessionId: request.session_id, inputJson, transportJson });
          presentationBytes += Buffer.byteLength(inputJson) + Buffer.byteLength(transportJson);
          return { input: transport };
        }
        return { block: true, reason: product.reason ?? 'Normal Guard containment is required; execution was not started.' };
      }
      if (product.decision === 'deny' || product.decision === 'block') {
        return { block: true, reason: product.reason ?? 'Blocked by actual NativeHook.' };
      }
      originalInputs.set(event.toolCallId, JSON.parse(snapshot.serialized).tool_input);
      return undefined;
    } catch (error) {
      return { block: true, reason: 'Controller NativeHook transport failed before execution: ' + String(error) };
    }
  });
  api.on('tool_result', async (event: any, ctx: any) => {
    if (!BUILTINS.has(event.toolName)) return undefined;
    const blocked = (reason: string) => {
      replacedResults.set(event.toolCallId, { text: reason, isError: true });
      return { content: [{ type: 'text', text: reason }], details: {}, isError: true };
    };
    try {
      const input = originalInputs.get(event.toolCallId);
      if (!input) return blocked('Original controller-reviewed SDK input is unavailable; output withheld.');
      const snapshot = capture(event, ctx, 'PostToolUse', input);
      const response = await relay(snapshot.serialized, ctx.signal);
      if (ctx.signal?.aborted || capture(event, ctx, 'PostToolUse', input).serialized !== snapshot.serialized
          || response?.schema_version !== '1.0' || response.tool_call_id !== event.toolCallId
          || response.request_digest !== snapshot.requestDigest || response.product_claims_authenticated !== false) {
        return blocked('Actual output/context changed during Native review; output withheld.');
      }
      const product = response.product_response;
      if (!product || ['deny', 'block'].includes(product.decision)) {
        return blocked(product?.reason ?? 'Actual NativeHook withheld this output.');
      }
      if (product.structured_content_mediation !== undefined) {
        return blocked('Structured Native mediation requires an unsupported destination proof; output withheld.');
      }
      const output = response.contained_output;
      if (boundContainedCalls.has(event.toolCallId) || output !== undefined) {
        if (!output || output.schema !== 'controller-contained-output.v1'
            || JSON.stringify(Object.keys(output).sort()) !==
              '["is_error","output_sha256","pre_payload_digest","result_digest","schema","tool_response"]'
            || typeof output.is_error !== 'boolean' || !Array.isArray(output.tool_response)
            || output.tool_response.length !== 1 || output.tool_response[0]?.type !== 'text'
            || typeof output.tool_response[0]?.text !== 'string'
            || ![output.output_sha256, output.pre_payload_digest, output.result_digest].every(
              value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value))
            || createHash('sha256').update(output.tool_response[0].text).digest('hex') !== output.output_sha256) {
          return blocked('Contained output lacks its exact controller capture binding; output withheld.');
        }
      }
      const content = output?.tool_response ?? JSON.parse(snapshot.serialized).tool_response;
      const text = content.map((item: any) => item.text).join('');
      const actualDigest = createHash('sha256').update(text).digest('hex');
      if (product.decision === 'allow' && product.model_output_action === 'allow_original'
          && product.reviewed_output_sha256 === actualDigest) {
        if (output) {
          replacedResults.set(event.toolCallId, { text, isError: output.is_error });
          return { content, details: {}, isError: output.is_error };
        }
        return undefined;
      }
      if (product.decision === 'allow' && product.model_output_action === 'replace_with_reviewed_excerpt'
          && typeof product.reviewed_excerpt === 'string' && product.reviewed_excerpt.length > 0) {
        const isError = output?.is_error ?? event.isError === true;
        replacedResults.set(event.toolCallId, { text: product.reviewed_excerpt, isError });
        return { content: [{ type: 'text', text: product.reviewed_excerpt }],
          details: {}, isError };
      }
      return blocked(product.reason ?? 'Actual NativeHook did not prove this exact output safe; output withheld.');
    } catch (error) {
      return blocked('Native post-output review failed: ' + String(error));
    } finally {
      originalInputs.delete(event.toolCallId);
      boundContainedCalls.delete(event.toolCallId);
    }
  });
  api.on('message_end', (event: any) => {
    if (event.message?.role !== 'toolResult') return;
    const replacement = replacedResults.get(event.message.toolCallId);
    if (!replacement) return;
    replacedResults.delete(event.message.toolCallId);
    return { message: { ...event.message, content: [{ type: 'text', text: replacement.text }],
      details: {}, isError: replacement.isError } };
  });
  api.on('context', (event: any, ctx: any) => {
    const sessionId = ctx?.sessionManager?.getSessionId?.();
    if (typeof sessionId !== 'string' || !Array.isArray(event.messages)) return undefined;
    let changed = false;
    const messages = event.messages.map((message: any) => {
      if (message.role !== 'assistant' || !Array.isArray(message.content)) return message;
      const content = message.content.map((block: any) => {
        if (block?.type !== 'toolCall' || block.name !== 'bash') return block;
        const presentation = presentations.get(block.id);
        if (!presentation || presentation.sessionId !== sessionId) return block;
        try {
          if (canonical(block.arguments) !== presentation.transportJson) return block;
          changed = true;
          return { ...block, arguments: JSON.parse(presentation.inputJson) };
        } catch { return block; }
      });
      return { ...message, content };
    });
    return changed ? { messages } : undefined;
  });
  api.on('session_shutdown', () => {
    originalInputs.clear(); boundContainedCalls.clear(); replacedResults.clear();
    presentations.clear(); presentationBytes = 0;
  });
}
