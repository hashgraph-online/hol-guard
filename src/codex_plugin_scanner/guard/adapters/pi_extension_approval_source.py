"""Generated Pi managed extension approval-resume helper source."""

# ruff: noqa: E501

from __future__ import annotations

APPROVAL_RESUME_HELPERS_SOURCE = r"""type ApprovalPollResult = 'allow' | 'block' | 'timeout' | 'aborted' | 'transport';

type ApprovalContinuationActivity = () => boolean;

function continuationIsActive(activity?: ApprovalContinuationActivity): boolean {
  if (!activity) return true;
  try {
    return activity();
  } catch {
    return false;
  }
}

function waitForApprovalPollInterval(
  ms: number,
  signal?: AbortSignal,
  activity?: ApprovalContinuationActivity,
): Promise<'ready' | 'aborted'> {
  if (signal?.aborted || !continuationIsActive(activity)) return Promise.resolve('aborted');
  return new Promise(resolve => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onAbort = () => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      resolve('aborted');
    };
    timer = setTimeout(() => {
      if (settled) return;
      if (!continuationIsActive(activity)) {
        onAbort();
        return;
      }
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      resolve('ready');
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

function approvalRequestId(response: GuardResponse): string | null {
  if (typeof response.approval_request_id !== 'string') return null;
  const requestId = response.approval_request_id.trim();
  if (!requestId) return null;
  return requestId;
}

function approvalPollPath(response: GuardResponse, requestId: string): string {
  const rawPath = typeof response.resume_poll_path === 'string' ? response.resume_poll_path.trim() : '';
  if (rawPath.startsWith('/v1/requests/')) return rawPath;
  return `/v1/requests/${encodeURIComponent(requestId)}`;
}

function approvalUrlFromResponse(response: GuardResponse): string | null {
  if (typeof response.approval_url !== 'string') return null;
  const approvalUrl = response.approval_url.trim();
  if (!approvalUrl) return null;
  return approvalUrl;
}

function approvalCenterKey(approvalUrl: string): string {
  try {
    return new URL(approvalUrl).origin;
  } catch {
    return approvalUrl;
  }
}

function approvalBlockedReason(
  response: GuardResponse,
  fallbackReason: string,
  kind: 'input' | 'tool_call' = 'tool_call',
): string {
  const reason = fallbackReason.trim() || 'Blocked by HOL Guard.';
  const approvalUrl = approvalUrlFromResponse(response);
  if (!approvalUrl) return reason;
  const urlLine = `HOL Guard approval page: ${approvalUrl}`;
  const waitLine = kind === 'tool_call'
    ? 'HOL Guard is waiting for this decision. The original action remains blocked; after approval, Guard will continue it unchanged without asking the model to replan.'
    : 'HOL Guard is waiting for this decision. The original prompt remains blocked; after approval, Guard will continue it in this session.';
  const noAskLine = 'Do not call ask for this HOL Guard approval as the approval mechanism; HOL Guard is already polling the request.';
  const askFallbackLine = `If you are already showing a broader recovery menu, include an option labeled "I've approved this request in HOL Guard" and include this exact URL: ${approvalUrl}`;
  const additions = [urlLine, waitLine, noAskLine, askFallbackLine].filter(line => !reason.includes(line));
  if (additions.length === 0) return reason;
  return `${reason}\n\n${additions.join('\n')}`;
}

function approvalManualRetryReason(response: GuardResponse, fallbackReason: string): string {
  const reason = fallbackReason.trim() || 'Blocked by HOL Guard.';
  const approvalUrl = approvalUrlFromResponse(response);
  const retryLine = 'This OMP host cannot safely resume a blocked tool call in the background. Retry the exact original tool call after approving it in HOL Guard.';
  const urlLine = approvalUrl ? `HOL Guard approval page: ${approvalUrl}` : '';
  return [reason, retryLine, urlLine].filter(Boolean).join('\n\n');
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

type OmpInteractiveContinuation<T> =
  | { kind: 'completed'; value: T }
  | { kind: 'aborted' }
  | { kind: 'failed' }
  | { kind: 'unavailable' };

function ompInteractiveContext(ctx: unknown): boolean {
  try {
    const typedContext = ctx as { mode?: unknown; ui?: { custom?: unknown } };
    return typedContext.mode === 'tui' && typeof typedContext.ui?.custom === 'function';
  } catch {
    return false;
  }
}

async function runOmpInteractiveContinuation<T>(
  ctx: unknown,
  operation: (signal: AbortSignal) => Promise<T>,
): Promise<OmpInteractiveContinuation<T>> {
  if (!ompInteractiveContext(ctx) || typeof AbortController !== 'function') {
    return { kind: 'unavailable' };
  }
  const typedContext = ctx as {
    ui: {
      custom: (
        factory: (...args: unknown[]) => unknown,
        options?: { overlay?: boolean },
      ) => Promise<unknown>;
    };
  };
  const operationController = new AbortController();
  let completed = false;
  try {
    const result = await typedContext.ui.custom(
      async (...args: unknown[]) => {
        const done = args[3] as ((value: OmpInteractiveContinuation<T>) => void) | undefined;
        if (typeof done !== 'function') {
          operationController.abort();
          return {
            render: () => ['HOL Guard could not create its approval wait state.'],
            invalidate: () => {},
            handleInput: () => {},
            dispose: () => {},
          };
        }
        const component = {
          render: () => ['HOL Guard is waiting for approval...'],
          invalidate: () => {},
          handleInput: () => {},
          dispose: () => {
            if (!completed) operationController.abort();
          },
        };
        void operation(operationController.signal).then(
          value => {
            if (completed) return;
            completed = true;
            done(
              operationController.signal.aborted
                ? { kind: 'aborted' }
                : { kind: 'completed', value },
            );
          },
          error => {
            if (completed) return;
            completed = true;
            done({ kind: isAbortError(error) || operationController.signal.aborted ? 'aborted' : 'failed' });
          },
        );
        return component;
      },
      { overlay: true },
    );
    if (
      result &&
      typeof result === 'object' &&
      'kind' in result &&
      ['completed', 'aborted', 'failed', 'unavailable'].includes((result as { kind?: unknown }).kind as string)
    ) {
      return result as OmpInteractiveContinuation<T>;
    }
    return { kind: 'failed' };
  } catch (error) {
    const aborted = isAbortError(error) || operationController.signal.aborted;
    completed = true;
    operationController.abort();
    return { kind: aborted ? 'aborted' : 'failed' };
  } finally {
    if (!operationController.signal.aborted) operationController.abort();
  }
}

function trySpawnOpen(command: string, args: string[]): Promise<boolean> {
  return new Promise(resolve => {
    let settled = false;
    const settle = (opened: boolean) => {
      if (settled) return;
      settled = true;
      resolve(opened);
    };
    try {
      const child = spawn(command, args, { detached: true, stdio: 'ignore' });
      child.once('spawn', () => {
        child.unref();
        settle(true);
      });
      child.once('error', () => settle(false));
    } catch {
      settle(false);
    }
  });
}

async function openApprovalUrl(response: GuardResponse, openedApprovalCenters: Set<string>): Promise<void> {
  const approvalUrl = approvalUrlFromResponse(response);
  if (!approvalUrl) return;
  const approvalCenter = approvalCenterKey(approvalUrl);
  if (openedApprovalCenters.has(approvalCenter)) return;
  openedApprovalCenters.add(approvalCenter);
  const platform = process.platform;
  let commands: Array<[string, string[]]>;
  if (platform === 'darwin') {
    commands = [['open', [approvalUrl]]];
  } else if (platform === 'win32') {
    commands = [['cmd', ['/c', 'start', '', approvalUrl]]];
  } else {
    commands = [
      ['xdg-open', [approvalUrl]],
      ['gio', ['open', approvalUrl]],
      ['exo-open', [approvalUrl]],
      ['sensible-browser', [approvalUrl]],
    ];
  }
  for (const [command, args] of commands) {
    if (await trySpawnOpen(command, args)) return;
  }
}

function approvalResumeMessage(details: {
  kind: 'input';
  requestId: string;
  prompt?: string;
}): string {
  return [
    'HOL Guard approved the Pi user prompt that was blocked in this session.',
    'Continue with the approved request now; do not ask the user to retry it manually.',
    details.prompt ? `Approved prompt:\n${details.prompt}` : '',
  ].filter(Boolean).join('\n\n');
}

async function pollApprovalResolution(
  requestId: string,
  pollPath: string,
  signal?: AbortSignal,
  activity?: ApprovalContinuationActivity,
): Promise<ApprovalPollResult> {
  if (typeof fetch !== 'function') return 'transport';
  const startedAt = Date.now();
  while (Date.now() - startedAt <= GUARD_APPROVAL_RESUME_MAX_WAIT_MS) {
    if (signal?.aborted || !continuationIsActive(activity)) return 'aborted';
    const connection = loadGuardDaemonConnection();
    if (!connection) return 'transport';
    const controller = typeof AbortController === 'function' ? new AbortController() : undefined;
    let removeAbortListener = () => {};
    if (controller && signal) {
      if (signal.aborted) return 'aborted';
      const onAbort = () => controller.abort();
      signal.addEventListener('abort', onAbort, { once: true });
      removeAbortListener = () => signal.removeEventListener('abort', onAbort);
    }
    const timeoutHandle = setTimeout(
      () => controller?.abort(),
      GUARD_APPROVAL_RESUME_FETCH_TIMEOUT_MS,
    );
    try {
      const response = await fetch(`http://127.0.0.1:${connection.port}${pollPath}`, {
        method: 'GET',
        headers: { 'X-Guard-Token': connection.authToken },
        signal: controller?.signal,
      });
      if (signal?.aborted || !continuationIsActive(activity)) return 'aborted';
      if (response.status === 404) return 'timeout';
      if (!response.ok) return 'transport';
      if (response.ok) {
        const item = (await response.json()) as { status?: unknown; resolution_action?: unknown };
        if (item.status === 'resolved') {
          if (item.resolution_action === 'allow') return 'allow';
          if (item.resolution_action === 'block') return 'block';
          return 'block';
        }
      }
    } catch (error) {
      if (signal?.aborted || !continuationIsActive(activity)) return 'aborted';
      // The per-request timeout is retryable; a daemon/transport error is not.
      if (!(error instanceof Error && error.name === 'AbortError')) return 'transport';
    } finally {
      clearTimeout(timeoutHandle);
      removeAbortListener();
    }
    if (await waitForApprovalPollInterval(
      GUARD_APPROVAL_RESUME_POLL_INTERVAL_MS,
      signal,
      activity,
    ) === 'aborted') {
      return 'aborted';
    }
  }
  return 'timeout';
}

function canonicalJson(value: unknown): string | null {
  const normalize = (item: unknown): unknown => {
    if (item === null || typeof item === 'string' || typeof item === 'boolean') {
      return item;
    }
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) throw new TypeError('non-finite number is not JSON serializable');
      return item;
    }
    if (item === undefined || typeof item === 'function' || typeof item === 'symbol') {
      throw new TypeError('unsupported runtime value is not JSON serializable');
    }
    if (typeof item === 'bigint') throw new TypeError('bigint is not JSON serializable');
    if (Array.isArray(item)) {
      return item.map(entry => normalize(entry));
    }
    if (typeof item === 'object') {
      const prototype = Object.getPrototypeOf(item);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError('non-plain object is not JSON serializable');
      }
      // A null-prototype map keeps an input key named "__proto__" as data.
      const normalized = Object.create(null) as Record<string, unknown>;
      for (const key of Object.keys(item as Record<string, unknown>).sort()) {
        normalized[key] = normalize((item as Record<string, unknown>)[key]);
      }
      return normalized;
    }
    throw new TypeError('unsupported runtime value is not JSON serializable');
  };
  try {
    const serialized = JSON.stringify(normalize(value));
    return typeof serialized === 'string' ? serialized : null;
  } catch {
    return null;
  }
}

function freezeSnapshot<T>(value: T): T {
  if (value && typeof value === 'object') {
    if (Array.isArray(value)) {
      for (const entry of value) freezeSnapshot(entry);
    } else {
      for (const entry of Object.values(value as Record<string, unknown>)) freezeSnapshot(entry);
    }
    Object.freeze(value);
  }
  return value;
}

function eventToolInput(event: unknown): Record<string, unknown> | null {
  const value = event as {
    input?: unknown;
    toolInput?: unknown;
    arguments?: unknown;
  };
  for (const candidate of [value.input, value.toolInput, value.arguments]) {
    if (candidate === undefined) continue;
    if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
      return candidate as Record<string, unknown>;
    }
    return null;
  }
  return null;
}

function handlerAbortSignal(ctx: unknown): AbortSignal | undefined {
  try {
    const candidate = (ctx as { signal?: unknown }).signal;
    if (
      candidate &&
      typeof candidate === 'object' &&
      typeof (candidate as { aborted?: unknown }).aborted === 'boolean' &&
      typeof (candidate as { addEventListener?: unknown }).addEventListener === 'function' &&
      typeof (candidate as { removeEventListener?: unknown }).removeEventListener === 'function'
    ) {
      return candidate as AbortSignal;
    }
  } catch {
  }
  return undefined;
}

type ToolCallSnapshot = {
  payload: Record<string, unknown>;
  canonicalPayload: string;
  cwd: string;
};

function contextCwd(ctx: unknown): string | null {
  try {
    const typedContext = ctx as {
      sessionManager?: { getCwd?: () => unknown };
    };
    const getCwd = typedContext.sessionManager?.getCwd;
    if (typeof getCwd !== 'function') return null;
    const cwd = getCwd.call(typedContext.sessionManager);
    return typeof cwd === 'string' && cwd.length > 0 ? cwd : null;
  } catch {
    return null;
  }
}

function contextSessionId(ctx: unknown): string | null {
  try {
    const typedContext = ctx as {
      sessionManager?: { getSessionId?: () => unknown };
    };
    const getSessionId = typedContext.sessionManager?.getSessionId;
    if (typeof getSessionId !== 'function') return null;
    const sessionId = getSessionId.call(typedContext.sessionManager);
    return typeof sessionId === 'string' && sessionId.trim().length > 0 ? sessionId : null;
  } catch {
    return null;
  }
}

function buildToolCallPayload(
  event: unknown,
  ctx: unknown,
  configPath: string,
  toolInput: Record<string, unknown>,
): Record<string, unknown> | null {
  try {
    const typedEvent = event as { toolCallId?: unknown; toolName?: unknown };
    const sessionId = contextSessionId(ctx);
    if (!sessionId) return null;
    return {
      hook_event_name: "PreToolUse",
      config_path: configPath,
      tool_call_id: typedEvent.toolCallId,
      session_id: sessionId,
      tool_name: typedEvent.toolName,
      tool_input: toolInput,
    };
  } catch {
    return null;
  }
}

function snapshotToolCall(event: unknown, ctx: unknown, configPath: string): ToolCallSnapshot | null {
  const cwd = contextCwd(ctx);
  if (!cwd) return null;
  const toolInput = eventToolInput(event);
  if (!toolInput) return null;
  const payload = buildToolCallPayload(event, ctx, configPath, toolInput);
  if (!payload) return null;
  const canonicalPayload = canonicalJson(payload);
  if (!canonicalPayload) return null;
  try {
    const immutablePayload = freezeSnapshot(JSON.parse(canonicalPayload)) as Record<string, unknown>;
    return { payload: immutablePayload, canonicalPayload, cwd };
  } catch {
    return null;
  }
}

function toolCallStillMatches(
  event: unknown,
  ctx: unknown,
  configPath: string,
  snapshot: ToolCallSnapshot,
): boolean {
  if (contextCwd(ctx) !== snapshot.cwd) return false;
  const toolInput = eventToolInput(event);
  const currentPayload = toolInput
    ? buildToolCallPayload(event, ctx, configPath, toolInput)
    : null;
  const currentCanonical = currentPayload ? canonicalJson(currentPayload) : null;
  return currentCanonical !== null && currentCanonical === snapshot.canonicalPayload;
}

function approvalContinuationFailureReason(
  response: GuardResponse,
  result: Exclude<ApprovalPollResult, 'allow'>,
): string {
  const suffix =
    result === 'block'
      ? 'HOL Guard approval was denied.'
      : result === 'timeout'
        ? 'HOL Guard approval expired or timed out; the tool call remains blocked.'
        : result === 'aborted'
          ? 'The host cancelled the pending HOL Guard approval; the tool call remains blocked.'
          : 'HOL Guard approval could not be revalidated because the local daemon was unavailable.';
  return response.reason?.trim() ? `${response.reason.trim()} ${suffix}` : suffix;
}

"""
