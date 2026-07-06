"""Generated Pi managed extension approval-resume helper source."""

# ruff: noqa: E501

from __future__ import annotations

APPROVAL_RESUME_HELPERS_SOURCE = r"""function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
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

function approvalBlockedReason(response: GuardResponse, fallbackReason: string): string {
  const reason = fallbackReason.trim() || 'Blocked by HOL Guard.';
  const approvalUrl = approvalUrlFromResponse(response);
  if (!approvalUrl) return reason;
  const urlLine = `HOL Guard approval page: ${approvalUrl}`;
  const waitLine = 'HOL Guard is already waiting for this approval and will resume this Pi session automatically after the user approves.';
  const askLine = `If you ask the user about this HOL Guard approval, include an option labeled "I've approved this request in HOL Guard" and include this exact URL: ${approvalUrl}`;
  const additions = [urlLine, waitLine, askLine].filter(line => !reason.includes(line));
  if (additions.length === 0) return reason;
  return `${reason}\n\n${additions.join('\n')}`;
}

function openApprovalUrl(response: GuardResponse, openedApprovalUrls: Set<string>): void {
  const approvalUrl = approvalUrlFromResponse(response);
  if (!approvalUrl || openedApprovalUrls.has(approvalUrl)) return;
  openedApprovalUrls.add(approvalUrl);
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
    try {
      const child = spawn(command, args, { detached: true, stdio: 'ignore' });
      child.unref();
      return;
    } catch {}
  }
}

function approvalResumeMessage(details: {
  kind: 'input' | 'tool_call';
  requestId: string;
  prompt?: string;
  toolName?: string;
}): string {
  if (details.kind === 'input') {
    return [
      'HOL Guard approved the Pi user prompt that was blocked in this session.',
      'Continue with the approved request now; do not ask the user to retry it manually.',
      details.prompt ? `Approved prompt:\n${details.prompt}` : '',
    ].filter(Boolean).join('\n\n');
  }
  const toolPart = details.toolName ? ` for ${details.toolName}` : '';
  return [
    `HOL Guard approved the blocked Pi tool call${toolPart}.`,
    'Continue the original user task now. Retry that tool call once if it is still required; '
      + 'the saved HOL Guard approval should allow it.',
    'Do not ask the user to retry the same action manually.',
  ].join('\n\n');
}

async function pollApprovalResolution(
  requestId: string,
  pollPath: string,
): Promise<'allow' | 'block' | null> {
  if (typeof fetch !== 'function') return null;
  const startedAt = Date.now();
  while (Date.now() - startedAt <= GUARD_APPROVAL_RESUME_MAX_WAIT_MS) {
    const connection = loadGuardDaemonConnection();
    if (!connection) return null;
    const controller = typeof AbortController === 'function' ? new AbortController() : undefined;
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
      if (response.status === 404) return null;
      if (response.ok) {
        const item = (await response.json()) as { status?: unknown; resolution_action?: unknown };
        if (item.status === 'resolved') {
          if (item.resolution_action === 'allow') return 'allow';
          if (item.resolution_action === 'block') return 'block';
          return null;
        }
      }
    } catch {
    } finally {
      clearTimeout(timeoutHandle);
    }
    await sleep(GUARD_APPROVAL_RESUME_POLL_INTERVAL_MS);
  }
  return null;
}

"""
