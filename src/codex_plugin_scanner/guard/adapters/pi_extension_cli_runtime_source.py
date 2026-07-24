"""Generated Pi CLI fallback runtime source."""

from __future__ import annotations

CLI_RUNTIME_HELPERS_SOURCE = r"""
type GuardCliResult = {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error & { code?: unknown };
};
let guardCliEvaluationInFlight = false;

function signalGuardCliChild(
  child: ReturnType<typeof spawn>,
  signal: NodeJS.Signals,
): void {
  if (process.platform !== 'win32' && typeof child.pid === 'number') {
    try {
      process.kill(-child.pid, signal);
      return;
    } catch {}
  }
  child.kill(signal);
}

function runGuardCliCommand(
  command: string,
  args: string[],
  serializedPayload: string,
  timeoutMs: number,
): Promise<GuardCliResult> {
  return new Promise((resolve) => {
    let settled = false;
    let timedOut = false;
    let stdout = '';
    let stderr = '';
    let escalationHandle: ReturnType<typeof setTimeout> | undefined;
    let forcedSettleHandle: ReturnType<typeof setTimeout> | undefined;
    const timeoutError = () => Object.assign(
      new Error('Guard CLI evaluation timed out.'),
      { code: 'ETIMEDOUT' },
    );
    const settle = (result: GuardCliResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutHandle);
      if (escalationHandle !== undefined) clearTimeout(escalationHandle);
      if (forcedSettleHandle !== undefined) clearTimeout(forcedSettleHandle);
      resolve(result);
    };
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(command, args, {
        detached: process.platform !== 'win32',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (error) {
      resolve({ status: null, stdout, stderr, error: error as Error });
      return;
    }
    const timeoutHandle = setTimeout(() => {
      timedOut = true;
      signalGuardCliChild(child, 'SIGTERM');
      escalationHandle = setTimeout(() => {
        signalGuardCliChild(child, 'SIGKILL');
        forcedSettleHandle = setTimeout(
          () => settle({ status: null, stdout, stderr, error: timeoutError() }),
          100,
        );
      }, 100);
    }, timeoutMs);
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      stdout = (stdout + chunk).slice(-GUARD_TEXT_LIMIT_CHARS);
    });
    child.stderr?.on('data', (chunk: string) => {
      stderr = (stderr + chunk).slice(-GUARD_TEXT_LIMIT_CHARS);
    });
    child.once('error', (error) => settle({ status: null, stdout, stderr, error }));
    child.once('close', (status) => settle({
      status: timedOut ? null : status,
      stdout,
      stderr,
      ...(timedOut ? { error: timeoutError() } : {}),
    }));
    child.stdin?.once('error', () => {});
    child.stdin?.end(`${serializedPayload}\n`);
  });
}
"""
