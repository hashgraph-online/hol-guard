"""Generated Pi CLI fallback and daemon recovery runtime source."""

from __future__ import annotations

CLI_RUNTIME_HELPERS_SOURCE = r"""
type GuardCliResult = {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error & { code?: unknown };
};
let guardCliEvaluationInFlight = false;
let guardCliContainmentFailed = false;
let guardDaemonRecoveryInFlight: Promise<boolean> | null = null;

function waitForGuardCliChildExit(
  child: ReturnType<typeof spawn>,
  timeoutMs: number,
): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    let settled = false;
    const finish = (exited: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(watchdog);
      resolve(exited);
    };
    const watchdog = setTimeout(
      () => finish(child.exitCode !== null || child.signalCode !== null),
      timeoutMs,
    );
    child.once('exit', () => finish(true));
  });
}

async function signalGuardCliChild(
  child: ReturnType<typeof spawn>,
  signal: NodeJS.Signals,
): Promise<boolean> {
  if (process.platform === 'win32' && typeof child.pid === 'number') {
    const systemRoot = process.env.SystemRoot ?? process.env.SYSTEMROOT;
    if (systemRoot) {
      const treeKilled = await new Promise<boolean>((resolve) => {
        const taskkill = spawn(
          `${systemRoot}\\System32\\taskkill.exe`,
          ['/PID', String(child.pid), '/T', '/F'],
          { stdio: 'ignore', windowsHide: true },
        );
        const watchdog = setTimeout(() => {
          taskkill.kill('SIGKILL');
          resolve(false);
        }, 200);
        taskkill.once('error', () => {
          clearTimeout(watchdog);
          resolve(false);
        });
        taskkill.once('close', (status) => {
          clearTimeout(watchdog);
          resolve(status === 0);
        });
      });
      if (!treeKilled) child.kill('SIGKILL');
      return waitForGuardCliChildExit(child, 200);
    }
  }
  if (process.platform !== 'win32' && typeof child.pid === 'number') {
    try {
      process.kill(-child.pid, signal);
      return waitForGuardCliChildExit(child, 200);
    } catch {}
  }
  child.kill(signal);
  return waitForGuardCliChildExit(child, 200);
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
      new Error('Guard child process timed out.'),
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
      void signalGuardCliChild(child, 'SIGTERM').then(() => {
        escalationHandle = setTimeout(() => {
          void signalGuardCliChild(child, 'SIGKILL').then((killed) => {
            if (!killed) {
              guardCliContainmentFailed = true;
              settle({
                status: null,
                stdout,
                stderr,
                error: Object.assign(
                  new Error('Guard child process containment could not be confirmed.'),
                  { code: 'ECONTAINMENT' },
                ),
              });
              return;
            }
            forcedSettleHandle = setTimeout(
              () => settle({ status: null, stdout, stderr, error: timeoutError() }),
              100,
            );
          });
        }, 100);
      });
    }, timeoutMs);
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      stdout = (stdout + chunk).slice(-GUARD_TEXT_LIMIT_CHARS);
    });
    child.stderr?.on('data', (chunk: string) => {
      stderr = (stderr + chunk).slice(-GUARD_TEXT_LIMIT_CHARS);
    });
    child.once('error', (error) => {
      if (!timedOut) settle({ status: null, stdout, stderr, error });
    });
    child.once('close', (status) => {
      if (!timedOut) settle({ status, stdout, stderr });
    });
    child.stdin?.once('error', () => {});
    child.stdin?.end(serializedPayload ? `${serializedPayload}\n` : '');
  });
}

type GuardDaemonRecoveryKind = "authenticated-control-plane-failure" | "transport-failure";

async function recoverGuardDaemon(
  timeoutMs: number,
  failureKind: GuardDaemonRecoveryKind,
): Promise<boolean> {
  if (guardCliContainmentFailed) return false;
  if (guardDaemonRecoveryInFlight !== null) return guardDaemonRecoveryInFlight;
  guardDaemonRecoveryInFlight = (async () => {
    const result = await runGuardCliCommand(
      GUARD_DAEMON_RECOVERY_COMMAND,
      [...GUARD_DAEMON_RECOVERY_ARGS, failureKind],
      '',
      timeoutMs,
    );
    return result.error === undefined && result.status === 0;
  })();
  try {
    return await guardDaemonRecoveryInFlight;
  } finally {
    guardDaemonRecoveryInFlight = null;
  }
}
"""
