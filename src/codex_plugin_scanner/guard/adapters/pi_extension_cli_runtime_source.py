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
const GUARD_WINDOWS_JOB_MARKER = 'HOL_GUARD_WINDOWS_JOB_CONTAINED\n';

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

function guardCliProcessErrorCode(error: unknown): string | null {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof error.code === 'string'
  ) ? error.code : null;
}

function guardCliProcessGroupExited(processGroupId: number): boolean {
  try {
    process.kill(-processGroupId, 0);
    return false;
  } catch (error) {
    return guardCliProcessErrorCode(error) === 'ESRCH';
  }
}

async function waitForGuardCliProcessGroupExit(
  processGroupId: number,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (guardCliProcessGroupExited(processGroupId)) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return guardCliProcessGroupExited(processGroupId);
}

async function signalGuardCliChild(
  child: ReturnType<typeof spawn>,
  signal: NodeJS.Signals,
  windowsJobContained: boolean,
): Promise<boolean> {
  try {
    if (
      process.platform === 'win32' &&
      windowsJobContained &&
      (child.exitCode !== null || child.signalCode !== null)
    ) return true;
    if (process.platform === 'win32' && typeof child.pid === 'number') {
      if (GUARD_TASKKILL_PATH !== null) {
        const treeKilled = await new Promise<boolean>((resolve) => {
          let taskkill: ReturnType<typeof spawn>;
          try {
            taskkill = spawn(
              GUARD_TASKKILL_PATH,
              ['/PID', String(child.pid), '/T', '/F'],
              { stdio: 'ignore', windowsHide: true },
            );
          } catch {
            resolve(false);
            return;
          }
          let settled = false;
          const finish = (killed: boolean) => {
            if (settled) return;
            settled = true;
            clearTimeout(watchdog);
            resolve(killed);
          };
          const watchdog = setTimeout(() => {
            try {
              taskkill.kill('SIGKILL');
            } catch {}
            finish(false);
          }, 200);
          taskkill.once('error', () => finish(false));
          taskkill.once('close', (status) => finish(status === 0));
        });
        if (!treeKilled) {
          try {
            child.kill('SIGKILL');
          } catch {}
          const parentExited = await waitForGuardCliChildExit(child, 200);
          return windowsJobContained && parentExited;
        }
        return waitForGuardCliChildExit(child, 200);
      }
      try {
        child.kill('SIGKILL');
      } catch {}
      await waitForGuardCliChildExit(child, 200);
      return false;
    }
    if (process.platform !== 'win32' && typeof child.pid === 'number') {
      try {
        process.kill(-child.pid, signal);
      } catch (error) {
        return guardCliProcessErrorCode(error) === 'ESRCH' || guardCliProcessGroupExited(child.pid);
      }
      await waitForGuardCliChildExit(child, 200);
      return waitForGuardCliProcessGroupExit(child.pid, 200);
    }
    try {
      child.kill(signal);
    } catch {
      return false;
    }
    return waitForGuardCliChildExit(child, 200);
  } catch {
    return false;
  }
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
    let windowsJobContained = false;
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
      const containmentFailure = () => {
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
      };
      void signalGuardCliChild(child, 'SIGTERM', windowsJobContained).then(
        () => {
          escalationHandle = setTimeout(() => {
            void signalGuardCliChild(child, 'SIGKILL', windowsJobContained).then(
              (killed) => {
                if (!killed) {
                  containmentFailure();
                  return;
                }
                forcedSettleHandle = setTimeout(
                  () => settle({ status: null, stdout, stderr, error: timeoutError() }),
                  100,
                );
              },
              containmentFailure,
            );
          }, 100);
        },
        containmentFailure,
      );
    }, timeoutMs);
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      stdout = (stdout + chunk).slice(-GUARD_TEXT_LIMIT_CHARS);
    });
    child.stderr?.on('data', (chunk: string) => {
      if (chunk.includes(GUARD_WINDOWS_JOB_MARKER)) {
        windowsJobContained = true;
        chunk = chunk.replaceAll(GUARD_WINDOWS_JOB_MARKER, '');
      }
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
      GUARD_DAEMON_RECOVERY_ACCEPTS_FAILURE_KIND
        ? [...GUARD_DAEMON_RECOVERY_ARGS, failureKind]
        : GUARD_DAEMON_RECOVERY_ARGS,
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
