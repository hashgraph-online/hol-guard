"""Generated OpenCode process lifecycle helpers."""

OPENCODE_PROCESS_TEMPLATE = """function waitForGuardProcessExit(
  proc: ReturnType<typeof nodeSpawn>,
  timeoutMs: number,
): Promise<boolean> {
  if (proc.exitCode !== null || proc.signalCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    let settled = false;
    const finish = (exited: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(watchdog);
      resolve(exited);
    };
    const watchdog = setTimeout(
      () => finish(proc.exitCode !== null || proc.signalCode !== null),
      timeoutMs,
    );
    proc.once("exit", () => finish(true));
  });
}

function guardProcessErrorCode(error: unknown): string | null {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof error.code === "string"
  ) ? error.code : null;
}

function guardProcessGroupExited(processGroupId: number): boolean {
  try {
    process.kill(-processGroupId, 0);
    return false;
  } catch (error) {
    return guardProcessErrorCode(error) === "ESRCH";
  }
}

async function waitForGuardProcessGroupExit(
  processGroupId: number,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (guardProcessGroupExited(processGroupId)) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return guardProcessGroupExited(processGroupId);
}

async function terminateGuardProcessGroup(
  proc: ReturnType<typeof nodeSpawn>,
  windowsJobContained: boolean,
): Promise<boolean> {
  try {
    const processGroupId = proc.pid;
    if (
      process.platform === "win32" &&
      windowsJobContained &&
      (proc.exitCode !== null || proc.signalCode !== null)
    ) return true;
    if (process.platform === "win32" && typeof processGroupId === "number") {
      if (GUARD_TASKKILL_PATH !== null) {
        const treeKilled = await new Promise<boolean>((resolve) => {
          let taskkill: ReturnType<typeof nodeSpawn>;
          try {
            taskkill = nodeSpawn(
              GUARD_TASKKILL_PATH,
              ["/PID", String(processGroupId), "/T", "/F"],
              { stdio: "ignore", windowsHide: true },
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
              taskkill.kill("SIGKILL");
            } catch {}
            finish(false);
          }, 200);
          taskkill.once("error", () => finish(false));
          taskkill.once("close", (status) => finish(status === 0));
        });
        if (!treeKilled) {
          try {
            proc.kill("SIGKILL");
          } catch {}
          const parentExited = await waitForGuardProcessExit(proc, 200);
          return windowsJobContained && parentExited;
        }
        return waitForGuardProcessExit(proc, 200);
      }
      try {
        proc.kill("SIGKILL");
      } catch {}
      await waitForGuardProcessExit(proc, 200);
      return false;
    }
    try {
      if (process.platform === "win32") {
        proc.kill("SIGTERM");
      } else if (typeof processGroupId === "number") {
        process.kill(-processGroupId, "SIGTERM");
      }
    } catch {}
    await waitForGuardProcessExit(proc, 100);
    try {
      if (process.platform === "win32") {
        proc.kill("SIGKILL");
      } else if (typeof processGroupId === "number") {
        // The direct parent may have exited while descendants still hold hook pipes.
        process.kill(-processGroupId, "SIGKILL");
      }
    } catch {}
    const parentExited = await waitForGuardProcessExit(proc, 200);
    const groupExited =
      process.platform === "win32" ||
      (typeof processGroupId === "number" && await waitForGuardProcessGroupExit(processGroupId, 200));
    return parentExited && groupExited;
  } catch {
    return false;
  }
}

export async function spawnGuardProcess(options: {
  args: string[];
  cwd: string;
  deadlineMs: number;
  env: Record<string, string>;
  stdin: string;
}): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    if (fallbackContainmentFailed) {
      reject(new Error("HOL Guard fallback containment previously failed"));
      return;
    }
    if (fallbackInFlight) {
      reject(new Error("HOL Guard fallback review is already in progress"));
      return;
    }
    const remainingMs = options.deadlineMs - Date.now();
    if (remainingMs <= 0) {
      reject(new Error("HOL Guard fallback review deadline expired"));
      return;
    }
    fallbackInFlight = true;
    let settled = false;
    let timedOut = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (
      outcome:
        | { kind: "resolve"; value: { exitCode: number; stdout: string; stderr: string } }
        | { kind: "reject"; error: unknown },
    ) => {
      if (settled) {
        return;
      }
      settled = true;
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      fallbackInFlight = false;
      if (outcome.kind === "resolve") {
        resolve(outcome.value);
      } else {
        reject(outcome.error);
      }
    };
    let pythonTarget: string;
    try {
      pythonTarget = resolveGuardPythonTarget();
    } catch (error) {
      finish({ kind: "reject", error });
      return;
    }
    let proc: ReturnType<typeof nodeSpawn>;
    try {
      proc = nodeSpawn(pythonTarget, options.args, {
        cwd: options.cwd,
        detached: process.platform !== "win32",
        env: options.env,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (error) {
      finish({ kind: "reject", error });
      return;
    }
    let stdout = "";
    let stderr = "";
    let windowsJobContained = false;
    proc.stdout?.setEncoding("utf8");
    proc.stderr?.setEncoding("utf8");
    proc.stdout?.on("data", (chunk: string) => {
      stdout += chunk;
    });
    proc.stderr?.on("data", (chunk: string) => {
      if (chunk.includes(GUARD_WINDOWS_JOB_MARKER)) {
        windowsJobContained = true;
        chunk = chunk.replaceAll(GUARD_WINDOWS_JOB_MARKER, "");
      }
      stderr += chunk;
    });
    proc.on("error", (error) => {
      if (timedOut) return;
      finish({ kind: "reject", error });
    });
    proc.on("close", (code: number | null) => {
      if (timedOut) return;
      finish({ kind: "resolve", value: { exitCode: code ?? 1, stdout, stderr } });
    });
    timer = setTimeout(() => {
      timedOut = true;
      const containmentFailure = () => {
        fallbackContainmentFailed = true;
        finish({
          kind: "reject",
          error: new Error("HOL Guard fallback containment could not be confirmed"),
        });
      };
      void terminateGuardProcessGroup(proc, windowsJobContained).then(
        (terminated) => {
          if (!terminated) {
            containmentFailure();
            return;
          }
          finish({ kind: "reject", error: new Error("HOL Guard fallback review timed out") });
        },
        containmentFailure,
      );
    }, remainingMs);
    timer.unref();
    proc.stdin?.on("error", () => {});
    proc.stdin?.end(options.stdin);
  });
}

"""
