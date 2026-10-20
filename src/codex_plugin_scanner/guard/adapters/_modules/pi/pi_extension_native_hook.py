"""Native hook bridge for generated Pi-family extensions.

The extension runs the compiled runtime's ``pi-hook-bridge`` once per hook
instead of posting to the daemon itself. The runtime asks a live resident
first and posts everything else to the daemon with the extension's own path,
query and token, then prints the status and body the extension would have
read from the daemon. The extension keeps its loopback ``fetch`` when the
runtime is absent, on Windows, or when the runtime cannot be started.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

PI_HOOK_BRIDGE_FEATURE = "pi-hook-bridge-v1"
# `fetch` keeps every Pi hook on the extension's own daemon request. Contract
# tests set it so a subprocess install and the parent verifier agree.
PI_HOOK_BRIDGE_SWITCH = "HOL_GUARD_PI_HOOK_BRIDGE"


def pi_native_hook_runtime(*, guard_home: Path, platform_name: str = os.name) -> Path | None:
    """The native runtime the extension spawns for each hook, or ``None``."""

    if platform_name == "nt" or os.environ.get(PI_HOOK_BRIDGE_SWITCH) == "fetch":
        return None
    from ...native_hook_bridge import native_hook_bridge_executable

    return native_hook_bridge_executable(PI_HOOK_BRIDGE_FEATURE, guard_home=guard_home)


def native_hook_runtime_source(guard_home_json: str) -> str:
    """The ``GUARD_NATIVE_HOOK_RUNTIME`` constant for the extension header."""

    runtime = pi_native_hook_runtime(guard_home=Path(json.loads(guard_home_json)))
    runtime_json = json.dumps(None if runtime is None else str(runtime))
    return f"const GUARD_NATIVE_HOOK_RUNTIME: string | null = {runtime_json};\n"


def native_hook_reply_source(harness: str) -> str:
    """TypeScript that runs the native bridge for one hook."""

    return f"const GUARD_NATIVE_HOOK_HARNESS = {json.dumps(harness)};\n" + _NATIVE_HOOK_REPLY_SOURCE


_NATIVE_HOOK_REPLY_SOURCE = r"""// The bridge escapes the daemon's body once more inside its JSON line.
const GUARD_NATIVE_HOOK_OUTPUT_LIMIT_CHARS = 8 * GUARD_MAX_SERIALIZED_RESPONSE_CHARS + 1024;
// Time the runtime may take to start and exit beyond its own deadline.
const GUARD_NATIVE_HOOK_GRACE_MS = 100;
const GUARD_NATIVE_HOOK_UNSTARTABLE = new Set(['ENOENT', 'EACCES', 'ENOEXEC', 'EPERM']);
// The bridge may use at most this share of the hook's remaining time. A reply
// that misses the bridge deadline then still leaves the extension time to
// recover the daemon and answer before the harness ends the hook.
const GUARD_NATIVE_HOOK_BUDGET_SHARE = 0.7;

// The daemon budget for one hook: capped for the bridge, unchanged when the
// extension posts to the daemon itself.
function nativeGuardBudgetMs(budgetMs: number, remainingMs: number): number {
  if (GUARD_NATIVE_HOOK_RUNTIME === null || process.platform === 'win32') return budgetMs;
  return Math.max(1, Math.min(budgetMs, Math.floor(remainingMs * GUARD_NATIVE_HOOK_BUDGET_SHARE)));
}

type GuardDaemonReply = {
  status: number;
  readBody: (limitChars: number) => Promise<string | null>;
};

function nativeGuardReplyFromLine(line: string): GuardDaemonReply | null {
  let envelope: unknown;
  try {
    envelope = JSON.parse(line);
  } catch {
    return null;
  }
  if (typeof envelope !== 'object' || envelope === null) return null;
  const { status, body } = envelope as { status?: unknown; body?: unknown };
  if (typeof status !== 'number' || !Number.isInteger(status) || status < 100 || status > 599) {
    return null;
  }
  if (typeof body !== 'string') return null;
  return {
    status,
    readBody: async (limitChars: number) => (body.length <= limitChars ? body : null),
  };
}

// The daemon's reply through the native bridge: `undefined` when the runtime
// is not used or cannot start, so the extension posts to the daemon itself,
// and `null` when the bridge ran but no reply arrived in time.
function nativeGuardReply(
  query: string,
  daemonPayload: string,
  timeoutMs: number,
): Promise<GuardDaemonReply | null | undefined> {
  const runtime = GUARD_NATIVE_HOOK_RUNTIME;
  if (runtime === null || process.platform === 'win32') return Promise.resolve(undefined);
  const config = JSON.stringify({
    harness: GUARD_NATIVE_HOOK_HARNESS,
    guard_home: GUARD_HOME,
    query,
    timeout_ms: Math.min(60_000, Math.max(1, Math.floor(timeoutMs))),
  });
  return new Promise((resolve) => {
    let settled = false;
    let stdout = '';
    const finish = (reply: GuardDaemonReply | null | undefined) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutHandle);
      resolve(reply);
    };
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(runtime, ['pi-hook-bridge', config], {
        stdio: ['pipe', 'pipe', 'ignore'],
        windowsHide: true,
      });
    } catch {
      resolve(undefined);
      return;
    }
    const stop = () => {
      try {
        child.kill('SIGKILL');
      } catch {}
    };
    const timeoutHandle = setTimeout(() => {
      stop();
      finish(null);
    }, Math.max(1, timeoutMs) + GUARD_NATIVE_HOOK_GRACE_MS);
    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      if (settled) return;
      stdout += chunk;
      if (stdout.length > GUARD_NATIVE_HOOK_OUTPUT_LIMIT_CHARS) {
        stop();
        finish(null);
      }
    });
    child.once('error', (error) => {
      const code = guardCliProcessErrorCode(error);
      finish(code !== null && GUARD_NATIVE_HOOK_UNSTARTABLE.has(code) ? undefined : null);
    });
    child.once('close', (status) => {
      finish(status === 0 ? nativeGuardReplyFromLine(stdout.trim()) : null);
    });
    child.stdin?.once('error', () => {});
    child.stdin?.end(`${daemonPayload}\n`);
  });
}

"""


__all__ = [
    "PI_HOOK_BRIDGE_FEATURE",
    "PI_HOOK_BRIDGE_SWITCH",
    "native_hook_reply_source",
    "native_hook_runtime_source",
    "pi_native_hook_runtime",
]
