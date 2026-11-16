import { ContextAssistanceApiError } from "./api";
import type { UsageMeter } from "./usage-api";

export const USAGE_POLL_MS = 3_000;
/** Reads in a row that may fail before the page says usage could not be read. */
export const USAGE_FAILURES_SHOWN = 3;
const FALLBACK = "Guard could not read usage right now. Try again in a moment.";

export type UsagePollHooks = {
  read: (signal: AbortSignal) => Promise<UsageMeter>;
  onMeter: (meter: UsageMeter) => void;
  onError: (message: string) => void;
  wait?: (ms: number, signal: AbortSignal) => Promise<void>;
};

export function waitFor(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(done, ms);
    signal.addEventListener("abort", done, { once: true });
    function done() {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    }
  });
}

/**
 * Reads the meter until its count is settled. A failed read is tried again
 * quietly: Guard's helper process answers slowly while it starts and can
 * restart during the minute a first count of a long history takes. The page
 * shows an error only after several reads in a row fail, or at once when Guard
 * answers with numbers this page does not understand.
 */
export async function pollUsage(signal: AbortSignal, hooks: UsagePollHooks): Promise<void> {
  const wait = hooks.wait ?? waitFor;
  let failures = 0;
  while (!signal.aborted) {
    let meter: UsageMeter;
    try {
      meter = await hooks.read(signal);
    } catch (cause) {
      if (signal.aborted) return;
      failures += 1;
      const understood = cause instanceof ContextAssistanceApiError;
      if ((understood && cause.code === "usage_payload_invalid") || failures >= USAGE_FAILURES_SHOWN) {
        hooks.onError(understood ? cause.message : FALLBACK);
        return;
      }
      await wait(USAGE_POLL_MS * failures, signal);
      continue;
    }
    // A read that finishes after the tab was left must not update a page that is gone.
    if (signal.aborted) return;
    failures = 0;
    hooks.onMeter(meter);
    if (meter.state !== "counting" && !meter.refreshing) return;
    await wait(USAGE_POLL_MS, signal);
  }
}
