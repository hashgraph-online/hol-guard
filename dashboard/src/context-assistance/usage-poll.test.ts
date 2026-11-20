import assert from "node:assert/strict";
import { ContextAssistanceApiError } from "./api";
import { readUsageMeter, type UsageMeter } from "./usage-api";
import { pollUsage, USAGE_FAILURES_SHOWN } from "./usage-poll";

const meter = (state: UsageMeter["state"], refreshing = false): UsageMeter =>
  ({ state, window_days: 7, today: [], week: [], unread: [], refreshing, savings: null });
const timeout = () => new DOMException("The operation timed out.", "TimeoutError");
const unavailable = () => new ContextAssistanceApiError("usage_unavailable", "Guard could not read usage right now. Try again in a moment.");

async function run(answers: (UsageMeter | Error)[]) {
  const shown: UsageMeter["state"][] = [];
  const errors: string[] = [];
  const waits: number[] = [];
  let reads = 0;
  await pollUsage(new AbortController().signal, {
    read: async () => {
      const answer = answers[reads++];
      if (answer === undefined) throw new Error("read past the script");
      if (answer instanceof Error) throw answer;
      return answer;
    },
    onMeter: (next) => shown.push(next.state),
    onError: (message) => errors.push(message),
    wait: async (ms) => { waits.push(ms); },
  });
  return { shown, errors, waits, reads };
}

// The reported case: Guard's helper restarts or starts slowly mid-count, so one read times out or fails.
// The page keeps counting and lands on the numbers instead of "Usage could not be read".
{
  const result = await run([meter("counting"), timeout(), unavailable(), meter("counting"), meter("ready")]);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.shown, ["counting", "counting", "ready"]);
  assert.deepEqual(result.waits, [3_000, 3_000, 6_000, 3_000]);
}

// A first read that times out (a cold start) is tried again too.
{
  const result = await run([timeout(), meter("ready")]);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.shown, ["ready"]);
}

// Totals on screen keep refreshing through a failed read.
{
  const result = await run([meter("ready", true), unavailable(), meter("ready")]);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.shown, ["ready", "ready"]);
}

// Guard really is down: the page says so after a few reads in a row, not forever "Counting".
{
  const result = await run(Array.from({ length: USAGE_FAILURES_SHOWN }, timeout));
  assert.equal(result.reads, USAGE_FAILURES_SHOWN);
  assert.deepEqual(result.errors, ["Guard could not read usage right now. Try again in a moment."]);
}

// Numbers the page cannot read will not change on a retry, so that shows at once.
{
  const result = await run([new ContextAssistanceApiError("usage_payload_invalid", "Guard returned usage numbers this page does not understand.")]);
  assert.equal(result.reads, 1);
  assert.deepEqual(result.errors, ["Guard returned usage numbers this page does not understand."]);
}

// Leaving the tab stops the reads without an error.
{
  const controller = new AbortController();
  const errors: string[] = [];
  let reads = 0;
  await pollUsage(controller.signal, {
    read: async () => { reads += 1; controller.abort(); throw timeout(); },
    onMeter: () => assert.fail("no meter after leaving"),
    onError: (message) => errors.push(message),
  });
  assert.equal(reads, 1);
  assert.deepEqual(errors, []);
}

// Reads through the real readUsageMeter against scripted replies from Guard.
async function runFetch(replies: (() => Response)[]) {
  const originalFetch = globalThis.fetch;
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const storage = new Map<string, string>();
  const browserStorage = { getItem: (key: string) => storage.get(key) ?? null, setItem: (key: string, value: string) => { storage.set(key, value); } };
  Object.defineProperty(globalThis, "window", { configurable: true, value: {
    location: new URL("http://127.0.0.1:4781/guard/settings?guard-token=usage-test-session"),
    sessionStorage: browserStorage, localStorage: browserStorage,
  } });
  let fetches = 0;
  globalThis.fetch = async () => {
    const reply = replies[fetches++];
    if (!reply) throw new Error("fetch past the script");
    return reply();
  };
  const shown: UsageMeter["state"][] = [];
  const errors: string[] = [];
  try {
    await pollUsage(new AbortController().signal, {
      read: readUsageMeter,
      onMeter: (next) => shown.push(next.state),
      onError: (message) => errors.push(message),
      wait: async () => {},
    });
  } finally {
    globalThis.fetch = originalFetch;
    if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
    else Reflect.deleteProperty(globalThis, "window");
  }
  return { fetches, shown, errors };
}

// A reply cut off after its headers is retried, not shown as numbers the page does not understand.
{
  const result = await runFetch([
    () => new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('{"state":"rea')); c.error(new TypeError("network error")); } }), { status: 200 }),
    () => new Response(JSON.stringify(meter("ready")), { status: 200 }),
  ]);
  assert.equal(result.fetches, 2);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.shown, ["ready"]);
}

// A complete reply that is not JSON will not change on a retry, so that shows at once.
{
  const result = await runFetch([() => new Response("<html>proxy error</html>", { status: 200 })]);
  assert.equal(result.fetches, 1);
  assert.deepEqual(result.errors, ["Guard returned usage numbers this page does not understand."]);
}

// A read that finishes after leaving the tab does not update the page.
{
  const controller = new AbortController();
  await pollUsage(controller.signal, {
    read: async () => { controller.abort(); return meter("ready"); },
    onMeter: () => assert.fail("no meter after leaving"),
    onError: () => assert.fail("no error after leaving"),
  });
}

console.log("usage-poll tests passed");
