import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { requestCigarVersions } from "./versions-api";
import { ContextAssistanceApiError } from "./api";
const state = JSON.parse(readFileSync(new URL("./fixtures/intent-state.json", import.meta.url), "utf8")).native_test.ready_observation;
const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
const originalFetch = globalThis.fetch;
const storage = new Map<string, string>();
const browserStorage = { getItem: (key: string) => storage.get(key) ?? null, setItem: (key: string, value: string) => { storage.set(key, value); } };
Object.defineProperty(globalThis, "window", { configurable: true, value: {
  location: new URL("http://127.0.0.1:4781/guard/cigar?guard-token=versions-test-session"),
  sessionStorage: browserStorage, localStorage: browserStorage,
} });
const calls: Array<{ url: string; init?: RequestInit }> = [];
let payload: unknown = { schema: "guard-cigar-versions-result.v1", result: { jobs: [] }, state };
let status = 200;
globalThis.fetch = async (input, init) => {
  calls.push({ url: String(input), init });
  return new Response(JSON.stringify(payload), { status, headers: { "Content-Type": "application/json" } });
};
try {
  const paths = { releases: "versions", jobs: "jobs", catalog: "catalog", interpreters: "interpreters" } as const;
  for (const action of Object.keys(paths) as (keyof typeof paths)[]) {
    const before = calls.length;
    const reply = await requestCigarVersions({ action }, { currentPassword: "unused-read-proof" });
    assert.equal(reply.state.effective_enabled, true);
    assert.equal(calls.length, before + 1, "metadata reads must issue no preparation or activation request");
    const call = calls.at(-1)!;
    assert.equal(call.url, "http://127.0.0.1:4781/v1/context-assistance/" + paths[action]);
    assert.equal(call.init?.method, undefined);
    assert.equal(call.init?.body, undefined);
    assert.equal(call.init?.cache, "no-store");
    assert.equal(new Headers(call.init?.headers).get("X-Guard-Dashboard-Session"), "versions-test-session");
  }
  for (const input of [{ action: "preferences" }, { action: "job", job_id: "ui:one" }, { action: "cancel", job_id: "ui:one" }] as const) {
    await requestCigarVersions(input, { currentPassword: "unused-proof" });
    assert.deepEqual(JSON.parse(String(calls.at(-1)!.init?.body)), { input });
  }
  const input = { action: "commit", job_id: "ui:prepared", expected_generation: "9007199254740993", reconnect: true } as const;
  await requestCigarVersions(input, { currentPassword: "fixture-proof", totpCode: "123456" });
  const call = calls.at(-1)!;
  assert.equal(call.init?.method, "POST");
  assert.deepEqual(JSON.parse(String(call.init?.body)), { input, approval_password: "fixture-proof", approval_totp_code: "123456" });
  const prepared = { action: "prepare_switch", job_id: "ui:new", target_runtime_id: "cigar:target", expected_generation: "18446744073709551615" } as const;
  await requestCigarVersions(prepared);
  assert.deepEqual(JSON.parse(String(calls.at(-1)!.init?.body)), { input: prepared });
  const previous = calls.length;
  payload = { code: "native_context_assistance_switch_commit_outcome_unknown", message: "private-source-content" }; status = 503;
  await assert.rejects(requestCigarVersions(input), (e: unknown) => e instanceof ContextAssistanceApiError
    && e.code.endsWith("outcome_unknown") && e.message.includes("Refresh jobs") && !e.message.includes("private-source"));
  assert.equal(calls.length, previous + 1, "unknown mutation outcomes must not retry themselves");
  status = 409; payload = { code: "native_context_assistance_switch_selection_conflict" };
  await assert.rejects(requestCigarVersions(input), /settings changed/);
  status = 401; await assert.rejects(requestCigarVersions(input), /Reconnect to the local Guard session/);
  status = 404; await assert.rejects(requestCigarVersions({ action: "releases" }), /Update Guard/);
  status = 200; payload = { schema: "guard-cigar-versions-result.v1", result: { jobs: [] }, state: { ready: true } };
  await assert.rejects(requestCigarVersions({ action: "jobs" }), /incompatible status/);
  payload = { schema: "guard-cigar-versions-result.v1", result: [], state };
  await assert.rejects(requestCigarVersions({ action: "jobs" }), /incompatible CIGAR update data/);
} finally {
  globalThis.fetch = originalFetch;
  if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
  else Reflect.deleteProperty(globalThis, "window");
}
console.log("Authenticated CIGAR versions transport, explicit effects, proof separation and no-retry outcomes passed.");
