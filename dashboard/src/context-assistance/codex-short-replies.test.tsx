import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { ContextAssistanceApiError } from "./api";
import { CodexShortReplies } from "./codex-short-replies";
import { readCodexShortReplies, setCodexShortReplies } from "./codex-short-replies-api";

const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
const originalFetch = globalThis.fetch;
const storage = new Map<string, string>();
const browserStorage = { getItem: (key: string) => storage.get(key) ?? null, setItem: (key: string, value: string) => { storage.set(key, value); } };
Object.defineProperty(globalThis, "window", { configurable: true, value: {
  location: new URL("http://127.0.0.1:4781/guard/cigar?guard-token=short-replies-test-session"),
  sessionStorage: browserStorage, localStorage: browserStorage,
} });
const calls: Array<{ url: string; init?: RequestInit }> = [];
let payload: unknown = { schema: "guard-codex-short-replies.v1", state: "on", text: "Keep your own words short.", config_path: "/h/.codex/config.toml" };
let status = 200;
globalThis.fetch = async (input, init) => {
  calls.push({ url: String(input), init });
  return new Response(JSON.stringify(payload), { status, headers: { "Content-Type": "application/json" } });
};
try {
  assert.deepEqual(await readCodexShortReplies(), { state: "on" });
  assert.equal(calls[0].url, "http://127.0.0.1:4781/v1/context-assistance/codex-short-replies");
  assert.equal(calls[0].init?.method, "GET");

  payload = { state: "off" };
  assert.deepEqual(await setCodexShortReplies(false, { currentPassword: "pw", totpCode: "123456" }), { state: "off" });
  assert.deepEqual(JSON.parse(String(calls[1].init?.body)), { enabled: false, approval_password: "pw", approval_totp_code: "123456" });
  payload = { state: "on" };
  await setCodexShortReplies(true);
  assert.deepEqual(JSON.parse(String(calls[2].init?.body)), { enabled: true }, "no proof fields are sent without a proof");

  for (const state of ["not_set", "yours"]) {
    payload = { state };
    assert.deepEqual(await readCodexShortReplies(), { state });
  }

  status = 403;
  payload = { error: "approval_gate_proof_required" };
  await assert.rejects(setCodexShortReplies(true), (error: unknown) => error instanceof ContextAssistanceApiError
    && error.code === "approval_gate_proof_required" && error.message === "Guard needs your approval before this change.");
  status = 409;
  payload = { error: "codex_short_replies_unavailable", code: "codex_config_unreadable" };
  await assert.rejects(setCodexShortReplies(true), /could not read your Codex config/);
  status = 500;
  payload = { error: "internal" };
  await assert.rejects(readCodexShortReplies(), /could not check your Codex config/);
  await assert.rejects(setCodexShortReplies(false), /could not change your Codex config\. Nothing was changed/);
  status = 200;
  payload = { state: "maybe" };
  await assert.rejects(readCodexShortReplies(), /does not understand/);

  // Until the config read answers, the page cannot say whether it is on, so it shows nothing.
  assert.equal(renderToStaticMarkup(<CodexShortReplies gate={null} disabled={false} cigarOn />), "");
} finally {
  globalThis.fetch = originalFetch;
  if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
  else Reflect.deleteProperty(globalThis, "window");
}
