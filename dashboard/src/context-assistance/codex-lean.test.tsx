import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { ContextAssistanceApiError } from "./api";
import { CodexLeanSessions } from "./codex-lean";
import { readCodexLean, removeCodexLean } from "./codex-lean-api";

const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
const originalFetch = globalThis.fetch;
const storage = new Map<string, string>();
const browserStorage = { getItem: (key: string) => storage.get(key) ?? null, setItem: (key: string, value: string) => { storage.set(key, value); } };
Object.defineProperty(globalThis, "window", { configurable: true, value: {
  location: new URL("http://127.0.0.1:4781/guard/cigar?guard-token=lean-test-session"),
  sessionStorage: browserStorage, localStorage: browserStorage,
} });
const calls: Array<{ url: string; init?: RequestInit }> = [];
let payload: unknown = { schema: "guard-codex-lean-sessions.v1", state: "off", limit: null, config_path: "/h/.codex/config.toml" };
let status = 200;
globalThis.fetch = async (input, init) => {
  calls.push({ url: String(input), init });
  return new Response(JSON.stringify(payload), { status, headers: { "Content-Type": "application/json" } });
};
try {
  assert.deepEqual(await readCodexLean(), { state: "off", limit: null });
  assert.equal(calls[0].url, "http://127.0.0.1:4781/v1/context-assistance/codex-lean");
  assert.equal(calls[0].init?.method, "GET");

  assert.deepEqual(await removeCodexLean({ currentPassword: "pw", totpCode: "123456" }), { state: "off", limit: null });
  assert.deepEqual(JSON.parse(String(calls[1].init?.body)), { enabled: false, approval_password: "pw", approval_totp_code: "123456" },
    "the page can only remove a size, never set one");
  await removeCodexLean();
  assert.deepEqual(JSON.parse(String(calls[2].init?.body)), { enabled: false }, "no proof fields are sent without a proof");

  status = 403;
  payload = { error: "approval_gate_proof_required", message: "Approve this change." };
  await assert.rejects(removeCodexLean(), (error: unknown) => error instanceof ContextAssistanceApiError
    && error.code === "approval_gate_proof_required" && error.message === "Guard needs your approval before this change.");
  status = 409;
  payload = { error: "codex_lean_unavailable", code: "codex_config_unreadable" };
  await assert.rejects(removeCodexLean(), /could not read your Codex config/);
  status = 500;
  payload = { error: "internal" };
  await assert.rejects(readCodexLean(), /could not check your Codex config/, "a failed read does not talk about a change");
  await assert.rejects(removeCodexLean(), /could not change your Codex config\. Nothing was changed/);
  status = 200;
  payload = { state: "maybe", limit: null };
  await assert.rejects(readCodexLean(), /does not understand/);

  // Before the config read answers there is nothing to remove, so the page shows nothing:
  // no switch that turns a smaller chat on.
  const markup = renderToStaticMarkup(<CodexLeanSessions gate={null} disabled={false} />);
  assert.equal(markup, "");
} finally {
  globalThis.fetch = originalFetch;
  if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
  else Reflect.deleteProperty(globalThis, "window");
}
