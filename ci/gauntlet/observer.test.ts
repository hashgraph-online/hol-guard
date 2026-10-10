import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "gauntlet-host-observer-"));
const log = join(root, "host.jsonl");
const priorLog = process.env.GUARD_GAUNTLET_HOST_OBSERVER_LOG;
const priorFetch = globalThis.fetch;
process.env.GUARD_GAUNTLET_HOST_OBSERVER_LOG = log;
const { default: install } = await import("./observer");

afterAll(() => {
  globalThis.fetch = priorFetch;
  if (priorLog === undefined) delete process.env.GUARD_GAUNTLET_HOST_OBSERVER_LOG;
  else process.env.GUARD_GAUNTLET_HOST_OBSERVER_LOG = priorLog;
  rmSync(root, { recursive: true });
});

test("SDK model and tool events survive telemetry unchanged", () => {
  const handlers = new Map<string, (event: Record<string, unknown>) => void>();
  install({ on: (name, callback) => { handlers.set(name, callback); } });
  const events = [
    { type: "message_end", message: { role: "assistant", content: [
      { type: "toolCall", id: "child", name: "read", arguments: { path: "README.md" } },
    ] } },
    { type: "tool_execution_start", toolCallId: "child", toolName: "read", args: { path: "README.md" } },
    { type: "tool_execution_end", toolCallId: "child", toolName: "read", result: { content: [] }, isError: false },
  ];
  for (const event of events) expect(handlers.get(event.type)!(event)).toBeUndefined();
  handlers.get("message_end")!({ type: "message_end", message: { role: "user", content: "private prompt" } });
  expect(readFileSync(log, "utf8").trim().split("\n").map(line => JSON.parse(line))).toEqual(events);
});

test("eval bridge hooks retain actual arguments and the executing parent", () => {
  const handlers = new Map<string, (event: Record<string, unknown>) => void>();
  install({ on: (name, callback) => { handlers.set(name, callback); } });
  const start = { type: "tool_call", toolCallId: "js-read-123", toolName: "read", input: { path: "README.md" } };
  const end = { type: "tool_result", toolCallId: "js-read-123", toolName: "read", input: start.input,
    content: [{ type: "text", text: "inert fixture" }], isError: false };
  expect(() => handlers.get("tool_call")!(start)).toThrow("ambiguous eval bridge parent");
  handlers.get("tool_execution_start")!({ type: "tool_execution_start", toolCallId: "eval", toolName: "eval" });
  expect(handlers.get("tool_call")!(start)).toBeUndefined();
  expect(handlers.get("tool_result")!(end)).toBeUndefined();
  const events = readFileSync(log, "utf8").trim().split("\n").map(line => JSON.parse(line));
  expect(events.slice(-2)).toEqual([
    { type: "eval_bridge_start", parentToolCallId: "eval", event: start },
    { type: "eval_bridge_end", parentToolCallId: "eval", event: end },
  ]);
  handlers.get("tool_execution_end")!({ type: "tool_execution_end", toolCallId: "eval", toolName: "eval" });
  expect(() => handlers.get("tool_result")!(end)).toThrow("unbound eval bridge completion");
});
