import { afterAll, expect, test } from "bun:test";
// Bound before the observer loads, like a generated extension in a host that
// already imported node:child_process.
import { spawn } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "gauntlet-host-observer-"));
const log = join(root, "host.jsonl");
const guardLog = join(root, "guard.jsonl");
const priorLog = process.env.GUARD_GAUNTLET_HOST_OBSERVER_LOG;
const priorGuardLog = process.env.GUARD_GAUNTLET_OBSERVER_LOG;
const priorFetch = globalThis.fetch;
process.env.GUARD_GAUNTLET_HOST_OBSERVER_LOG = log;
process.env.GUARD_GAUNTLET_OBSERVER_LOG = guardLog;
const { default: install } = await import("./observer");

afterAll(() => {
  globalThis.fetch = priorFetch;
  if (priorLog === undefined) delete process.env.GUARD_GAUNTLET_HOST_OBSERVER_LOG;
  else process.env.GUARD_GAUNTLET_HOST_OBSERVER_LOG = priorLog;
  if (priorGuardLog === undefined) delete process.env.GUARD_GAUNTLET_OBSERVER_LOG;
  else process.env.GUARD_GAUNTLET_OBSERVER_LOG = priorGuardLog;
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
  expect(handlers.get("tool_call")!(start)).toBeUndefined();
  handlers.get("tool_execution_start")!({ type: "tool_execution_start", toolCallId: "eval", toolName: "eval" });
  expect(handlers.get("tool_call")!(start)).toBeUndefined();
  expect(handlers.get("tool_result")!(end)).toBeUndefined();
  const events = readFileSync(log, "utf8").trim().split("\n").map(line => JSON.parse(line));
  expect(events.slice(-2)).toEqual([
    { type: "eval_bridge_start", parentToolCallId: "eval", parentToolCallIds: ["eval"], event: start },
    { type: "eval_bridge_end", parentToolCallId: "eval", parentToolCallIds: ["eval"], event: end },
  ]);
  handlers.get("tool_execution_end")!({ type: "tool_execution_end", toolCallId: "eval", toolName: "eval" });
  expect(handlers.get("tool_result")!(end)).toBeUndefined();
});

test("overlapping eval calls are observed without changing execution", () => {
  const handlers = new Map<string, (event: Record<string, unknown>) => void>();
  install({ on: (name, callback) => { handlers.set(name, callback); } });
  for (const id of ["first", "second"]) {
    handlers.get("tool_execution_start")!({ type: "tool_execution_start", toolCallId: id, toolName: "eval" });
  }
  const start = { type: "tool_call", toolCallId: "js-read-overlap", toolName: "read", input: { path: "README.md" } };
  expect(handlers.get("tool_call")!(start)).toBeUndefined();
  const end = { type: "tool_result", toolCallId: start.toolCallId, toolName: "read", input: start.input,
    content: [], isError: false };
  expect(handlers.get("tool_result")!(end)).toBeUndefined();
  const events = readFileSync(log, "utf8").trim().split("\n").map(line => JSON.parse(line));
  expect(events.slice(-2).map(event => [event.parentToolCallId, event.parentToolCallIds])).toEqual([
    [null, ["first", "second"]], [null, ["first", "second"]],
  ]);
});

test("contained wrapper request bytes are captured beside the start event", () => {
  const handlers = new Map<string, (event: Record<string, unknown>) => void>();
  install({ on: (name, callback) => { handlers.set(name, callback); } });
  const folder = join(root, "dev's work", "hol-guard-contained-test-unit");
  mkdirSync(folder, { mode: 0o700, recursive: true });
  const request = join(folder, "request.json");
  writeFileSync(request, '{"schema":"guard-contained-test-request.v1"}', { mode: 0o600 });
  const wrapper = (file: string) => ["/venv/bin/hol-guard", "execute-contained-test", "--guard-home", "/g",
    "--workspace", "/w", "--request-file", file, "--request-sha256", "a".repeat(64), "--home", "/h"]
    .map(value => `'${value.replaceAll("'", "'\\''")}'`).join(" ");
  const start = (id: string, command: string) =>
    ({ type: "tool_execution_start", toolCallId: id, toolName: "bash", args: { command } });
  handlers.get("tool_execution_start")!(start("bound", wrapper(request)));
  chmodSync(request, 0o644);
  handlers.get("tool_execution_start")!(start("loose-mode", wrapper(request)));
  handlers.get("tool_execution_start")!(start("foreign", wrapper(join(root, "request.json"))));
  const events = readFileSync(log, "utf8").trim().split("\n").map(line => JSON.parse(line));
  expect(events.slice(-4)).toEqual([
    start("bound", wrapper(request)),
    { type: "contained_request_capture", toolCallId: "bound",
      request: Buffer.from('{"schema":"guard-contained-test-request.v1"}').toString("base64") },
    start("loose-mode", wrapper(request)),
    start("foreign", wrapper(join(root, "request.json"))),
  ]);
});

test("the Windows sink's request is captured without POSIX owner bits", () => {
  const handlers = new Map<string, (event: Record<string, unknown>) => void>();
  install({ on: (name, callback) => { handlers.set(name, callback); } });
  const folder = join(root, "hol-guard-contained-test-windows");
  mkdirSync(folder, { mode: 0o700, recursive: true });
  const request = join(folder, "request.json");
  writeFileSync(request, '{"schema":"guard-contained-test-request.v1"}', { mode: 0o644 });
  const bootstrap = "import sys;sys.path.insert(0, 'C:/g/lib');from codex_plugin_scanner.cli import main";
  const wrapper = (prefix: string[]) => [...prefix, "execute-contained-test", "--guard-home", "C:\\g",
    "--workspace", "C:\\w", "--request-file", request, "--request-sha256", "a".repeat(64), "--home", "C:\\h"]
    .map(value => `'${value.replaceAll("'", "'\\''")}'`).join(" ");
  const sink = wrapper(["C:\\g\\python.exe", "-I", "-c", bootstrap, "guard"]);
  const changed = wrapper(["C:\\g\\python.exe", "-c", bootstrap, "guard"]);
  const start = (id: string, command: string) =>
    ({ type: "tool_execution_start", toolCallId: id, toolName: "bash", args: { command } });
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "win32" });
  try {
    handlers.get("tool_execution_start")!(start("windows", sink));
    handlers.get("tool_execution_start")!(start("not-isolated", changed));
  } finally {
    Object.defineProperty(process, "platform", platform);
  }
  const events = readFileSync(log, "utf8").trim().split("\n").map(line => JSON.parse(line));
  expect(events.slice(-3)).toEqual([
    start("windows", sink),
    { type: "contained_request_capture", toolCallId: "windows",
      request: Buffer.from('{"schema":"guard-contained-test-request.v1"}').toString("base64") },
    start("not-isolated", changed),
  ]);
});

test("a bridge spawned through an import bound before the observer is observed and probed", async () => {
  const received = join(root, "bridge-stdin.json");
  const runtime = join(root, "runtime");
  writeFileSync(runtime, `#!/bin/sh\ncat > '${received}'\nprintf '%s\\n' '{"status":200,"body":"{\\"decision\\":\\"allow\\"}"}'\n`,
    { mode: 0o700 });
  const request = { hook_event_name: "PreToolUse", tool_name: "bash", tool_call_id: "call", tool_input: { command: "ls" } };
  const child = spawn(runtime, ["pi-hook-bridge", "{}"], { stdio: ["pipe", "pipe", "ignore"] });
  const closed = new Promise(resolve => child.once("close", resolve));
  child.stdin?.end(JSON.stringify(request) + "\n");
  expect(await closed).toBe(0);
  const forwarded = JSON.parse(readFileSync(received, "utf8"));
  const [row] = readFileSync(guardLog, "utf8").trim().split("\n").map(line => JSON.parse(line));
  expect(row).toMatchObject({
    transport: "pi-hook-bridge", event: "PreToolUse", tool: "bash", tool_call_id: "call",
    http_status: 200, decision: "allow", probe_request_id: forwarded.guard_transition_probe.request_id,
  });
  expect(forwarded.tool_input).toEqual(request.tool_input);
});
