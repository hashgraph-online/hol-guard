import { expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, realpathSync, symlinkSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cwdSpelling, permittedWatchInput, WATCH_COMMAND } from "./watch_scope";

test("Watch scope allows only the fixed harmless bash command", () => {
  expect(permittedWatchInput("bash", { command: WATCH_COMMAND, timeout: 1 })).toBe(true);
  expect(permittedWatchInput("bash", { command: WATCH_COMMAND, timeout: 120 })).toBe(true);
  for (const input of [null, [], { command: "echo substitute", timeout: 120 },
    { command: WATCH_COMMAND, timeout: 120, cwd: "/tmp" },
    { command: WATCH_COMMAND }, { command: WATCH_COMMAND, timeout: 0 },
    { command: WATCH_COMMAND, timeout: -1 }, { command: WATCH_COMMAND, timeout: Infinity },
    { command: WATCH_COMMAND, timeout: 121 }, { command: WATCH_COMMAND, timeout: 3600 },
    { command: WATCH_COMMAND, timeout: NaN }]) {
    expect(permittedWatchInput("bash", input)).toBe(false);
  }
  expect(permittedWatchInput("read", { command: WATCH_COMMAND, timeout: 120 })).toBe(false);
});

test("Watch scope accepts inert bash defaults without allowing execution overrides", () => {
  expect(permittedWatchInput("bash", {
    command: WATCH_COMMAND, timeout: 30, cwd: "/fixture", env: {}, pty: false, async: false,
  }, "/fixture")).toBe(true);
  expect(permittedWatchInput("bash", {
    i: "Running requested fixture command", command: WATCH_COMMAND, timeout: 120, pty: false, async: false,
  })).toBe(true);
  expect(permittedWatchInput("bash", { intent: "Run fixture", command: WATCH_COMMAND, timeout: 120 })).toBe(true);
  for (const overrides of [
    { env: { PYTHONPATH: "/other" } }, { env: [] }, { env: null },
    { pty: true }, { pty: 0 }, { pty: "false" },
    { async: true }, { async: 0 }, { async: "false" },
    { unknown: false }, { stdin: "print('substituted')" },
    { i: 1 }, { i: { command: "echo substituted" } }, { intent: ["label"] },
  ]) {
    expect(permittedWatchInput("bash", { command: WATCH_COMMAND, timeout: 120, ...overrides })).toBe(false);
  }
});

test("Watch scope accepts 18.4.12's inert service-mode defaults but nothing that acts", () => {
  // The exact live shape: materialized defaults that OMP itself normalizes away.
  expect(permittedWatchInput("bash", {
    i: "Run the fixture", command: WATCH_COMMAND, timeout: 120,
    cwd: "", pty: false, async: false, name: "",
    ready: { log: "", port: 0, host: "", timeout: 0 },
  })).toBe(true);
  expect(permittedWatchInput("bash", { command: WATCH_COMMAND, timeout: 120, name: "", ready: {} })).toBe(true);
  expect(permittedWatchInput("bash", { command: WATCH_COMMAND, timeout: 120, ready: { log: "", host: "" } })).toBe(true);
  for (const overrides of [
    { name: "watcher" }, { name: 0 }, { name: " " },
    { ready: "ready" }, { ready: [] },
    { ready: { port: 8080 } }, { ready: { log: "listening" } }, { ready: { host: "127.0.0.1" } },
    { ready: { timeout: 30 } }, { ready: { extra: "" } },
    { name: "", ready: { port: 8080 } },
    { cwd: "/tmp" }, { cwd: " " }, { cwd: 0 },
    { shell: "/bin/sh" }, { ready2: {} },
  ]) {
    expect(permittedWatchInput("bash", { command: WATCH_COMMAND, timeout: 120, ...overrides })).toBe(false);
  }
});

test("Watch scope accepts system-root aliases but rejects mutable directory symlinks", () => {
  const root = mkdtempSync(join(tmpdir(), "guard-watch-scope-"));
  try {
    const workspace = join(root, "workspace");
    const sibling = join(root, "sibling");
    const alias = join(root, "alias");
    mkdirSync(workspace);
    mkdirSync(sibling);
    symlinkSync(workspace, alias);
    expect(permittedWatchInput("bash", { command: WATCH_COMMAND, timeout: 120, cwd: workspace }, realpathSync(workspace))).toBe(true);
    expect(permittedWatchInput("bash", { command: WATCH_COMMAND, timeout: 120, cwd: alias }, workspace)).toBe(false);
    rmSync(alias);
    symlinkSync(sibling, alias);
    expect(permittedWatchInput("bash", { command: WATCH_COMMAND, timeout: 120, cwd: alias }, workspace)).toBe(false);
    expect(permittedWatchInput("bash", { command: WATCH_COMMAND, timeout: 120, cwd: sibling }, workspace)).toBe(false);
    expect(permittedWatchInput("bash", { command: WATCH_COMMAND, timeout: 120, cwd: join(root, "missing") }, workspace)).toBe(false);
    expect(permittedWatchInput("bash", { command: "echo substituted", timeout: 120, cwd: alias }, workspace)).toBe(false);
  } finally {
    rmSync(root, { recursive: true });
  }
});

// Optional proof against the real pinned SDK: the per-case agent config must
// switch the bash schema back to the non-service variant (no name/ready).
test.skipIf(!process.env.GUARD_GAUNTLET_SDK_ROOT)("Gauntlet agent config keeps the bash schema's service fields out", async () => {
  const root = process.env.GUARD_GAUNTLET_SDK_ROOT!;
  const load = (name: string) => import(Bun.resolveSync(name, root));
  const { Settings } = await load("@oh-my-pi/pi-coding-agent");
  const { BashTool } = await load("@oh-my-pi/pi-coding-agent/tools/bash");
  const dir = mkdtempSync(join(tmpdir(), "guard-agent-config-"));
  try {
    // The same config.yml write_agent_configuration emits into the case's agent dir.
    writeFileSync(join(dir, "config.yml"), JSON.stringify({ launch: { enabled: false } }));
    const disabled = await Settings.loadReadOnly({ agentDir: dir, cwd: dir });
    const expression = (settings: unknown) =>
      (new BashTool({ settings } as ConstructorParameters<typeof BashTool>[0]).parameters as { expression: string })
        .expression;
    // Control: the SDK default is launch.enabled=true, so the service schema appears.
    expect(expression(Settings.isolated())).toContain("ready?");
    const schema = expression(disabled);
    expect(schema).not.toContain("name?");
    expect(schema).not.toContain("ready?");
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test("Watch scope spells Windows directories by platform rules only", () => {
  const workspace = "C:\\Users\\tester\\work\\workspace";
  for (const spelling of ["C:/Users/tester/work/workspace", "c:\\Users\\tester\\work\\workspace", "C:\\Users\\tester\\work\\.\\workspace"]) {
    expect(cwdSpelling(spelling, "win32")).toBe(cwdSpelling(workspace, "win32"));
  }
  expect(cwdSpelling("C:/Users/tester/work/sibling", "win32")).not.toBe(cwdSpelling(workspace, "win32"));
  expect(cwdSpelling("C:/Users/tester/work/workspace", "darwin")).not.toBe(cwdSpelling(workspace, "darwin"));
  expect(cwdSpelling("/private/tmp/fixture", "darwin")).toBe("/tmp/fixture");
});
