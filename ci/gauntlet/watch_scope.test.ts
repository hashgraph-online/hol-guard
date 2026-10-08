import { expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, realpathSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { permittedWatchInput, WATCH_COMMAND } from "./watch_scope";

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
  for (const overrides of [
    { env: { PYTHONPATH: "/other" } }, { env: [] }, { env: null },
    { pty: true }, { pty: 0 }, { pty: "false" },
    { async: true }, { async: 0 }, { async: "false" },
    { unknown: false }, { stdin: "print('substituted')" },
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
