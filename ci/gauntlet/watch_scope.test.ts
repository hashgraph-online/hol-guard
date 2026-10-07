import { expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, realpathSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { permittedWatchInput, WATCH_COMMAND } from "./watch_scope";

test("Watch scope allows only the fixed harmless bash command", () => {
  expect(permittedWatchInput("bash", { command: WATCH_COMMAND })).toBe(true);
  expect(permittedWatchInput("bash", { command: WATCH_COMMAND, timeout: 120 })).toBe(true);
  expect(permittedWatchInput("bash", { command: WATCH_COMMAND, timeout: 0 })).toBe(true);
  expect(permittedWatchInput("bash", { command: WATCH_COMMAND, cwd: "/fixture" }, "/fixture")).toBe(true);
  for (const input of [null, [], { command: "echo substitute" },
    { command: WATCH_COMMAND, cwd: "/tmp" },
    { command: WATCH_COMMAND, timeout: -1 },
    { command: WATCH_COMMAND, timeout: 121 }, { command: WATCH_COMMAND, timeout: NaN }]) {
    expect(permittedWatchInput("bash", input)).toBe(false);
  }
  expect(permittedWatchInput("read", { command: WATCH_COMMAND })).toBe(false);
});

test("Watch scope accepts inert bash defaults without allowing execution overrides", () => {
  expect(permittedWatchInput("bash", {
    command: WATCH_COMMAND, timeout: 30, cwd: "/fixture", env: {}, pty: false, async: false,
  }, "/fixture")).toBe(true);
  for (const overrides of [
    { env: { PYTHONPATH: "/other" } }, { env: [] }, { env: null },
    { pty: true }, { pty: 0 }, { async: true }, { async: 0 }, { unknown: false },
  ]) {
    expect(permittedWatchInput("bash", { command: WATCH_COMMAND, ...overrides })).toBe(false);
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
    expect(permittedWatchInput("bash", { command: WATCH_COMMAND, cwd: workspace }, realpathSync(workspace))).toBe(true);
    expect(permittedWatchInput("bash", { command: WATCH_COMMAND, cwd: alias }, workspace)).toBe(false);
    rmSync(alias);
    symlinkSync(sibling, alias);
    expect(permittedWatchInput("bash", { command: WATCH_COMMAND, cwd: alias }, workspace)).toBe(false);
    expect(permittedWatchInput("bash", { command: WATCH_COMMAND, cwd: sibling }, workspace)).toBe(false);
    expect(permittedWatchInput("bash", { command: WATCH_COMMAND, cwd: join(root, "missing") }, workspace)).toBe(false);
    expect(permittedWatchInput("bash", { command: "echo substituted", cwd: alias }, workspace)).toBe(false);
  } finally {
    rmSync(root, { recursive: true });
  }
});
