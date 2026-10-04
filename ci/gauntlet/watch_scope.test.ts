import { expect, test } from "bun:test";
import { permittedWatchInput, WATCH_COMMAND } from "./watch_scope";

test("Watch scope allows only the fixed harmless bash command", () => {
  expect(permittedWatchInput("bash", { command: WATCH_COMMAND })).toBe(true);
  expect(permittedWatchInput("bash", { command: WATCH_COMMAND, timeout: 120 })).toBe(true);
  expect(permittedWatchInput("bash", { command: WATCH_COMMAND, cwd: "/fixture" }, "/fixture")).toBe(true);
  for (const input of [null, [], { command: "echo substitute" },
    { command: WATCH_COMMAND, cwd: "/tmp" }, { command: WATCH_COMMAND, env: {} },
    { command: WATCH_COMMAND, timeout: 121 }, { command: WATCH_COMMAND, timeout: NaN }]) {
    expect(permittedWatchInput("bash", input)).toBe(false);
  }
  expect(permittedWatchInput("read", { command: WATCH_COMMAND })).toBe(false);
});
