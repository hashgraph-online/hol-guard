import assert from "node:assert/strict";
import test from "node:test";
import { blockedPaths, goalOf, parseCommand, SECRET_PATHS, workText } from "./work";

const installed = ["codex", "claude-code"];
test("takes the program and a model", () => {
  assert.deepEqual(parseCommand("codex", installed), { harness: "codex", model: null });
  assert.deepEqual(parseCommand(" claude --model sonnet ", installed), { harness: "claude-code", model: "sonnet" });
  assert.deepEqual(parseCommand("/opt/bin/codex -m gpt-5", installed), { harness: "codex", model: "gpt-5" });
  assert.deepEqual(parseCommand("codex --model=o4", installed), { harness: "codex", model: "o4" });
});
test("refuses other programs, flags that change safety, and missing CLIs", () => {
  assert.ok("error" in parseCommand("bash", installed));
  assert.ok("error" in parseCommand("codex --dangerously-bypass-approvals-and-sandbox", installed));
  assert.ok("error" in parseCommand("claude --dangerously-skip-permissions", installed));
  assert.ok("error" in parseCommand("codex --model", installed));
  assert.ok("error" in parseCommand("codex --model --yolo", installed));
  assert.ok("error" in parseCommand("claude", ["codex"]));
  assert.ok("error" in parseCommand("  ", installed));
});
test("keeps project paths and refuses ones that leave the project", () => {
  assert.deepEqual(blockedPaths("private/\n./notes, private/", false), { paths: ["private/", "notes"], bad: [] });
  assert.equal(blockedPaths("/etc\n../up\na/../b\n~/x\na b\na)b", false).bad.length, 6);
  // "./" is the whole project, not a folder limit: report it instead of dropping it.
  assert.deepEqual(blockedPaths("./\n././", false), { paths: [], bad: ["./", "././"] });
});
test("adds secret files when asked", () => {
  assert.deepEqual(blockedPaths("", true).paths, SECRET_PATHS);
});
test("puts the goal first and lists only what was given", () => {
  const text = workText({ goal: "Fix login", scope: "src/auth", done: "tests pass", avoid: "" }, ["private"]);
  assert.equal(text, "Goal: Fix login\nFiles in scope: src/auth\nDone when: tests pass\nYou cannot open these paths, so do not try: private");
  assert.equal(goalOf(text), "Fix login");
  assert.equal(goalOf("plain task\nmore"), "plain task");
  assert.equal(goalOf(null), null);
});
