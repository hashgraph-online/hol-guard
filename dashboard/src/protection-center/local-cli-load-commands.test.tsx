import assert from "node:assert/strict";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { DiscoveryFailure } from "../discovery-failure";
import { LocalCliApiError, normalizeLocalCliItem } from "../local-cli-api";
import {
  LocalCliLoadCommands,
  PATH_ENTRY_CODES,
  enteredToolPath,
  loadCommandsFailureMessage,
  loadsAsScript,
  recordedToolPath,
} from "./local-cli-load-commands";
import { DISCOVERY_WAIT_MS, discoveryPollDelay } from "../discovery-job-wait";

const raw = {
  cli_id: "local-cli.lanectl-abcdef12",
  name: "lanectl",
  kind: "executable",
  identity_hash: "a".repeat(64),
  example_label: "lanectl",
  interpreter_name: null,
  observed_count: 2,
  last_seen_at: "2026-10-17T00:00:00Z",
  surface: "cli",
  state: "allowed",
  stale: false,
  grant_revision: 1,
  authority_revision: 1,
  suggestable: false,
  commands: [],
};
const render = (value: Record<string, unknown>, disabled = false) => renderToStaticMarkup(createElement(LocalCliLoadCommands, {
  item: normalizeLocalCliItem(value), disabled, onLoaded: async () => true,
}));

// A program offers one action and says what Guard will run before it runs it.
const empty = render(raw);
assert.match(empty, />Load commands</);
assert.match(empty, /lanectl --help/);
assert.match(empty, /empty temporary folder/);
assert.match(empty, /load commands only for tools you trust/);
assert.match(empty, /never changes a choice you already made/);
assert.doesNotMatch(empty, /role="alert"/);

// With commands already listed, the action checks for new ones.
const listed = render({ ...raw, commands: [{ command_id: "deploy", name: "deploy", usage: "lanectl deploy", description: "", state: "allow" }] });
assert.match(listed, />Check for new commands</);

// Guard's own root and other entries are not listed commands.
const synthetic = render({ ...raw, commands: ["root", "other"].map((id) => ({ command_id: id, name: id, usage: id, description: "", state: "inherit" })) });
assert.match(synthetic, />Load commands</);

// The action follows the panel's busy state.
assert.match(render(raw, true), /<button[^>]*disabled=""/);

// A script loads from the file Guard saw it run: the daemon finds it, so the
// page never asks for a path up front.
for (const scriptLike of [{ ...raw, kind: "script" }, { ...raw, name: "approve-merge.sh" }, { ...raw, name: "release.PY" }]) {
  const script = render(scriptLike);
  assert.doesNotMatch(script, /does not record where/);
  assert.doesNotMatch(script, /Full path to /);
  assert.doesNotMatch(script, /<input/);
  assert.match(script, /load commands only for scripts you trust/);
  assert.match(script, /<button[^>]*>Load commands</);
  assert.doesNotMatch(script, /<button[^>]*disabled=""[^>]*>Load commands</);
  assert.doesNotMatch(script, /disabled:cursor-wait/);
  assert.doesNotMatch(script, /Add custom extension/);
}
assert.equal(loadsAsScript({ kind: "executable", name: "lanectl" }), false);
assert.equal(loadsAsScript({ kind: "executable", name: "pr-approve-merge.sh" }), true);
assert.equal(loadsAsScript({ kind: "executable", name: "-lanectl" }), true);
assert.equal(loadsAsScript({ kind: "script", name: "lanectl" }), true);
assert.doesNotMatch(empty, /Full path to/);

// The file the hook recorded is what Guard runs, and the page says so.
const launched = render({ ...raw, name: "pr-approve-merge.sh", source_path: "/opt/tools/pr-approve-merge.sh" });
assert.match(launched, /\/opt\/tools\/pr-approve-merge.sh --help/);
assert.doesNotMatch(launched, /<input/);
assert.equal(recordedToolPath({ source_path: "/opt/tools/approve-merge.sh" }), "/opt/tools/approve-merge.sh");
assert.equal(recordedToolPath({ source_path: "~/bin/approve-merge.sh" }), "~/bin/approve-merge.sh");
assert.equal(recordedToolPath({ source_path: "C:\\tools\\approve-merge.ps1" }), "C:\\tools\\approve-merge.ps1");
// An older record holds only a class, which names no file.
for (const recorded of ["user-tool", "approve-merge.sh", "", null]) {
  assert.equal(recordedToolPath({ source_path: recorded }), "", String(recorded));
}
assert.match(render({ ...raw, name: "approve-merge.sh", source_path: "user-tool" }), /approve-merge.sh --help/);

// A path copied from a shell keeps its quotes; Guard sends the path alone.
assert.equal(enteredToolPath("  '/opt/my tools/approve-merge.sh' "), "/opt/my tools/approve-merge.sh");
assert.equal(enteredToolPath('"/opt/tools/approve-merge.sh"'), "/opt/tools/approve-merge.sh");
assert.equal(enteredToolPath("/opt/tools/it's.sh"), "/opt/tools/it's.sh");
assert.equal(enteredToolPath("'/opt/tools/a.sh\""), "'/opt/tools/a.sh\"");
assert.equal(enteredToolPath("   "), "");

// A --help probe usually finishes in well under half a second, so the first
// progress checks come quickly instead of after a fixed half-second wait.
assert.equal(discoveryPollDelay(0), 100);
assert.ok(discoveryPollDelay(0) + discoveryPollDelay(1) < 500);
assert.equal(discoveryPollDelay(3), 500);
assert.equal(discoveryPollDelay(119), 500);
// The quick first checks do not shorten the wait: a long scan still gets the
// whole minute before the page gives up on it.
let waited = 0;
for (let poll = 0; waited < DISCOVERY_WAIT_MS; poll += 1) waited += discoveryPollDelay(poll);
assert.equal(DISCOVERY_WAIT_MS, 60_000);
assert.equal(waited, DISCOVERY_WAIT_MS);

// Shared job failures that name connectors get tool wording; others pass through.
assert.match(loadCommandsFailureMessage(new DiscoveryFailure("catalog_limit_reached", "connector text")), /lists more commands than Guard can keep/);
assert.match(loadCommandsFailureMessage(new DiscoveryFailure("discovery_failed", "connector text")), /Loading stopped/);
assert.equal(loadCommandsFailureMessage(new DiscoveryFailure("cli_help_unreadable", "help text")), "help text");
assert.equal(loadCommandsFailureMessage(new LocalCliApiError("cli_identity_changed", "not the program Guard recorded")), "not the program Guard recorded");
assert.match(loadCommandsFailureMessage(new TypeError("Failed to fetch")), /Try again/);

// Every failure of the daemon's own PATH lookup offers the full path next: it
// can miss the tool, or find another program of that name. The daemon checks
// the identity of whatever the path resolves to before it probes anything.
for (const code of ["cli_not_on_guard_path", "cli_identity_changed", "cli_reload_needs_path"]) {
  assert.ok(PATH_ENTRY_CODES.has(code), code);
}
// A path the operator mistyped, or a tool that is really gone, is not one.
for (const code of ["cli_path_invalid", "cli_path_not_found", "cli_help_unreadable"]) {
  assert.ok(!PATH_ENTRY_CODES.has(code), code);
}
