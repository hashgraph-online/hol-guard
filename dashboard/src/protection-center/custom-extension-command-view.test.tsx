import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import type { LocalCliCommand } from "../local-cli-api";
import { CustomExtensionCommandBrowser } from "./custom-extension-command-browser";
import {
  commandGroupKey,
  commandMatchesFilter,
  commandMatchesQuery,
  commandNamePrefix,
  commandRowUsageFor,
  groupCommands,
  groupStateSummary,
  savedStateMap,
  sortCommands,
  stateFilterCounts,
} from "./custom-extension-command-view";

function script(name: string, state: LocalCliCommand["state"] = "inherit", description = `node ${name}.mjs`): LocalCliCommand {
  return { command_id: `script.${name}`, name, usage: `bun run ${name}`, description, parent_id: null, state };
}

const commands = [
  { command_id: "root", name: "bun run", usage: "bun run", description: "Run bun run without a subcommand.", parent_id: null, state: "inherit" as const },
  script("build", "allow"),
  script("android:pixel", "allow", "tsx scripts/run-android-pixel-live.ts"),
  script("cap:android"),
  script("android:emu", "block"),
  script("test10"),
  script("test2"),
];

// Query terms all have to match, across name, usage and the script body.
assert.equal(commandMatchesQuery(commands[2]!, "android pixel"), true);
assert.equal(commandMatchesQuery(commands[2]!, "run-android-pixel"), true);
assert.equal(commandMatchesQuery(commands[2]!, "android emu"), false);
assert.equal(commandMatchesQuery(commands[2]!, "   "), true);

// "Unsaved" compares the draft with the saved catalog, not the default.
const saved = savedStateMap(commands.map((command) => ({ ...command, state: command.command_id === "script.build" ? "inherit" : command.state })));
assert.equal(commandMatchesFilter(commands[1]!, "changed", saved), true);
assert.equal(commandMatchesFilter(commands[2]!, "changed", saved), false);
assert.equal(commandMatchesFilter(commands[4]!, "block", saved), true);
assert.deepEqual(stateFilterCounts(commands, saved), { all: 7, changed: 1, inherit: 4, allow: 2, review: 0, block: 1 });

// Names sort naturally, and the setting sort puts blocked first.
assert.deepEqual(sortCommands(commands, "name").map((command) => command.name).slice(-2), ["test2", "test10"]);
assert.equal(sortCommands(commands, "state")[0]!.name, "android:emu");
assert.deepEqual(sortCommands(commands, "catalog"), commands);

// Families follow the prefix; root rows and MCP tools never group.
assert.equal(commandGroupKey(commands[0]!, "package-scripts"), "id:root");
assert.equal(commandGroupKey(commands[1]!, "package-scripts"), "name:build");
assert.equal(commandGroupKey(script("build:web"), "package-scripts"), "name:build");
assert.equal(commandGroupKey(commands[2]!, "mcp"), "id:script.android:pixel");
assert.equal(commandGroupKey({ ...script("deploy"), parent_id: "cli.release.deploy" }, "cli"), "id:cli");
const groups = groupCommands(commands, "package-scripts");
assert.deepEqual(groups.map((group) => [group.label, group.commands.length]), [
  ["bun run", 1], ["build", 1], ["android", 2], ["cap", 1], ["test10", 1], ["test2", 1],
]);
assert.equal(commandNamePrefix("android:pixel", "android"), "android:");
assert.equal(commandNamePrefix("androidx", "android"), "");
assert.equal(groupStateSummary(groups[2]!.commands), "1 allowed · 1 blocked");
assert.equal(groupStateSummary([script("a"), script("b")]), "All Recommended");
assert.equal(groupStateSummary([script("a", "allow"), script("b")]), "1 allowed · 1 Recommended");

// Package script usage repeats the runner; CLI usage stays.
assert.equal(commandRowUsageFor(commands[1]!, "package-scripts"), null);
assert.equal(commandRowUsageFor(commands[1]!, "cli"), "bun run build");

const render = (list: readonly LocalCliCommand[]) => renderToStaticMarkup(createElement(CustomExtensionCommandBrowser, {
  commands: list,
  savedCommands: list,
  surface: "package-scripts",
  disabled: false,
  bulkEligible: (command: LocalCliCommand) => command.command_id !== "root",
  bulkGroupLabel: "All scripts protection setting",
  bulkMixedCopy: "Custom mix.",
  onChange: () => undefined,
  onBulkChange: () => undefined,
}));

const small = render(commands);
assert.match(small, /Find a script/);
assert.match(small, /package\.json order/);
assert.match(small, /aria-label="android scripts"/);
assert.match(small, /aria-label="android family protection setting"/);
assert.match(small, /aria-label="android:pixel protection setting"/);
assert.match(small, /Collapse all/);
assert.doesNotMatch(small, /Unsaved/);
assert.doesNotMatch(small, /bun run build</);

// Long catalogs start with families collapsed so the page opens as a short index.
const long = render([
  ...commands,
  ...Array.from({ length: 40 }, (_, index) => script(`lint:part${index}`)),
]);
assert.match(long, /Expand all/);
assert.match(long, /40 scripts · All Recommended/);
assert.doesNotMatch(long, /lint:part0 protection setting/);
assert.match(long, /aria-label="lint family protection setting"/);

assert.match(render([]), /Guard has not loaded scripts/);

console.log("custom-extension-command-view.test.tsx: all assertions passed");
