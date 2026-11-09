import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ProtectionModuleDetail } from "./protection-module-detail";
import { extensionRunScope } from "./extension-run-scope";
import { PROTECTION_AUTHORITY_FIXTURES, protectionModuleFixture } from "./fixtures/protection-fixtures";

const PLAIN_TERMS = /token|gateway|endpoint|harness|posture|receipt|agent/i;
const RUNNABLE_IN_CLOUD = /(ready|available|enabled|runs?|can run) (in|on|through) Guard Cloud|Cloud actions:? (on|ready|available|enabled)/i;

for (const state of ["allowed", "blocked", "partial", "required", "lockdown"] as const) {
  for (const cloudPolicy of [false, true]) {
    const copy = extensionRunScope(cloudPolicy, state);
    assert.equal(copy.cloud, "Not turned on from this computer.", `${state}/${cloudPolicy} never claims Cloud actions`);
    const all = [copy.here, copy.cloud, ...copy.notes].join(" ");
    assert.doesNotMatch(all, RUNNABLE_IN_CLOUD, `${state}/${cloudPolicy} copy never implies Guard Cloud may run it`);
    assert.doesNotMatch(all, PLAIN_TERMS, `${state}/${cloudPolicy} copy stays in plain terms`);
    assert.match(all, /verified or paid listing does not do that/, "paid or verified listings grant nothing");
  }
}
assert.match(extensionRunScope(false, "allowed").here, /^On\./);
assert.equal(extensionRunScope(false, "blocked").here, "Blocked. Matching actions stay blocked here.");
assert.doesNotMatch(extensionRunScope(true, "blocked").here, /\bOff\b/, "blocked Permissions never read as the Extension being off");
assert.equal(extensionRunScope(false, "allowed").notes.length, 1);
assert.match(
  extensionRunScope(true, "allowed").notes.join(" "),
  /does not let Guard Cloud run anything/,
  "Policy from Guard Cloud is not presented as Cloud actions",
);

function render(
  extension: ReturnType<typeof protectionModuleFixture>,
  effective = PROTECTION_AUTHORITY_FIXTURES.protected,
): string {
  return renderToStaticMarkup(createElement(ProtectionModuleDetail, {
    extension,
    effective,
    catalogDigest: "a".repeat(64),
    onBack: () => undefined,
    onRefresh: () => undefined,
  }));
}

// A verified remote MCP Extension from the Guard Cloud catalog still reads as not turned on for Guard Cloud,
// and its catalog source alone does not claim a workspace Policy controls it.
const hosted = render(protectionModuleFixture({
  extension_id: "mcp.example-remote",
  name: "Example remote tools",
  source: "signed-cloud",
  trust_class: "first-party",
  publisher: { id: "example", displayName: "Example (verified)" },
}));
assert.match(hosted, /Where it runs/);
assert.match(hosted, /Not turned on from this computer\./);
assert.doesNotMatch(hosted, /does not let Guard Cloud run anything/);
assert.doesNotMatch(hosted.replace(/<[^>]+>/g, " "), RUNNABLE_IN_CLOUD);

const git = protectionModuleFixture({ extension_id: "command.git", name: "Git", source: "built-in" });
const local = render(git);
assert.match(local, /Where it runs/);
assert.doesNotMatch(local, /does not let Guard Cloud run anything/);

// A built-in Extension whose settings a Guard Cloud Policy sets shows the Policy note, and still no Cloud actions.
const managed = render(git, PROTECTION_AUTHORITY_FIXTURES.managedBlock);
assert.match(managed, /Guard Cloud workspace(&#x27;|')s Policy sets some of its settings here/);
assert.match(managed, /does not let Guard Cloud run anything/);
assert.match(managed, /Not turned on from this computer\./);
assert.doesNotMatch(managed.replace(/<[^>]+>/g, " "), RUNNABLE_IN_CLOUD);

console.log("extension-run-scope.test.tsx: all tests passed");
