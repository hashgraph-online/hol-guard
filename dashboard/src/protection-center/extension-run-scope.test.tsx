import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ProtectionModuleDetail } from "./protection-module-detail";
import { extensionRunScope } from "./extension-run-scope";
import { PROTECTION_AUTHORITY_FIXTURES, protectionModuleFixture } from "./fixtures/protection-fixtures";

const PLAIN_TERMS = /token|gateway|endpoint|harness|posture|receipt|agent/i;
const RUNNABLE_IN_CLOUD = /(ready|available|enabled|runs?|can run) (in|on|through) Guard Cloud|Cloud actions:? (on|ready|available|enabled)/i;

for (const state of ["allowed", "blocked", "partial", "required", "lockdown"] as const) {
  for (const source of ["built-in", "local-admin", "signed-cloud"] as const) {
    const copy = extensionRunScope({ source }, state);
    assert.equal(copy.cloud, "Not turned on from this computer.", `${state}/${source} never claims Cloud actions`);
    const all = [copy.here, copy.cloud, ...copy.notes].join(" ");
    assert.doesNotMatch(all, RUNNABLE_IN_CLOUD, `${state}/${source} copy never implies Guard Cloud may run it`);
    assert.doesNotMatch(all, PLAIN_TERMS, `${state}/${source} copy stays in plain terms`);
    assert.match(all, /verified or paid listing does not do that/, "paid or verified listings grant nothing");
  }
}
assert.match(extensionRunScope({ source: "built-in" }, "allowed").here, /^On\./);
assert.match(extensionRunScope({ source: "built-in" }, "blocked").here, /^Off\./);
assert.equal(extensionRunScope({ source: "built-in" }, "allowed").notes.length, 1);
assert.match(
  extensionRunScope({ source: "signed-cloud" }, "allowed").notes.join(" "),
  /does not let Guard Cloud run anything/,
  "Policy from Guard Cloud is not presented as Cloud actions",
);

function render(extension: ReturnType<typeof protectionModuleFixture>): string {
  return renderToStaticMarkup(createElement(ProtectionModuleDetail, {
    extension,
    effective: PROTECTION_AUTHORITY_FIXTURES.protected,
    catalogDigest: "a".repeat(64),
    onBack: () => undefined,
    onRefresh: () => undefined,
  }));
}

// A verified, cloud-synced, remote MCP Extension that is on here still reads as not turned on for Guard Cloud.
const hosted = render(protectionModuleFixture({
  extension_id: "mcp.example-remote",
  name: "Example remote tools",
  source: "signed-cloud",
  trust_class: "first-party",
  publisher: { id: "example", displayName: "Example (verified)" },
}));
assert.match(hosted, /Where it runs/);
assert.match(hosted, /Not turned on from this computer\./);
assert.match(hosted, /does not let Guard Cloud run anything/);
assert.doesNotMatch(hosted.replace(/<[^>]+>/g, " "), RUNNABLE_IN_CLOUD);

const local = render(protectionModuleFixture({ extension_id: "command.git", name: "Git", source: "built-in" }));
assert.match(local, /Where it runs/);
assert.doesNotMatch(local, /does not let Guard Cloud run anything/);

console.log("extension-run-scope.test.tsx: all tests passed");
