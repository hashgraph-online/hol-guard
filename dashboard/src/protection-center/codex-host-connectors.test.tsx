import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { filterCodexHostApps, normalizeCodexHostInventory } from "../codex-host-inventory";
import { normalizeLocalCliList } from "../local-cli-api";
import { CodexHostConnectors } from "./codex-host-connectors";

const raw = {
  host: "Codex", connection_id: "c".repeat(64), catalog_coverage: "host-summary",
  account_verified: false, schemas_available: false, permissions_granted: false,
  snapshot_age: "unknown", metadata_complete: true,
  expires_at_ms: Date.now() + 30_000,
  apps: [{ app_id: "example", name: "Example app", enabled: true, callable: true,
    metadata_available: true, tools: [{ name: "send_message", title: "Send a message",
      description: "Write a synthetic message", inputSchema: { type: "object" }, state: "allowed" }] }],
};
const inventory = normalizeCodexHostInventory(raw);
assert.ok(inventory);
assert.deepEqual(inventory.apps[0].tools[0], {
  name: "send_message", title: "Send a message", description: "Write a synthetic message",
});
assert.equal("inputSchema" in inventory.apps[0].tools[0], false);
assert.equal("state" in inventory.apps[0].tools[0], false);
assert.equal(filterCodexHostApps(inventory.apps, " SYNTHETIC ").length, 1);
assert.equal(filterCodexHostApps(inventory.apps, "unavailable").length, 0);
assert.equal(filterCodexHostApps(inventory.apps, "Example")[0].tools.length, 1);

for (const invalid of [
  { ...raw, account_verified: true }, { ...raw, schemas_available: true },
  { ...raw, permissions_granted: true }, { ...raw, host: "different host" },
  { ...raw, apps: [raw.apps[0], raw.apps[0]] },
  { ...raw, apps: [{ ...raw.apps[0], tools: [raw.apps[0].tools[0], raw.apps[0].tools[0]] }] },
]) assert.equal(normalizeCodexHostInventory(invalid), undefined);

const list = normalizeLocalCliList({ schema_version: "guard.local-clis.v1", revision: 0,
  items: [], host_inventory: raw });
assert.equal(list.items.length, 0);
assert.equal(list.host_inventory?.apps[0].name, "Example app");
assert.equal(normalizeLocalCliList({ schema_version: "guard.local-clis.v1", revision: 0,
  items: [], host_inventory: { ...raw, permissions_granted: true } }).host_inventory, undefined);

const html = renderToStaticMarkup(createElement(CodexHostConnectors, { inventory }));
assert.match(html, /Apps reported by Codex/);
assert.match(html, /Enabled in Codex/);
assert.match(html, /Guard has not verified their accounts or tool permissions/);
assert.match(html, /Search Codex apps and tool summaries/);
assert.match(html, /<details/);
assert.doesNotMatch(html, /<select|role="switch"|Always allow|Always block|inputSchema/);
assert.equal(renderToStaticMarkup(createElement(CodexHostConnectors)), "");
const empty = renderToStaticMarkup(createElement(CodexHostConnectors, { inventory: { ...inventory, apps: [] } }));
assert.match(empty, /Codex did not report any apps/);
const expired = renderToStaticMarkup(createElement(CodexHostConnectors, {
  inventory: { ...inventory, expires_at_ms: Date.now() - 1 },
}));
assert.match(expired, /Host summaries expired or are unavailable/);
assert.doesNotMatch(expired, /Example app|send_message|<details/);
const astral = normalizeCodexHostInventory({ ...raw,
  apps: [{ ...raw.apps[0], name: "🧪".repeat(256) }],
});
assert.equal(astral?.apps[0].name, "🧪".repeat(256));
assert.equal(normalizeCodexHostInventory({ ...raw,
  apps: [{ ...raw.apps[0], name: "🧪".repeat(257) }],
}), undefined);

const many = { ...inventory, apps: Array.from({ length: 100 }, (_, index) => ({
  ...inventory.apps[0], app_id: `example_${index}`, name: `Example ${index}`,
})) };
const paginated = renderToStaticMarkup(createElement(CodexHostConnectors, { inventory: many }));
assert.equal((paginated.match(/<details/g) ?? []).length, 25);
assert.match(paginated, /Show more Codex apps/);
console.log("Codex host metadata, isolation, and display contracts passed");
