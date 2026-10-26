import assert from "node:assert/strict";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { normalizeLocalCliItem } from "../local-cli-api";
import { LocalCliCapabilities } from "./local-cli-capabilities";

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
  capabilities: { "loopback-network": "off", "state-dir-read": "on", "state-dir-write": "off" },
};
const render = (value: Record<string, unknown>) => renderToStaticMarkup(createElement(LocalCliCapabilities, {
  item: normalizeLocalCliItem(value), revision: 1, onRefresh: async () => undefined,
}));

// The listed map is kept; an unknown capability state reads as off.
const normalized = normalizeLocalCliItem({ ...raw, capabilities: { ...raw.capabilities, "state-dir-write": "maybe" } });
assert.deepEqual(normalized.capabilities, { "loopback-network": "off", "state-dir-read": "on", "state-dir-write": "off" });
assert.equal(normalized.suggested_capability, undefined);

// A suggestion names the denied access and offers one way to turn it on.
const suggested = render({ ...raw, suggested_capability: "loopback-network" });
assert.match(suggested, /A run was stopped from connecting to this computer/);
assert.match(suggested, /Turn on local network access/);
assert.match(suggested, /role="status"/);
assert.match(suggested, /Everything else outside the workspace stays blocked/);
assert.doesNotMatch(suggested, /ask the user/i);

// Every capability shows its current state and a matching action.
assert.match(suggested, /Read its settings<span[^>]*>On</);
assert.match(suggested, /aria-label="Turn off read its settings"/);
assert.match(suggested, /aria-label="Turn on save its settings"/);

// No suggestion without a recorded cause, or for a capability already on or unknown.
const plain = render(raw);
assert.doesNotMatch(plain, /local-cli-capability-suggestion/);
assert.doesNotMatch(render({ ...raw, suggested_capability: "state-dir-read" }), /local-cli-capability-suggestion/);
assert.equal(normalizeLocalCliItem({ ...raw, suggested_capability: "raw-network" }).suggested_capability, undefined);

// An item listed without capabilities renders nothing.
const { capabilities: _ignored, ...withoutCapabilities } = raw;
assert.equal(render(withoutCapabilities), "");
