import assert from "node:assert/strict";

import { connectorWorkspaceItems, normalizeLocalCliList } from "../local-cli-api";
import { extensionBrandTestId, resolveExtensionBrand } from "./model/extension-brand";
import {
  addCustomExtensionPrefillHref,
  customExtensionBadge,
  customExtensionDisplayName,
  initialAddCommand,
  prefillSuggestedStates,
  profileSetupCommand,
} from "./custom-extension-profile";

const hash = "a".repeat(64);
const item = (extra: Record<string, unknown> = {}) => ({
  cli_id: "local-cli.profile-wrangler", identity_hash: hash, kind: "executable", name: "wrangler",
  example_label: "wrangler", observed_count: 0, state: "unset", stale: false, grant_revision: null,
  authority_revision: 1, suggestion_score: 0, suggestable: false, surface: "cli", commands: [], ...extra,
});
const list = (body: Record<string, unknown>) =>
  normalizeLocalCliList({ schema_version: "guard.daemon.local-clis.v1", revision: 1, items: [], ...body });

// Normalizer: seeded_items default, optional fields, invalid optional fields dropped.
assert.deepEqual(list({}).seeded_items, []);
const seeded = list({
  seeded_items: [item({ seeded: true, installed: false, profile_id: "wrangler", brand: "cloudflare", display_name: "Cloudflare Wrangler" }),
    item({ cli_id: "local-cli.profile-other" })],
}).seeded_items;
assert.equal(seeded.length, 1, "seeded_items must be flagged seeded");
assert.equal(seeded[0]!.brand, "cloudflare");
assert.equal(seeded[0]!.installed, false);
assert.equal(seeded[0]!.display_name, "Cloudflare Wrangler");
const dropped = list({ items: [item({ profile_id: "Bad Id!", brand: "../x", display_name: 5, seeded: "yes", installed: 1,
  commands: [{ command_id: "deploy", name: "deploy", usage: "wrangler deploy", state: "inherit", suggested_state: "nope" },
    { command_id: "whoami", name: "whoami", usage: "wrangler whoami", state: "inherit", suggested_state: "allow" }] })] }).items[0]!;
for (const key of ["profile_id", "brand", "display_name", "seeded", "installed"] as const) assert.equal(key in dropped, false, key);
assert.equal("suggested_state" in dropped.commands[0]!, false);
assert.equal(dropped.commands[1]!.suggested_state, "allow");

// connectorWorkspaceItems: unset suggestable CLI rows and seeded rows are included.
const normal = list({ items: [item({ cli_id: "local-cli.detected", name: "detected", suggestable: true }),
  item({ cli_id: "local-cli.plain", name: "plain" })] }).items;
const rows = connectorWorkspaceItems(normal, "", seeded);
assert.deepEqual(rows.map((row) => row.cli_id).sort(), ["local-cli.detected", "local-cli.profile-wrangler"]);
assert.equal(customExtensionBadge(rows.find((row) => row.cli_id === "local-cli.detected")!), "Detected");
assert.equal(customExtensionBadge(seeded[0]!), "Set up");
assert.equal(customExtensionDisplayName(seeded[0]!), "Cloudflare Wrangler");
assert.equal(connectorWorkspaceItems(normal, "cloudflare", seeded).length, 1);
assert.equal(connectorWorkspaceItems([{ ...normal[0]!, cli_id: seeded[0]!.cli_id }], "", seeded).length, 1, "no duplicate row");
assert.equal(profileSetupCommand(seeded[0]!), "npx wrangler");

// Brand: item brand drives custom rows; unknown brands fall back to inference.
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "local-cli.profile-wrangler", brand: "cloudflare" })), "cloudflare");
assert.equal(resolveExtensionBrand({ extension_id: "local-cli.x", brand: "cloudflare" }).kind, "marks");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "local-cli.x", brand: "toString" })), "fallback-shield");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "local-cli.x", name: "wrangler" })), "cloudflare");

// Picker prefill: only never-saved commands take the suggestion.
const command = (state: string, suggested?: string) => ({
  command_id: state, name: state, usage: state, description: "", parent_id: null, state, suggested_state: suggested,
}) as never;
const commands = [command("inherit", "allow"), command("block", "allow"), command("inherit"), command("inherit", "inherit")];
const filled = prefillSuggestedStates({ state: "unset", commands });
assert.deepEqual(filled.map((entry) => entry.state), ["allow", "block", "inherit", "inherit"]);
// Added extensions keep their saved choices, including a deliberate "inherit".
assert.equal(prefillSuggestedStates({ state: "allowed", commands }), commands);

// Prefill URL is allowlisted.
assert.equal(addCustomExtensionPrefillHref("/extensions/add", "npx wrangler"), "/extensions/add?command=npx%20wrangler");
assert.equal(addCustomExtensionPrefillHref("/extensions/add", "rm -rf /"), "/extensions/add");
assert.equal(initialAddCommand("?command=npx%20wrangler"), "npx wrangler");
assert.equal(initialAddCommand("?command=curl%20evil"), "");
