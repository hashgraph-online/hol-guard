import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseCigarCatalog, parseCigarCatalogMetadata } from "./versions-catalog";
import { parseCigarUpdateSettings } from "./versions-preferences";
const document = JSON.parse(readFileSync(new URL("../../../integrations/cigar/release-catalog.v1.json", import.meta.url), "utf8"));
const metadata = { source: "bundled", fresh_for_preparation: true, diagnostic: null, trust_configured: false,
  trust_diagnostic: null, remote_feed_configured: false, feed_diagnostic: null, activation_granted: false };
const input = { schema: "guard-cigar-releases.v1", host_platform: "darwin-arm64", builds: document.builds,
  interpreter_builds: document.interpreters, catalog: metadata };
const parsed = parseCigarCatalog(input);
assert.equal(parsed.host_platform, "darwin-arm64");
assert.equal(parsed.builds[0].identity.build_id, document.builds[0].identity.build_id);
assert.equal(parsed.builds[0].platforms[0].qualification, document.builds[0].platforms[0].qualification);
assert.ok(parsed.builds[0].platforms[0].download_bytes > 0);
assert.equal(parseCigarCatalog({ ...input, host_platform: undefined }).host_platform, null,
  "older native metadata must not cause the browser platform to be inferred");
const next = structuredClone(document.builds[0]);
next.identity.build_id = "same-version-other-build"; next.identity.manifest_sha256 = "f".repeat(64);
const equalVersion = parseCigarCatalog({ ...input, builds: [document.builds[0], next] });
assert.equal(equalVersion.builds.length, 2);
assert.equal(equalVersion.builds[0].identity.sdk_version, equalVersion.builds[1].identity.sdk_version);
assert.notEqual(equalVersion.builds[0].identity.build_id, equalVersion.builds[1].identity.build_id);
next.identity.sdk_version = "0.99.1rc1"; next.channel = "preview";
assert.equal(parseCigarCatalog({ ...input, builds: [next] }).builds[0].identity.sdk_version, "0.99.1rc1");
assert.equal(parseCigarCatalog({ ...input, builds: [{ ...next, withdrawn: true }] }).builds[0].withdrawn, true);
assert.equal(parseCigarCatalogMetadata({ ...metadata, source: "cached", fresh_for_preparation: false, diagnostic: "native_context_assistance_cigar_catalog_expired" }).fresh_for_preparation, false);
for (const bad of [
  { ...input, host_platform: "/caller/python" }, { ...input, builds: [next, next] },
  { ...input, builds: [{ ...next, platforms: [] }] },
  { ...input, catalog: { ...metadata, activation_granted: true } },
  { ...input, catalog: { ...metadata, diagnostic: "expired" } },
  { ...input, builds: [{ ...next, identity: { ...next.identity, source_revision: "main" } }] },
]) assert.throws(() => parseCigarCatalog(bad), /incompatible CIGAR catalog data/);
const preferences = { mode: "manual", allow_preview: false, retain_last_good: true };
const settings = { schema: "guard-cigar-update-preferences.v1", requested: preferences,
  effective: { ...preferences, pinned_build: "managed-build" }, revision: "sha256:" + "a".repeat(64),
  diagnostic: null, locked_settings: ["context_assistance_updates.pinned_build"],
  capabilities: { modes: ["manual", "notify"], automatic_preparation: false, automatic_selection: false, retention_reduction: false } };
const update = parseCigarUpdateSettings(settings);
assert.equal(update.requested.pinned_build, undefined);
assert.equal(update.effective.pinned_build, "managed-build");
assert.equal(update.revision, settings.revision);
assert.equal(update.capabilities.automatic_selection, false);
assert.deepEqual(update.capabilities.modes, ["manual", "notify"]);
for (const bad of [
  { ...settings, revision: "newest" }, { ...settings, revision: 1 },
  { ...settings, effective: { ...preferences, pinned_build: "/external/path" } },
  { ...settings, capabilities: { ...settings.capabilities, modes: ["manual", "manual"] } },
  { ...settings, locked_settings: ["unrelated_security_setting"] },
]) assert.throws(() => parseCigarUpdateSettings(bad), /incompatible CIGAR update preferences/);
console.log("CIGAR catalog identities, same-version builds, host metadata, qualification labels and managed preference contracts passed.");
