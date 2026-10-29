import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseContextAssistanceStatus, contextStatusCopy } from "./status";
import { withContextProfile, settingsWithContextOff } from "./settings-model";
import type { GuardSettings } from "../guard-types";

// An actual native candidate observation, rather than a second handwritten DTO.
const receipt = JSON.parse(readFileSync(new URL("../../../docs/guard/cigar-integration/evidence/intent-state-verification.json", import.meta.url), "utf8"));
const ready = parseContextAssistanceStatus(receipt.native_test.ready_observation);
assert.equal(ready.effective_enabled, true);
assert.equal(contextStatusCopy(ready).label, "Ready");
assert.deepEqual(ready.runtime?.interpreter.version, [3, 14, 7]);

const off = { ...ready, availability: "off", requested_enabled: false, effective_enabled: false,
  preferences: { ...ready.preferences, enabled: false }, runtime: null, last_check: null,
  effective_preferences: { ...ready.effective_preferences, enabled: false },
  generation: "9007199254740993", qualification: null };
assert.equal(parseContextAssistanceStatus(off).generation, "9007199254740993");
assert.equal(contextStatusCopy(parseContextAssistanceStatus(off)).label, "Off");
assert.equal(contextStatusCopy(parseContextAssistanceStatus({ ...off, job: { id: "42", operation: "recheck", phase: "verifying" } })).label, "Checking runtime");

const waiting = parseContextAssistanceStatus({ ...off, availability: "unavailable", requested_enabled: true,
  preferences: { ...ready.preferences, enabled: true }, effective_preferences: { ...ready.effective_preferences, enabled: true },
  diagnostic: "runtime_not_verified" });
assert.equal(contextStatusCopy(waiting).label, "Not started", "saved consent must not be presented as a failed runtime check");
assert.match(contextStatusCopy(waiting).detail, /Click Start CIGAR/);
assert.equal(contextStatusCopy({ ...waiting, last_check: ready.runtime }).label, "Not started",
  "a historical check never claims that a runtime is currently Ready");
assert.equal(contextStatusCopy({ ...waiting, diagnostic: "runtime_idle" }).label, "Paused");
assert.equal(contextStatusCopy({ ...waiting, diagnostic: "python_version_unsupported" }).label, "Unavailable");
assert.equal(contextStatusCopy({ ...waiting, verification_permitted: false }).label, "Unavailable");

// Storage readiness is a separate native proof, independent of the existing
// actual interpreter/compile observation used by this projection fixture.
const persistent = { ...ready,
  capabilities: { shared_agents: true, private_persistence: true },
  preferences: { ...ready.preferences, storage: { ...ready.preferences.storage, mode: "sqlite" } },
  effective_preferences: { ...ready.effective_preferences, storage: { ...ready.effective_preferences.storage, mode: "sqlite" } },
  runtime: { ...ready.runtime, persistence_compile_verified: true } };
assert.equal(parseContextAssistanceStatus(persistent).effective_enabled, true);
for (const malformed of [
  { ...persistent, runtime: { ...persistent.runtime, persistence_compile_verified: undefined } },
  { ...persistent, runtime: { ...persistent.runtime, persistence_compile_verified: false } },
  { ...persistent, runtime: { ...persistent.runtime, persistence_compile_verified: "true" } },
  { ...persistent, capabilities: { shared_agents: true, private_persistence: false } },
  { ...persistent, capabilities: undefined },
]) assert.throws(() => parseContextAssistanceStatus(malformed));

for (const malformed of [
  {}, { ...off, generation: 9007199254740993 }, { ...off, preferences: null },
  { ...ready, runtime: null }, { ...ready, effective_enabled: false },
  { ...ready, requested_enabled: false },
  { ...ready, runtime: { ...ready.runtime, compile_verified: false } },
  { ...ready, runtime: { ...ready.runtime, shared_compile_verified: "true" } },
  { ...ready, effective_preferences: { ...ready.effective_preferences, features: { ...ready.effective_preferences.features, shared_agents: true } },
    runtime: { ...ready.runtime, shared_compile_verified: false } },
  { ...off, capabilities: { shared_agents: "supported", private_persistence: false } },
  { ...ready, effective_preferences: { ...ready.effective_preferences, enabled: false } },
  { ...ready, verification_permitted: false },
  { ...off, installation_options: [{ runtime_id: "unverified" }] },
  { ...off, job: { id: "42", operation: "activate", phase: "unknown" } },
]) assert.throws(() => parseContextAssistanceStatus(malformed));

const restricted = parseContextAssistanceStatus(receipt.restriction_observation);
assert.equal(restricted.requested_enabled, true);
assert.equal(restricted.preferences.enabled, true);
assert.equal(restricted.effective_preferences.enabled, false);
assert.equal(restricted.verification_permitted, false);
assert.match(contextStatusCopy(restricted).detail, /preference is saved/);

const smaller = withContextProfile(ready.preferences, "low_memory");
assert.equal(smaller.limits.max_active_workspaces, 1);
assert.ok(smaller.limits.context_tokens < ready.preferences.limits.context_tokens);
assert.equal(smaller.limits.idle_shutdown_seconds, 120);
assert.deepEqual(smaller.sources, ready.preferences.sources);
assert.equal(smaller.enabled, true, "resource preference changes never invent or erase consent");
assert.deepEqual(withContextProfile(smaller, "balanced").limits, ready.preferences.limits);

const draft = { mode: "enforce", telemetry: true, context_assistance: smaller } as GuardSettings;
const stopped = settingsWithContextOff(draft, ready.preferences);
assert.equal(stopped.context_assistance?.enabled, false);
assert.equal(stopped.mode, "enforce");
assert.equal(stopped.telemetry, true);
assert.deepEqual(stopped.context_assistance?.limits, smaller.limits, "immediate stop preserves unrelated unsaved preferences");
assert.equal(draft.context_assistance?.enabled, true, "the saved and draft objects are not mutated");
console.log("Context assistance status, scope of readiness, presets and immediate opt-out checks passed.");
