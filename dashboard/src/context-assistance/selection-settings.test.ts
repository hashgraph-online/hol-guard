import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { GuardSettings } from "../guard-types";
import { parseContextAssistanceStatus } from "./status";
import { sameCigarPreferences, withCigarSelection } from "./selection-settings";
const fixture = JSON.parse(readFileSync(new URL("../../../docs/guard/cigar-integration/evidence/intent-state-verification.json", import.meta.url), "utf8"));
const previous = parseContextAssistanceStatus(fixture.native_test.ready_observation).preferences;
const native = { ...previous, runtime_id: "cigar:new" };
const settings = { mode: "enforce", telemetry: false, context_assistance: previous,
  context_assistance_requested: previous, approval_gate: { enabled: true }, harness_postures: { codex: "watch" } } as unknown as GuardSettings;
const saved = withCigarSelection(settings, native, previous);
assert.equal(saved.context_assistance, native);
assert.equal(saved.approval_gate, settings.approval_gate);
assert.equal(saved.harness_postures, settings.harness_postures);
assert.equal(saved.telemetry, false);
assert.equal(saved.context_assistance_requested, native);
const dirty = { ...settings, telemetry: true, context_assistance: { ...previous, enabled: false,
  limits: { ...previous.limits, context_tokens: 512 } } };
const merged = withCigarSelection(dirty, native, previous, true);
assert.equal(merged.telemetry, true);
assert.equal(merged.context_assistance!.runtime_id, native.runtime_id);
assert.equal(merged.context_assistance!.enabled, false, "a pending opt-out must survive a switch");
assert.equal(merged.context_assistance!.limits.context_tokens, 512);
const off = { ...native, enabled: false };
assert.equal(withCigarSelection({ ...settings, context_assistance: { ...previous, resource_profile: "custom" } }, off, previous, true).context_assistance!.enabled, false);
const newer = { ...settings, context_assistance: { ...previous, enabled: false } };
assert.equal(withCigarSelection(newer, native, previous), newer, "stale results cannot replace a later saved stop");
const chosen = { ...dirty, context_assistance: { ...previous, runtime_id: "user:pending" } };
assert.equal(withCigarSelection(chosen, native, previous, true), chosen);
assert.equal(withCigarSelection(settings, off, previous).context_assistance!.enabled, false);
const previousOff = { ...previous, enabled: false };
const orderedOff = Object.fromEntries(Object.entries(previousOff).reverse()) as unknown as typeof previousOff;
orderedOff.features = Object.fromEntries(Object.entries(previousOff.features).reverse()) as unknown as typeof previousOff.features;
assert.notEqual(JSON.stringify(previousOff), JSON.stringify(orderedOff));
assert.equal(sameCigarPreferences(previousOff, orderedOff), true);
const pendingOn = { ...settings, context_assistance: { ...previousOff, enabled: true } };
assert.equal(withCigarSelection(pendingOn, orderedOff, previousOff, true), pendingOn,
  "metadata key order must not erase a pending opt-in");
const { execution_context: _execution, ...legacyFeatures } = previousOff.features;
const legacyOff = { ...previousOff, features: legacyFeatures };
const explicitOff = { ...legacyOff, features: { ...legacyFeatures, execution_context: false } };
assert.equal(sameCigarPreferences(legacyOff, explicitOff), true);
assert.equal(sameCigarPreferences(explicitOff, legacyOff), true);
assert.equal(sameCigarPreferences(legacyOff, { ...explicitOff, features: { ...explicitOff.features, execution_context: true } }), false);
const pendingLegacyOn = { ...settings, context_assistance: { ...legacyOff, enabled: true } };
assert.equal(withCigarSelection(pendingLegacyOn, explicitOff, legacyOff, true), pendingLegacyOn,
  "a defaulted optional field is not a native preference change");
console.log("CIGAR selection updates preserve unrelated settings, dirty preferences, explicit opt-out and newer saved state.");
