import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { ContextSettingsControls, type ContextSettingsControlsProps } from "./settings-controls";
import { parseContextAssistanceStatus } from "./status";

const receipt = JSON.parse(readFileSync(new URL("./fixtures/intent-state.json", import.meta.url), "utf8"));
const ready = parseContextAssistanceStatus(receipt.native_test.ready_observation);
const base: ContextSettingsControlsProps = {
  value: ready.preferences, status: ready, installations: null,
  loading: false, busy: false, disabled: false, locked: false, dirty: false, error: null,
  onChange: () => undefined, onRefresh: () => undefined, onChooseRuntime: () => undefined, onControl: () => undefined,
};
const render = (props: Partial<ContextSettingsControlsProps> = {}) => renderToStaticMarkup(createElement(ContextSettingsControls, { ...base, ...props }));
function buttonDisabled(html: string, label: string): boolean {
  const attributes = html.match(new RegExp(`<button([^>]*)>${label}</button>`))?.[1];
  assert.ok(attributes !== undefined, `missing button: ${label}`);
  return /\sdisabled(?:=|\s|$)/.test(attributes);
}

assert.match(render(), /Requires a verified final CPython 3\.14 runtime/);
assert.match(render(), /Ready\./);
assert.equal(buttonDisabled(render(), "Turn off now"), false);
assert.equal(buttonDisabled(render({ locked: true }), "Turn off now"), false,
  "managed preferences never remove immediate opt-out");
assert.match(render({ locked: true }), /organization manages these preferences/);

const pending = { ...ready, effective_enabled: false, availability: "checking" as const,
  runtime: null, job: { id: "4", operation: "activate" as const, phase: "verifying" as const } };
assert.equal(buttonDisabled(render({ status: pending }), "Turn off now"), false);
assert.equal(buttonDisabled(render({ status: pending }), "Start context assistance"), true,
  "a pending native job cannot be started twice");

const requested = { ...ready, effective_enabled: false, availability: "unavailable" as const,
  runtime: null, diagnostic: "runtime_not_verified" };
assert.doesNotMatch(render({ status: requested }), /Ready\./);
assert.equal(buttonDisabled(render({ status: requested, dirty: true }), "Start context assistance"), true);
assert.equal(buttonDisabled(render({ status: requested, dirty: false }), "Start context assistance"), false);
assert.match(render({ installations: [] }), /No registered CIGAR runtime is available/);
assert.match(render({ installations: [] }), /Python 3\.14 may already be installed/);
assert.match(render({ status: null, error: "Status is unavailable." }), /role="alert"/);
assert.equal(buttonDisabled(render({ status: null }), "Turn off now"), false,
  "lost availability cannot remove opt-out for an enabled saved preference");

const unsupported = render({ value: null, status: null });
assert.doesNotMatch(unsupported, /role="switch"/);
assert.match(unsupported, /Update Guard/);
const restricted = parseContextAssistanceStatus(receipt.restriction_observation);
const managed = render({ value: restricted.preferences, status: restricted, locked: true });
assert.match(managed, /preference is saved/);
assert.equal(buttonDisabled(managed, "Turn off now"), false);
assert.equal(buttonDisabled(managed, "Check selected runtime"), true);
assert.equal(buttonDisabled(managed, "Start context assistance"), true);

function executionSwitch(html: string) {
  const id = html.match(/<p id="([^"]+)"[^>]*>Associate native context with execution<\/p>/)?.[1];
  assert.ok(id, "execution setting needs an accessible label");
  const attributes = [...html.matchAll(/<button\b([^>]*)>/g)]
    .map((match) => match[1]).find((value) => value.includes(`aria-labelledby="${id}"`));
  assert.ok(attributes, "execution setting needs its labelled switch");
  return { disabled: /\sdisabled(?:=|\s|$)/.test(attributes), checked: attributes.includes('aria-checked="true"') };
}
assert.deepEqual(executionSwitch(render()), { disabled: true, checked: false },
  "an older core without this native route cannot offer opt-in");
const executionCapable = { ...ready, capabilities: { shared_agents: true, private_persistence: true, execution_context: true } };
assert.deepEqual(executionSwitch(render({ status: executionCapable })), { disabled: false, checked: false });
const executionSelected = { ...ready.preferences, features: { ...ready.preferences.features, execution_context: true } };
assert.deepEqual(executionSwitch(render({ value: executionSelected })), { disabled: false, checked: true },
  "loss of the route cannot remove the saved feature's off switch");
assert.equal(executionSwitch(render({ status: executionCapable,
  value: { ...ready.preferences, sources: { ...ready.preferences.sources, native_policy_facts: false } } })).disabled, true);
console.log("Context assistance settings rendering and unavailable/managed/cancellation controls passed.");
