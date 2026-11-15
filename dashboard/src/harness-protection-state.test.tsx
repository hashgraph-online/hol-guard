import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";

import { AppVersionCompatibilityCard } from "./apps/app-version-compatibility-card";
import {
  eventProtectionName,
  normalizeEventStates,
  normalizeProtectionState,
  PROTECTION_STATE_COPY,
  protectionStateLabel,
  UNKNOWN_PROTECTION_LABEL,
} from "./harness-protection-state";
import { normalizeVersionCompatibility } from "./harness-version-compatibility";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

type FixtureState = { state: string; label: string; tone: string };
const fixture = JSON.parse(
  readFileSync(new URL("../../tests/fixtures/harness-protection-states.v1.json", import.meta.url), "utf8"),
) as { states: FixtureState[]; unknown_state_label: string };

// The dashboard, CLI and native runtime share one vocabulary and one set of labels.
assert(
  JSON.stringify(Object.keys(PROTECTION_STATE_COPY)) === JSON.stringify(fixture.states.map((item) => item.state)),
  "dashboard states match the shared fixture in order",
);
for (const item of fixture.states) {
  const copy = PROTECTION_STATE_COPY[item.state as keyof typeof PROTECTION_STATE_COPY];
  assert(copy.label === item.label, `${item.state} label matches the fixture`);
  assert(copy.tone === item.tone, `${item.state} tone matches the fixture`);
}
assert(UNKNOWN_PROTECTION_LABEL === fixture.unknown_state_label, "unknown label matches the fixture");

// Anything the daemon does not name is unknown, never proven.
assert(normalizeProtectionState("protected") === null, "unknown states are dropped");
assert(normalizeProtectionState(undefined) === null, "a missing state is unknown");
assert(protectionStateLabel(null) === "Protection unknown", "a missing state renders as unknown");
const events = normalizeEventStates([
  { event: "PreToolUse", transport: "native_hook", mode: "blocking", state: "live_block_proven", reason: null },
  { event: "PostToolUse", transport: "native_hook", mode: "observe", state: "proven", reason: null },
  { transport: "native_hook", state: "configured" },
  "PreToolUse",
]);
assert(events.length === 1 && events[0].event === "PreToolUse", "malformed event entries are dropped");
assert(events[0].tools.length === 0 && eventProtectionName(events[0]) === "PreToolUse", "an unsplit event keeps its name");
const split = normalizeEventStates([
  { event: "PreToolUse", tools: ["apply_patch", 3, ""], transport: "native_hook", state: "configured" },
]);
assert(eventProtectionName(split[0]) === "PreToolUse [apply_patch]", "a split event is named by its tools");
const bySurface = normalizeEventStates([
  { event: "*", surface: "cli", transport: "none", state: "unsupported" },
  { event: "*", surface: "cloud_agent", transport: "none", state: "unsupported" },
]);
assert(
  eventProtectionName(bySurface[0]) === "* · cli" && eventProtectionName(bySurface[1]) === "* · cloud_agent",
  "a surface split keeps each surface in its name",
);

const compatibility = normalizeVersionCompatibility("claude-code", {
  schema: "hol-guard-harness-version-compatibility.v1",
  harness: "claude-code",
  state: "coverage_unavailable",
  reason: "harness_not_covered",
  enforcement_effect: "none",
  detected_version: "0.0.0-fixture",
  protection_state: "configured",
  event_states: [
    { event: "PreToolUse", transport: "native_hook", mode: "blocking", state: "configured", reason: "no_live_evidence" },
    { event: "PostToolUse", transport: "native_hook", mode: "observe", state: "observe_only", reason: "runs_after_execution" },
  ],
});
assert(compatibility.protectionState === "configured", "protection state is read from the payload");
assert(compatibility.eventStates.length === 2, "event states are read from the payload");
const card = renderToStaticMarkup(<AppVersionCompatibilityCard initial={compatibility} />);
assert(card.includes("Configured, not proven"), "card names the overall state");
assert(card.includes("Observe only"), "card lists each event");
assert(card.includes("No live run has proven a block on this event yet."), "card explains an unproven event");
assert(!card.includes("Live block proven"), "an unproven app never shows a proven label");

// An app Guard cannot read a version for still shows its protection proof.
const undiscovered = normalizeVersionCompatibility("cline", {
  schema: "hol-guard-harness-version-compatibility.v1",
  harness: "cline",
  state: "version_unknown",
  reason: "discovery_unsupported",
  enforcement_effect: "none",
  protection_state: "configured",
  event_states: [
    { event: "PreToolUse", transport: "native_hook", mode: "blocking", state: "configured", reason: "no_live_evidence" },
    { event: "PreToolUse", transport: "agent_plugin", mode: "blocking", state: "configured", reason: "no_live_evidence" },
  ],
});
const undiscoveredCard = renderToStaticMarkup(<AppVersionCompatibilityCard initial={undiscovered} />);
assert(undiscoveredCard.includes("Configured, not proven"), "an app without version discovery shows its proof");
assert(!undiscoveredCard.includes("Version coverage"), "an app without version discovery hides version coverage");
// One event on two transports renders as two named rows.
assert(undiscoveredCard.includes("PreToolUse (native_hook)"), "a repeated event names its first transport");
assert(undiscoveredCard.includes("PreToolUse (agent_plugin)"), "a repeated event names its second transport");

console.log("harness protection state tests passed");
