import { renderToStaticMarkup } from "react-dom/server";

import { HarnessPostureManager, HarnessPostureSummaryCard } from "./harness-posture-card";
import type { GuardProtectionCapability, GuardSettings } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function settings(overrides: Partial<GuardSettings> = {}): GuardSettings {
  return {
    mode: "enforce",
    protection_posture: "protected",
    security_level: "balanced",
    harness_postures: {},
    ...overrides,
  } as GuardSettings;
}

function capability(harness: string, displayName: string, extra: Partial<GuardProtectionCapability> = {}): GuardProtectionCapability {
  return { harness, display_name: displayName, ...extra } as GuardProtectionCapability;
}

const capabilities = [
  capability("codex", "Codex"),
  capability("claude-code", "Claude Code"),
  capability("cursor", "Cursor"),
];

const allProtected = renderToStaticMarkup(
  <HarnessPostureManager
    settings={settings()}
    capabilities={capabilities}
    onSettingsChange={() => undefined}
  />,
);
assert(allProtected.includes("Every app is protected."), "manager states when every app is protected");
assert(
  allProtected.includes("Apps start with the machine setting (Protected)"),
  "manager names the machine setting apps inherit",
);
assert(
  allProtected.includes("Follows the machine setting"),
  "inherited rows say where their level comes from",
);
assert(allProtected.includes("Find an app"), "manager offers a search field");

const oneWatched = renderToStaticMarkup(
  <HarnessPostureManager
    settings={settings({ harness_postures: { "claude-code": "watch" } })}
    capabilities={capabilities}
    onSettingsChange={() => undefined}
  />,
);
assert(
  oneWatched.includes("1 of 3 apps in Watch: Claude Code."),
  "manager names the app in Watch",
);
assert(oneWatched.includes("Watch · recording only"), "own Watch row says recording only");
assert(oneWatched.includes("bg-brand-attention"), "watched rows carry the attention tone");
const codexIndex = oneWatched.indexOf('data-harness="codex"');
const claudeIndex = oneWatched.indexOf('data-harness="claude-code"');
assert(
  claudeIndex >= 0 && codexIndex >= 0 && claudeIndex < codexIndex,
  "rows in Watch sort first",
);

const overrideUnderCareful = renderToStaticMarkup(
  <HarnessPostureManager
    settings={settings({ protection_posture: "extra_careful", harness_postures: { codex: "protected" } })}
    capabilities={capabilities}
    onSettingsChange={() => undefined}
  />,
);
assert(overrideUnderCareful.includes("Set for this app"), "an app with its own choice says so");
assert(
  overrideUnderCareful.includes("machine setting (Extra careful)"),
  "manager names the stricter machine setting",
);

// Legacy observe mode without an explicit posture reads as Watch in the header.
const observeOnlyManager = renderToStaticMarkup(
  <HarnessPostureManager
    settings={settings({ protection_posture: undefined, mode: "observe" })}
    capabilities={capabilities}
    onSettingsChange={() => undefined}
  />,
);
assert(
  observeOnlyManager.includes("machine setting (Watch)"),
  "legacy observe settings show the Watch machine label, matching the rows",
);

const limitedCapability = renderToStaticMarkup(
  <HarnessPostureManager
    settings={settings()}
    capabilities={[capability("codex", "Codex", { limited: true, honesty_sentence: "Runs before Guard can ask." })]}
    onSettingsChange={() => undefined}
  />,
);
assert(
  limitedCapability.includes("Limited: Runs before Guard can ask."),
  "limited apps surface their honesty sentence",
);

const lockedManager = renderToStaticMarkup(
  <HarnessPostureManager
    settings={settings({ harness_postures_locked: true })}
    capabilities={capabilities}
    onSettingsChange={() => undefined}
  />,
);
assert(
  lockedManager.includes("Your organization manages protection for each app"),
  "managed lock explains why choices are unavailable",
);

const summary = renderToStaticMarkup(
  <HarnessPostureSummaryCard
    settings={settings({ harness_postures: { "claude-code": "watch", cursor: "protected" } })}
    capabilities={capabilities}
    onOpenApps={() => undefined}
  />,
);
assert(summary.includes("1 of 3 apps in Watch: Claude Code."), "summary card reuses the shared summary line");
assert(summary.includes("Your choices: Claude Code and Cursor."), "summary card names apps with their own choice");
assert(summary.includes("Choose per app"), "summary card links to the per-app manager");

const inheritedSummary = renderToStaticMarkup(
  <HarnessPostureSummaryCard
    settings={settings()}
    capabilities={capabilities}
    onOpenApps={() => undefined}
  />,
);
assert(
  inheritedSummary.includes("Every app is protected."),
  "summary card shows the calm default",
);
assert(
  inheritedSummary.includes("Apps follow the machine setting unless you choose Watch for one of them."),
  "summary card explains inheritance",
);
assert(
  inheritedSummary.includes("rounded-full bg-brand-green"),
  "protected machines show the green status dot",
);

// Machine-wide Watch without overrides still reads as attention on the card.
const machineWatchSummary = renderToStaticMarkup(
  <HarnessPostureSummaryCard
    settings={settings({ protection_posture: "watch", mode: "observe" })}
    capabilities={capabilities}
    onOpenApps={() => undefined}
  />,
);
assert(machineWatchSummary.includes("Every app is in Watch."), "machine Watch summary names the state");
assert(
  machineWatchSummary.includes("rounded-full bg-brand-attention"),
  "machine Watch shows the attention status dot",
);

console.log("harness-posture-card.test.tsx: all assertions passed");
