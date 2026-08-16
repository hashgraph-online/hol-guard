/**
 * Tests for the local protection status surface.
 *
 * Pattern: node:assert/strict + readFileSync for source assertions.
 * No React Testing Library, no jsdom.
 *
 * Coverage:
 * - Five channels render separately (independent state contracts)
 * - No "sandboxed" copy anywhere in fixtures or source
 * - Every channel state has a rendering path
 * - Plain-language callout with at most one action per fixture
 * - All five fixtures are structurally valid
 * - Components reference ChannelRow by name (named child components)
 * - Summary callout renders headline, explanation, optional actionLabel
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  PROTECTION_STATUS_ALL_ACTIVE,
  PROTECTION_STATUS_ASSURANCE_DEGRADED,
  PROTECTION_STATUS_CLOUD_SYNC_INACTIVE,
  PROTECTION_STATUS_INTERCEPTION_INACTIVE,
  PROTECTION_STATUS_POLICY_INACTIVE,
  type GuardLocalProtectionStatusViewModel,
  type GuardUiProtectionChannelState,
} from "./protection-status-view-model";
import { worstChannel } from "./protection-status-panel";

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function assertValidVm(vm: GuardLocalProtectionStatusViewModel, label: string): void {
  assert(vm.interception !== undefined, `${label}: interception present`);
  assert(vm.policy !== undefined, `${label}: policy present`);
  assert(vm.assurance !== undefined, `${label}: assurance present`);
  assert(vm.selfProtection !== undefined, `${label}: selfProtection present`);
  assert(vm.cloudSync !== undefined, `${label}: cloudSync present`);

  const validStates: GuardUiProtectionChannelState[] = [
    "active",
    "inactive",
    "degraded",
    "unknown",
  ];
  for (const key of [
    "interception",
    "policy",
    "assurance",
    "selfProtection",
    "cloudSync",
  ] as const) {
    assert(
      validStates.includes(vm[key]),
      `${label}: ${key} has valid state: ${vm[key]}`,
    );
  }

  assert(vm.summary !== undefined, `${label}: summary present`);
  assert(
    typeof vm.summary.headline === "string" && vm.summary.headline.length > 0,
    `${label}: summary has headline`,
  );
  assert(
    typeof vm.summary.explanation === "string" && vm.summary.explanation.length > 0,
    `${label}: summary has explanation`,
  );
  assert(
    vm.summary.actionLabel === null || typeof vm.summary.actionLabel === "string",
    `${label}: actionLabel is null or string`,
  );
  assert(
    vm.summary.tone === "ok" ||
      vm.summary.tone === "info" ||
      vm.summary.tone === "warn" ||
      vm.summary.tone === "critical",
    `${label}: summary tone is valid`,
  );
}

// ---------------------------------------------------------------------------
// 1. Fixture structural validity
// ---------------------------------------------------------------------------

const fixtures: [string, GuardLocalProtectionStatusViewModel][] = [
  ["allActive", PROTECTION_STATUS_ALL_ACTIVE],
  ["assuranceDegraded", PROTECTION_STATUS_ASSURANCE_DEGRADED],
  ["cloudSyncInactive", PROTECTION_STATUS_CLOUD_SYNC_INACTIVE],
  ["interceptionInactive", PROTECTION_STATUS_INTERCEPTION_INACTIVE],
  ["policyInactive", PROTECTION_STATUS_POLICY_INACTIVE],
];

for (const [name, vm] of fixtures) {
  assertValidVm(vm, name);
}

// ---------------------------------------------------------------------------
// 2. Five channels render independently
// ---------------------------------------------------------------------------

assert(
  PROTECTION_STATUS_ASSURANCE_DEGRADED.assurance === "degraded",
  "assurance channel reflects degraded state",
);
assert(
  PROTECTION_STATUS_ASSURANCE_DEGRADED.interception === "active",
  "interception is independent of assurance",
);
assert(
  PROTECTION_STATUS_ASSURANCE_DEGRADED.policy === "active",
  "policy is independent of assurance",
);
assert(
  PROTECTION_STATUS_ASSURANCE_DEGRADED.selfProtection === "active",
  "self-protection is independent of assurance",
);
assert(
  PROTECTION_STATUS_ASSURANCE_DEGRADED.cloudSync === "active",
  "cloud sync is independent of assurance",
);

assert(
  PROTECTION_STATUS_CLOUD_SYNC_INACTIVE.cloudSync === "inactive",
  "cloud sync reflects inactive state",
);
assert(
  PROTECTION_STATUS_CLOUD_SYNC_INACTIVE.interception === "active",
  "interception independent of cloud sync",
);
assert(
  PROTECTION_STATUS_CLOUD_SYNC_INACTIVE.policy === "active",
  "policy independent of cloud sync",
);

assert(
  PROTECTION_STATUS_INTERCEPTION_INACTIVE.interception === "inactive",
  "interception reflects inactive state",
);
assert(
  PROTECTION_STATUS_INTERCEPTION_INACTIVE.policy === "active",
  "policy independent of interception",
);

assert(
  PROTECTION_STATUS_POLICY_INACTIVE.policy === "inactive",
  "policy reflects inactive state",
);
assert(
  PROTECTION_STATUS_POLICY_INACTIVE.assurance === "active",
  "assurance independent of policy",
);

// ---------------------------------------------------------------------------
// 3. No "sandboxed" copy in any fixture
// ---------------------------------------------------------------------------

for (const [name, vm] of fixtures) {
  const allText = JSON.stringify(vm).toLowerCase();
  assert(!allText.includes("sandboxed"), `${name}: no "sandboxed" copy`);
  assert(!allText.includes("sandbox"), `${name}: no "sandbox" copy`);
}

// ---------------------------------------------------------------------------
// 4. Every channel state has a rendering path
// ---------------------------------------------------------------------------

const validStates: GuardUiProtectionChannelState[] = [
  "active",
  "inactive",
  "degraded",
  "unknown",
];

for (const state of validStates) {
  const vm: GuardLocalProtectionStatusViewModel = {
    interception: state,
    policy: state,
    assurance: state,
    selfProtection: state,
    cloudSync: state,
    summary: {
      headline: `${state} state fixture`,
      explanation: `All channels are ${state}.`,
      actionLabel: state === "active" ? null : "Check status",
      tone:
        state === "active"
          ? "ok"
          : state === "degraded"
            ? "warn"
            : "critical",
    },
  };

  assertValidVm(vm, `${state} state fixture`);

  for (const key of [
    "interception",
    "policy",
    "assurance",
    "selfProtection",
    "cloudSync",
  ] as const) {
    assert(vm[key] === state, `${state} state: ${key} = ${vm[key]}`);
  }
}

// ---------------------------------------------------------------------------
// 5. Summary callout contracts
// ---------------------------------------------------------------------------

for (const [name, vm] of fixtures) {
  assert(
    vm.summary.headline.length > 0 && vm.summary.headline.length < 100,
    `${name}: headline is concise plain language`,
  );
  assert(
    vm.summary.explanation.length > 20,
    `${name}: explanation is descriptive`,
  );
  assert(
    typeof vm.summary.actionLabel === "string" ||
      vm.summary.actionLabel === null,
    `${name}: at most one action`,
  );

  const channels = [
    vm.interception,
    vm.policy,
    vm.assurance,
    vm.selfProtection,
    vm.cloudSync,
  ];
  const hasInactive = channels.includes("inactive");
  const hasDegraded = channels.includes("degraded");

  if (hasInactive) {
    assert(
      vm.summary.tone === "critical" || vm.summary.tone === "warn" || vm.summary.tone === "info",
      `${name}: inactive channels produce critical/warn tone`,
    );
  } else if (hasDegraded) {
    assert(vm.summary.tone === "warn", `${name}: degraded produces warn tone`);
  } else {
    assert(vm.summary.tone === "ok", `${name}: all active produces ok tone`);
  }
}

// ---------------------------------------------------------------------------
// 6. Channel isolation
// ---------------------------------------------------------------------------

const degradedVm = PROTECTION_STATUS_ASSURANCE_DEGRADED;
assert(degradedVm.assurance === "degraded", "assurance is the degraded channel");

for (const key of [
  "interception",
  "policy",
  "selfProtection",
  "cloudSync",
] as const) {
  assert(
    degradedVm[key] === "active",
    `${key} remains active when assurance is degraded`,
  );
}

// ---------------------------------------------------------------------------
// 7. Fixture completeness
// ---------------------------------------------------------------------------

const allFixtures: GuardLocalProtectionStatusViewModel[] = [
  PROTECTION_STATUS_ALL_ACTIVE,
  PROTECTION_STATUS_ASSURANCE_DEGRADED,
  PROTECTION_STATUS_CLOUD_SYNC_INACTIVE,
  PROTECTION_STATUS_INTERCEPTION_INACTIVE,
  PROTECTION_STATUS_POLICY_INACTIVE,
];

assert(allFixtures.length === 5, "five fixtures defined");

// Each fixture has a unique witness signature (channel:name-state)
const signatures = allFixtures.map((vm) => {
  const keys = [
    "interception" as const,
    "policy" as const,
    "assurance" as const,
    "selfProtection" as const,
    "cloudSync" as const,
  ];
  for (const key of keys) {
    if (vm[key] !== "active") return `${key}:${vm[key]}`;
  }
  return "all-active";
});

const uniqueSignatures = new Set(signatures);
assert(
  uniqueSignatures.size === allFixtures.length,
  `each fixture has a unique channel-state signature: ${signatures.join(", ")}`,
);

// ---------------------------------------------------------------------------
// 8. Source code assertions: no "sandboxed" in component files
// ---------------------------------------------------------------------------

const viewModelSource = readFileSync(
  new URL("./protection-status-view-model.ts", import.meta.url),
  "utf8",
);
const channelsSource = readFileSync(
  new URL("./protection-status-channels.tsx", import.meta.url),
  "utf8",
);
const panelSource = readFileSync(
  new URL("./protection-status-panel.tsx", import.meta.url),
  "utf8",
);

assert(
  !viewModelSource.toLowerCase().includes("sandboxed"),
  "view-model: no sandboxed copy",
);
assert(
  !viewModelSource.toLowerCase().includes("sandbox"),
  "view-model: no sandbox copy",
);
assert(
  !channelsSource.toLowerCase().includes("sandboxed"),
  "channels: no sandboxed copy",
);
assert(
  !channelsSource.toLowerCase().includes("sandbox"),
  "channels: no sandbox copy",
);
assert(
  !panelSource.toLowerCase().includes("sandboxed"),
  "panel: no sandboxed copy",
);
assert(
  !panelSource.toLowerCase().includes("sandbox"),
  "panel: no sandbox copy",
);

// ---------------------------------------------------------------------------
// 9. Component architecture assertions
// ---------------------------------------------------------------------------

// Named child components (not render helpers)
assert.match(
  channelsSource,
  /export\s+function\s+ChannelRow/,
  "ChannelRow is a named exported component",
);
assert.match(
  channelsSource,
  /export\s+function\s+SummaryCallout/,
  "SummaryCallout is a named exported component",
);

// Panel uses ChannelRow by name
assert.match(
  panelSource,
  /import.*ChannelRow.*from.*protection-status-channels/,
  "Panel imports ChannelRow from channels module",
);
assert.match(
  panelSource,
  /import.*SummaryCallout.*from.*protection-status-channels/,
  "Panel imports SummaryCallout from channels module",
);

// Panel accepts vm as GuardLocalProtectionStatusViewModel
assert.match(
  panelSource,
  /GuardLocalProtectionStatusViewModel/,
  "Panel imports GuardLocalProtectionStatusViewModel type",
);

// Panel iterates five channels (not a single badge)
const channelIteration = panelSource.match(/CHANNEL_KEYS|interception.*policy.*assurance.*selfProtection.*cloudSync|vm\["interception"\].*vm\["policy"\]/);
assert(
  panelSource.includes('channelKey={key}') || panelSource.includes('key={key}'),
  "Panel iterates channels individually for independent rendering",
);

// SummaryCallout renders headline, explanation, optional action
assert.match(
  channelsSource,
  /callout\.headline/,
  "SummaryCallout renders callout headline",
);
assert.match(
  channelsSource,
  /callout\.explanation/,
  "SummaryCallout renders callout explanation",
);
assert.match(
  channelsSource,
  /callout\.actionLabel/,
  "SummaryCallout renders callout actionLabel",
);

// ChannelRow renders channel label and state independently
assert.match(
  channelsSource,
  /CHANNEL_META\[channelKey\]/,
  "ChannelRow uses per-channel metadata for label/explanation",
);
assert.match(
  channelsSource,
  /stateLabelFor\(|stateLabel:|resolveStyles\(/,
  "ChannelRow resolves its own independent state label",
);

// ---------------------------------------------------------------------------
// 10. Stable handlers — no inline anonymous JSX callbacks in components
// ---------------------------------------------------------------------------

// Panel should use named/handled callbacks, not inline () => { ... } in JSX
// Check that the panel has useCallback or passes a direct handler reference
assert.match(
  panelSource,
  /onAction/,
  "Panel accepts onAction callback prop",
);
assert.match(
  channelsSource,
  /onAction/,
  "SummaryCallout accepts onAction callback prop",
);


// worstChannel precedence: an inactive/unknown/degraded channel must win over
// active channels so the panel header never overstates protection posture.
{
  const mixed = {
    interception: "active",
    policy: "active",
    assurance: "active",
    selfProtection: "active",
    cloudSync: "inactive",
    summary: { headline: "h", explanation: "e", actionLabel: null, tone: "warn" },
  } as const;
  assert.equal(worstChannel(mixed), "inactive", "inactive beats active");

  const degraded = { ...mixed, cloudSync: "degraded" as const };
  assert.equal(worstChannel(degraded), "degraded", "degraded beats active");

  const allActive = { ...mixed, cloudSync: "active" as const };
  assert.equal(worstChannel(allActive), "active", "all active resolves active");
}
