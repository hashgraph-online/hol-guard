import { cloudPolicyRecoveryHint } from "./fleet-protection-recovery";
import { activeFailedHarnesses, ProtectionRepairFlowError } from "./protection-repair-flow";
import { repairHarnessesFor, resolveFleetHeroCopy } from "./fleet-workspace";
import type { FleetHeroCopy } from "./fleet-workspace";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const targetedRepairError = new ProtectionRepairFlowError("App hooks need repair.", ["codex", "grok"]);
assert(
  targetedRepairError.failedHarnesses.length === 2,
  "repair failures retain every app needed for the next actions",
);
assert(
  activeFailedHarnesses(["codex", "codex", "grok"], ["grok"])[0] === "grok",
  "resolved and duplicate app failures do not leave stale repair actions",
);

const urls = {
  fleet_url: "https://hol.org/guard/protect",
  dashboard_url: "http://localhost:7392",
  connect_url: "http://localhost:7392/connect",
};

const localOnlyWithApps = resolveFleetHeroCopy("local_only", 2, "protected", urls);
assert(
  localOnlyWithApps.primaryCtaLabel !== "Open Cloud Devices",
  `F1: local_only primary CTA must not be "Open Cloud Devices" — got "${localOnlyWithApps.primaryCtaLabel}"`
);
assert(
  localOnlyWithApps.primaryCtaHref === urls.connect_url,
  `F1: local_only primary CTA href should be connect_url — got "${localOnlyWithApps.primaryCtaHref}"`
);
assert(
  localOnlyWithApps.primaryCtaLabel.toLowerCase().includes("connect"),
  `F1: local_only primary CTA label should mention connect — got "${localOnlyWithApps.primaryCtaLabel}"`
);
assert(localOnlyWithApps.status === "clear", "F1: local_only with apps status should be clear");

const localOnlyNoApps = resolveFleetHeroCopy("local_only", 0, "degraded", urls);
assert(
  localOnlyNoApps.primaryCtaHref === urls.connect_url,
  `F2: local_only no-apps primary CTA href should be connect_url — got "${localOnlyNoApps.primaryCtaHref}"`
);
assert(localOnlyNoApps.status === "setup_gap", "F2: local_only no apps status should be setup_gap");

const pairedWaitingWithApps = resolveFleetHeroCopy("paired_waiting", 3, "protected", urls);
assert(
  pairedWaitingWithApps.primaryCtaLabel === "Open Cloud Devices",
  `F3: paired_waiting primary CTA should be "Open Cloud Devices" — got "${pairedWaitingWithApps.primaryCtaLabel}"`
);
assert(
  pairedWaitingWithApps.headline.toLowerCase().includes("proof") ||
    pairedWaitingWithApps.subheadline.toLowerCase().includes("proof"),
  "F3: paired_waiting copy should mention proof in headline or subheadline"
);
assert(pairedWaitingWithApps.status === "clear", "F3: paired_waiting with apps status should be clear");

const pairedWaitingNoApps = resolveFleetHeroCopy("paired_waiting", 0, "degraded", urls);
assert(pairedWaitingNoApps.status === "setup_gap", "F3b: paired_waiting no apps status should be setup_gap");

const pairedActiveWithApps = resolveFleetHeroCopy("paired_active", 2, "protected", urls);
assert(
  pairedActiveWithApps.primaryCtaLabel === "Open Cloud Devices",
  `F4: paired_active primary CTA should be "Open Cloud Devices" — got "${pairedActiveWithApps.primaryCtaLabel}"`
);
assert(
  pairedActiveWithApps.primaryCtaHref === urls.fleet_url,
  `F4: paired_active primary CTA href should be fleet_url — got "${pairedActiveWithApps.primaryCtaHref}"`
);
assert(pairedActiveWithApps.status === "clear", "F4: paired_active with apps status should be clear");

const pairedActiveNoApps = resolveFleetHeroCopy("paired_active", 0, "degraded", urls);

const localCloudProof = cloudPolicyRecoveryHint({
  cloudState: "local_only",
  cloudSyncState: "disabled",
  cloudPolicySyncError: null,
  connectUrl: urls.connect_url,
});
assert(localCloudProof?.actionLabel === "Connect Guard Cloud", "local Cloud proof uses the separate connect action");
assert(localCloudProof?.startsOAuth === true, "disconnected Cloud proof starts the local OAuth flow");
assert(
  localCloudProof?.detail.includes("Local Guard remains active") === true,
  "missing Cloud proof must not degrade local Guard copy",
);
assert(
  localCloudProof?.detail.includes("separate from local repair") === true,
  "Cloud proof must not be described as a local integrity repair",
);
const activeCloudProof = cloudPolicyRecoveryHint({
  cloudState: "paired_active",
  cloudSyncState: "healthy",
  cloudPolicySyncError: null,
  connectUrl: urls.connect_url,
});
assert(activeCloudProof === null, "healthy Cloud proof needs no recovery hint");
const pendingCloudProof = cloudPolicyRecoveryHint({
  cloudState: "paired_active",
  cloudSyncState: "pending",
  cloudPolicySyncError: null,
  connectUrl: urls.fleet_url,
});
assert(
  pendingCloudProof?.actionLabel === "Open Guard Cloud" &&
    pendingCloudProof.detail.includes("separate from local repair") &&
    pendingCloudProof.startsOAuth === false,
  "incomplete Cloud proof remains an independent Cloud action",
);

const degradedWithApps = resolveFleetHeroCopy("paired_active", 2, "degraded", urls);
assert(degradedWithApps.status === "degraded", "active installs cannot imply protected fleet health");
assert(degradedWithApps.headline === "App protection is degraded", "degraded fleet copy is explicit");
assert(pairedActiveNoApps.status === "setup_gap", "F5: paired_active no apps status should be setup_gap");

const checkingWithApps = resolveFleetHeroCopy("paired_active", 2, "checking", urls);
assert(checkingWithApps.status === "checking", "unproven fleet health must not look degraded");
assert(checkingWithApps.headline === "Checking app protection", "checking fleet copy is explicit");
assert(
  !checkingWithApps.headline.toLowerCase().includes("degraded"),
  "checking fleet copy must not use degraded language",
);

const targetedRepairs = repairHarnessesFor(
  [
    { harness: "codex", active: true },
    { harness: "grok", active: true },
    { harness: "cursor", active: false },
  ],
  {
    schema_version: "guard.protection-health.v1",
    state: "degraded",
    label: "Degraded",
    detail: "One app needs repair.",
    evidence_gap: false,
    checks: [],
    reason_codes: [],
    apps: [
      {
        harness: "codex",
        state: "protected",
        label: "Protected",
        detail: "Hooks verified.",
        evidence_gap: false,
        checks: [{ check_id: "harness_hooks", status: "pass", reason_code: "hooks_verified" }],
        reason_codes: ["hooks_verified"],
      },
      {
        harness: "grok",
        state: "degraded",
        label: "Degraded",
        detail: "Hooks need repair.",
        evidence_gap: false,
        checks: [{ check_id: "harness_hooks", status: "fail", reason_code: "hook_verification_failed" }],
        reason_codes: ["hook_verification_failed"],
      },
    ],
  },
);
assert(
  targetedRepairs.length === 2 && targetedRepairs[0] === "grok" && targetedRepairs[1] === "cursor",
  "F8: fleet repair must reinstall inactive apps and active apps with failed hook proof",
);

const allStates: FleetHeroCopy[] = [localOnlyWithApps, pairedWaitingWithApps, pairedActiveWithApps];
for (const state of allStates) {
  assert(
    state.secondaryCtaLabel === "Open Home",
    `F6: secondary CTA should always be "Open Home" — got "${state.secondaryCtaLabel}"`
  );
  assert(
    state.secondaryCtaHref === urls.dashboard_url,
    `F6: secondary CTA href should be dashboard_url — got "${state.secondaryCtaHref}"`
  );
}

const JARGON = ["daemon", "runtime", "harness", "artifact", "MCP"];
function containsJargon(text: string): boolean {
  return JARGON.some((word) => text.toLowerCase().includes(word.toLowerCase()));
}

const allCopies = [
  localOnlyWithApps, localOnlyNoApps, pairedWaitingWithApps, pairedWaitingNoApps, pairedActiveWithApps, pairedActiveNoApps,
];
for (const copy of allCopies) {
  assert(
    !containsJargon(copy.headline),
    `F7: headline must not contain jargon — got: "${copy.headline}"`
  );
  assert(
    !containsJargon(copy.subheadline),
    `F7: subheadline must not contain jargon — got: "${copy.subheadline}"`
  );
  assert(
    !containsJargon(copy.primaryCtaLabel),
    `F7: primaryCtaLabel must not contain jargon — got: "${copy.primaryCtaLabel}"`
  );
}

console.log("fleet-workspace.test.ts: all tests passed");
