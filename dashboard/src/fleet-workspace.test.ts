import { resolveFleetHeroCopy } from "./fleet-workspace";
import type { FleetHeroCopy } from "./fleet-workspace";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

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

const degradedWithApps = resolveFleetHeroCopy("paired_active", 2, "degraded", urls);
assert(degradedWithApps.status === "degraded", "active installs cannot imply protected fleet health");
assert(degradedWithApps.headline === "App protection is degraded", "degraded fleet copy is explicit");
assert(pairedActiveNoApps.status === "setup_gap", "F5: paired_active no apps status should be setup_gap");

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
