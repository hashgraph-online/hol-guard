import { renderToStaticMarkup } from "react-dom/server";

import { AppVersionCompatibilityCard } from "./apps/app-version-compatibility-card";
import { versionCompatibilityFor } from "./harness-detection";
import {
  normalizeVersionCompatibility,
  versionCheckUnsupported,
  versionRowLabel,
} from "./harness-version-compatibility";
import { HarnessVersionLabel } from "./harness-version-label";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

// 18.4.12 and 18.8.3 are regression fixture values, not production coverage claims.
function payload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: "hol-guard-harness-version-compatibility.v1",
    harness: "omp",
    state: "untested",
    reason: "version_not_in_evidence",
    detected_version: "18.11.2",
    version_is_prerelease: false,
    version_source: "package-metadata",
    observed_at: "2026-10-16T00:00:00Z",
    observation_fresh: true,
    guard_version: "9.9.9",
    platform: "darwin-arm64",
    coverage_revision: "fixture.1",
    tested_versions: ["18.4.12", "18.8.3"],
    tested_scope: null,
    tested_events: [],
    declared_events: ["PostToolUse", "PreToolUse", "UserPromptSubmit"],
    evidence: [],
    limitations: ["Exact versions only."],
    remediation: [
      { label: "Releases", url: "https://github.com/can1357/oh-my-pi/releases" },
      { label: "Bad", url: "javascript:alert(1)" },
    ],
    acknowledgement: { eligible: true, acknowledged: false, key: "a".repeat(64) },
    enforcement_effect: "none",
    ...overrides,
  };
}

const testedEvidence = [{
  harness_version: "18.8.3",
  guard_version: "9.9.9",
  platforms: ["darwin-arm64"],
  transport: "managed_extension",
  events: ["PostToolUse", "PreToolUse", "UserPromptSubmit"],
  suite: { id: "guard-gauntlet-full-task", result: "passed" },
  evidence_level: "live_block",
  evidence_reference: "https://github.com/hashgraph-online/hol-guard/actions/runs/1",
  observed_at: "2026-10-16T00:00:00Z",
}];

// An older daemon (no field) or an unrecognized payload is never "tested".
for (const raw of [undefined, null, {}, { state: "tested" }, payload({ schema: "v0" }), payload({ state: "probably" }),
  payload({ enforcement_effect: "block" })]) {
  const normalized = normalizeVersionCompatibility("omp", raw);
  assert(normalized.state === "version_unknown", `legacy or malformed payload is unknown: ${JSON.stringify(raw)}`);
  assert(normalized.reason === "legacy_daemon", "legacy payload explains the daemon is too old");
  assert(!normalized.acknowledgement.eligible, "legacy payload cannot be acknowledged");
}

const testedWithoutEvidence = normalizeVersionCompatibility("omp", payload({ state: "tested", detected_version: "18.8.3" }));
assert(testedWithoutEvidence.state === "version_unknown", "tested without evidence is not trusted");

// Evidence must be complete and cover the detected version before "tested" is shown.
for (const evidence of [
  [{ ...testedEvidence[0], suite: "guard-gauntlet-full-task" }],
  [{ ...testedEvidence[0], suite: { id: "guard-gauntlet-full-task", result: "failed" } }],
  [{ ...testedEvidence[0], events: [] }],
  [{ ...testedEvidence[0], evidence_reference: "http://example.com/run" }],
  [{ ...testedEvidence[0], harness_version: "18.4.12" }],
]) {
  const normalized = normalizeVersionCompatibility("omp", payload({ state: "tested", detected_version: "18.8.3", evidence }));
  assert(normalized.state === "version_unknown", `incomplete evidence is not trusted: ${JSON.stringify(evidence)}`);
}

const untested = normalizeVersionCompatibility("omp", payload());
assert(untested.state === "untested", "untested payload is preserved");
assert(versionRowLabel(untested) === "Untested version", "untested row label");
assert(untested.remediation.length === 1, "non-https remediation links are dropped");
const untestedRow = renderToStaticMarkup(<HarnessVersionLabel compatibility={untested} />);
assert(untestedRow.includes("Untested version · 18.11.2"), "row shows text and version, not color alone");
assert(untestedRow.includes("text-amber-700") && untestedRow.includes("<svg"), "untested row is amber with an icon");

const acknowledged = normalizeVersionCompatibility("omp", payload({
  acknowledgement: { eligible: true, acknowledged: true, key: "a".repeat(64) },
}));
assert(versionRowLabel(acknowledged) === "Untested · acknowledged", "acknowledged row collapses");
const acknowledgedCard = renderToStaticMarkup(<AppVersionCompatibilityCard initial={acknowledged} />);
assert(acknowledgedCard.includes("Show warning again"), "acknowledged card can be cleared");
assert(!acknowledgedCard.includes("Acknowledge for this version"), "acknowledged card hides the acknowledge action");

const untestedCard = renderToStaticMarkup(<AppVersionCompatibilityCard initial={untested} />);
assert(untestedCard.includes("Acknowledge for this version"), "untested card offers acknowledgement");
assert(untestedCard.includes("18.4.12, 18.8.3"), "untested card lists tested versions");
assert(untestedCard.includes("never changes what Guard allows or blocks"), "card states enforcement is unchanged");

const unknown = normalizeVersionCompatibility("omp", payload({
  state: "version_unknown",
  reason: "multiple_installations",
  detected_version: null,
  acknowledgement: { eligible: true, acknowledged: false, key: "a".repeat(64) },
}));
assert(!unknown.acknowledgement.eligible, "unknown versions cannot be acknowledged even if the payload says so");
const unknownCard = renderToStaticMarkup(<AppVersionCompatibilityCard initial={unknown} />);
assert(unknownCard.includes("More than one installation"), "unknown card explains why");
assert(!unknownCard.includes("Acknowledge for this version"), "unknown card offers no acknowledgement");

const tested = normalizeVersionCompatibility("omp", payload({
  state: "tested",
  reason: null,
  detected_version: "18.8.3",
  tested_scope: "partial",
  tested_events: ["PreToolUse"],
  evidence: testedEvidence,
  acknowledgement: { eligible: false, acknowledged: false, key: null },
}));
assert(tested.state === "tested", "tested payload with evidence is preserved");
assert(versionRowLabel(tested) === "Tested · some events", "partial scope is not shown as fully tested");
const testedCard = renderToStaticMarkup(<AppVersionCompatibilityCard initial={tested} />);
assert(testedCard.includes("Not covered by this evidence: PostToolUse, UserPromptSubmit"), "partial scope lists gaps");

const unavailable = normalizeVersionCompatibility("omp", payload({
  state: "coverage_unavailable",
  reason: "harness_not_covered",
  tested_versions: [],
}));
assert(versionRowLabel(unavailable) === "Coverage unavailable", "unavailable row label");

const unsupported = normalizeVersionCompatibility("codex", payload({
  harness: "codex",
  state: "version_unknown",
  reason: "discovery_unsupported",
}));
assert(versionCheckUnsupported(unsupported), "apps without a version source are quiet");
assert(renderToStaticMarkup(<HarnessVersionLabel compatibility={unsupported} />) === "", "no row noise for unsupported apps");

const detection = {
  kind: "ready" as const,
  items: [{ harness: "omp", version_compatibility: payload() }] as never,
};
assert(versionCompatibilityFor(detection, "omp")?.state === "untested", "detection items are normalized");
assert(versionCompatibilityFor({ kind: "loading" }, "omp") === null, "nothing renders while loading");

console.log("harness version compatibility tests passed");
