import {
  BULK_HIGH_TIER_THRESHOLD,
  BULK_LOW_TIER_THRESHOLD,
  buildBulkConfirmPhrase,
  buildBulkRiskDisclosure,
  bulkConfirmMatches,
  bulkRiskTone,
  resolveBulkRiskTier,
  type BulkSelectionStats,
} from "./queue-bulk-risk-disclosure";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function baseStats(overrides: Partial<BulkSelectionStats> = {}): BulkSelectionStats {
  return {
    actionCount: 0,
    groupCount: 0,
    duplicateActionCount: 0,
    sensitiveCount: 0,
    sensitiveSamplePaths: [],
    ...overrides,
  };
}

// T-RISK-01: low tier copy + no typed confirm
const low = buildBulkRiskDisclosure(baseStats({ actionCount: 3, groupCount: 3 }));
assert(low.tier === "low", "T-RISK-01a: 3 reads is low tier");
assert(low.requiresTypedConfirm === false, "T-RISK-01b: low tier does not require typed confirm");
assert(low.tone === "green", "T-RISK-01c: low tier tone is green");
assert(low.headline.includes("3 reads"), "T-RISK-01d: low headline includes action count");
assert(low.confirmPhrase === "approve 3 reads", "T-RISK-01e: low confirm phrase format");

// T-RISK-02: elevated tier (6 reads, no sensitive)
const elevated = buildBulkRiskDisclosure(baseStats({ actionCount: 6, groupCount: 5 }));
assert(elevated.tier === "elevated", "T-RISK-02a: 6 reads is elevated tier");
assert(elevated.tone === "amber", "T-RISK-02b: elevated tone is amber");
assert(elevated.requiresTypedConfirm === false, "T-RISK-02c: elevated does not require typed confirm");
assert(elevated.headline.includes("6 reads"), "T-RISK-02d: elevated headline includes count");

// T-RISK-02b: elevated via duplicate retries
const elevatedDup = buildBulkRiskDisclosure(
  baseStats({ actionCount: 4, groupCount: 3, duplicateActionCount: 1 }),
);
assert(elevatedDup.tier === "elevated", "T-RISK-02e: duplicate retries escalate to elevated");
assert(
  elevatedDup.bullets.some((b) => b.includes("duplicate retr") && b.includes("included")),
  "T-RISK-02f: elevated dup copy mentions duplicate retry",
);

// T-RISK-03: high tier at threshold
const high = buildBulkRiskDisclosure(
  baseStats({ actionCount: BULK_HIGH_TIER_THRESHOLD, groupCount: 8 }),
);
assert(high.tier === "high", "T-RISK-03a: 10 reads is high tier");
assert(high.tone === "attention", "T-RISK-03b: high tone is attention");
assert(high.requiresTypedConfirm === true, "T-RISK-03c: high tier requires typed confirm");
assert(
  high.headline.toLowerCase().includes("high-impact"),
  "T-RISK-03d: high headline flags high-impact",
);
assert(
  high.body.toLowerCase().includes("mass approval"),
  "T-RISK-03e: high body warns about mass approval",
);

// T-RISK-03b: high tier forced by sensitive items even at low count
const highSensitive = buildBulkRiskDisclosure(
  baseStats({ actionCount: 2, groupCount: 2, sensitiveCount: 1, sensitiveSamplePaths: [".env"] }),
);
assert(highSensitive.tier === "high", "T-RISK-03f: sensitive items force high tier");
assert(highSensitive.requiresTypedConfirm === true, "T-RISK-03g: sensitive requires typed confirm");
assert(
  highSensitive.bullets.some((b) => b.includes("sensitive") && b.includes("NOT")),
  "T-RISK-03h: sensitive bullets call out exclusion",
);
assert(
  highSensitive.bullets.some((b) => b.includes(".env")),
  "T-RISK-03i: sensitive sample paths included in copy",
);

// T-RISK-04: threshold boundaries (5 = low, 6 = elevated, 9 = elevated, 10 = high)
assert(
  resolveBulkRiskTier(baseStats({ actionCount: BULK_LOW_TIER_THRESHOLD, groupCount: 5 })) === "low",
  "T-RISK-04a: 5 reads is low boundary",
);
assert(
  resolveBulkRiskTier(baseStats({ actionCount: BULK_LOW_TIER_THRESHOLD + 1, groupCount: 6 })) === "elevated",
  "T-RISK-04b: 6 reads crosses into elevated",
);
assert(
  resolveBulkRiskTier(baseStats({ actionCount: BULK_HIGH_TIER_THRESHOLD - 1, groupCount: 8 })) === "elevated",
  "T-RISK-04c: 9 reads stays elevated",
);
assert(
  resolveBulkRiskTier(baseStats({ actionCount: BULK_HIGH_TIER_THRESHOLD, groupCount: 9 })) === "high",
  "T-RISK-04d: 10 reads crosses into high",
);

// T-RISK-05: confirm phrase formatting + pluralization
assert(buildBulkConfirmPhrase(1) === "approve 1 reads", "T-RISK-05a: single-count phrase still uses reads");
assert(buildBulkConfirmPhrase(12) === "approve 12 reads", "T-RISK-05b: multi-count phrase");
assert(buildBulkConfirmPhrase(0) === "approve 0 reads", "T-RISK-05c: zero-count phrase");

// T-RISK-06: typed-confirmation matching (case-insensitive, whitespace-trimmed)
assert(
  bulkConfirmMatches("Approve 12 reads", "approve 12 reads") === true,
  "T-RISK-06a: case-insensitive match",
);
assert(
  bulkConfirmMatches("  approve   12  reads  ", "approve 12 reads") === true,
  "T-RISK-06b: whitespace-tolerant match",
);
assert(
  bulkConfirmMatches("approve 12", "approve 12 reads") === false,
  "T-RISK-06c: partial phrase does not match",
);
assert(
  bulkConfirmMatches("", "approve 12 reads") === false,
  "T-RISK-06d: empty input never matches",
);
assert(
  bulkConfirmMatches("approve 5 reads", "approve 12 reads") === false,
  "T-RISK-06e: wrong count does not match",
);

// T-RISK-07: zero selection guard returns low tier with no bullets
const zero = buildBulkRiskDisclosure(baseStats());
assert(zero.tier === "low", "T-RISK-07a: zero selection is low tier");
assert(zero.bullets.length === 0, "T-RISK-07b: zero selection has no bullets");
assert(
  zero.headline.toLowerCase().includes("select"),
  "T-RISK-07c: zero selection headline invites selection",
);

// T-RISK-08: tone mapping helper
assert(bulkRiskTone("low") === "green", "T-RISK-08a: low tone green");
assert(bulkRiskTone("elevated") === "amber", "T-RISK-08b: elevated tone amber");
assert(bulkRiskTone("high") === "attention", "T-RISK-08c: high tone attention");

console.log("queue-bulk-risk-disclosure.test.ts: all tests passed");
