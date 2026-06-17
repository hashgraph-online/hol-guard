// Risk disclosure helpers for the Review Queue bulk approval flow.
//
// These are pure functions so the escalating disclosure copy can be unit tested
// in isolation. The dashboard layer owns all real-world safety rails
// (server-side `bulk_allow_read_only_once` still rejects anything that is not a
// read-only, non-sensitive file read); these helpers only describe *what the
// user is about to do* in plain, escalating language.

export type BulkRiskTier = "low" | "elevated" | "high";

export type BulkRiskTone = "green" | "amber" | "attention";

export type BulkSelectionStats = {
  /** Total number of underlying actions across selected groups (1 + each duplicate retry). */
  actionCount: number;
  /** Number of selected groups (without their duplicate retries). */
  groupCount: number;
  /** Number of underlying actions that are duplicate retries across all selected groups. */
  duplicateActionCount: number;
  /**
   * Sensitive file-read groups currently in the queue. These are never approved
   * by bulk approval — they stay in the queue for individual review — but their
   * presence is surfaced in the disclosure so the user knows what was excluded.
   */
  sensitiveCount: number;
  /** Up to three sample sensitive paths to show in the disclosure, if any. */
  sensitiveSamplePaths: string[];
};

export type BulkRiskDisclosure = {
  tier: BulkRiskTier;
  tone: BulkRiskTone;
  headline: string;
  body: string;
  bullets: string[];
  /** True only when the user must type `confirmPhrase` to enable the confirm button. */
  requiresTypedConfirm: boolean;
  /** Phrase the user must type verbatim (case-insensitive, whitespace-trimmed). */
  confirmPhrase: string;
};

export const BULK_LOW_TIER_THRESHOLD = 5;
export const BULK_HIGH_TIER_THRESHOLD = 10;

/**
 * Resolve the risk tier from the current selection. Sensitive items force
 * `high` even at low counts so the disclosure always calls them out; otherwise
 * the tier scales with the action count and any duplicate retries.
 */
export function resolveBulkRiskTier(stats: BulkSelectionStats): BulkRiskTier {
  if (stats.actionCount <= 0) {
    return "low";
  }
  if (stats.sensitiveCount > 0 || stats.actionCount >= BULK_HIGH_TIER_THRESHOLD) {
    return "high";
  }
  if (stats.duplicateActionCount > 0 || stats.actionCount > BULK_LOW_TIER_THRESHOLD) {
    return "elevated";
  }
  return "low";
}

export function bulkRiskTone(tier: BulkRiskTier): BulkRiskTone {
  if (tier === "high") return "attention";
  if (tier === "elevated") return "amber";
  return "green";
}

/**
 * Build the short phrase the user must retype at the `high` tier.
 * Kept memorable and explicit: `approve 12 reads` / `approve 1 read`.
 */
export function buildBulkConfirmPhrase(actionCount: number): string {
  const safe = Math.max(0, Math.floor(actionCount));
  return `approve ${safe} ${pluralReads(safe)}`;
}

/**
 * Case-insensitive, whitespace-trimmed match for the typed confirmation phrase.
 * Empty phrase input never matches.
 */
export function bulkConfirmMatches(typed: string, phrase: string): boolean {
  const normalize = (value: string) => value.trim().toLowerCase().replace(/\s+/g, " ");
  return normalize(typed) === normalize(phrase) && normalize(typed).length > 0;
}

function pluralReads(count: number): string {
  return count === 1 ? "read" : "reads";
}

function pluralItems(count: number): string {
  return count === 1 ? "item" : "items";
}

/**
 * Build the escalating risk disclosure for a selection. The copy is written for
 * a non-security-expert: it names what is happening, what could go wrong, and
 * exactly what scope the decision covers.
 */
export function buildBulkRiskDisclosure(stats: BulkSelectionStats): BulkRiskDisclosure {
  const tier = resolveBulkRiskTier(stats);
  const phrase = buildBulkConfirmPhrase(stats.actionCount);
  const actionWord = pluralReads(stats.actionCount);

  if (stats.actionCount <= 0) {
    return {
      tier: "low",
      tone: "green",
      headline: "Select read-only file reads to approve together",
      body: "Pick the file reads you have already reviewed. Sensitive paths stay in the queue for individual review.",
      bullets: [],
      requiresTypedConfirm: false,
      confirmPhrase: phrase,
    };
  }

  const bullets: string[] = [
    `Approving ${stats.actionCount} ${actionWord} from ${stats.groupCount} ${pluralItems(stats.groupCount)} lets each retry read its file once.`,
    `Bulk approval never remembers the decision — the same path will ask again next time.`,
  ];

  if (stats.duplicateActionCount > 0) {
    bullets.push(
      `${stats.duplicateActionCount} duplicate ${stats.duplicateActionCount === 1 ? "retry is" : "retries are"} included — make sure the repeats are expected, not a loop.`,
    );
  }

  if (stats.sensitiveCount > 0) {
    const sampleList = stats.sensitiveSamplePaths.slice(0, 3);
    const sampleText = sampleList.length > 0 ? ` Examples: ${sampleList.join(", ")}.` : "";
    bullets.push(
      `${stats.sensitiveCount} sensitive ${stats.sensitiveCount === 1 ? "read stays" : "reads stay"} in the queue and will NOT be approved here.${sampleText}`,
    );
  }

  if (tier === "high") {
    return {
      tier,
      tone: "attention",
      headline: `High-impact bulk approval: ${stats.actionCount} ${actionWord} at once`,
      body:
        stats.sensitiveCount > 0
          ? "You are approving a large batch while sensitive reads sit unapproved in the queue. Mass approval skips opening each request, so a wrong path here is hard to catch later. Re-confirm the type and phrase below."
          : "You are approving a large batch at once. Mass approval skips opening each request, so an unexpected path is hard to catch later. Re-confirm the type and phrase below.",
      bullets,
      requiresTypedConfirm: true,
      confirmPhrase: phrase,
    };
  }

  if (tier === "elevated") {
    return {
      tier,
      tone: "amber",
      headline: `Approving ${stats.actionCount} ${actionWord} at once`,
      body:
        stats.duplicateActionCount > 0
          ? "Some selected reads include duplicate retries. Each retry will read its file once, and the decision is not remembered. Skim the list before confirming."
          : "Each selected retry will read its file once, and the decision is not remembered. Skim the list before confirming.",
      bullets,
      requiresTypedConfirm: false,
      confirmPhrase: phrase,
    };
  }

  return {
    tier,
    tone: "green",
    headline: `Approving ${stats.actionCount} ${actionWord} at once`,
    body: "Each selected retry will read its file once. The decision is not remembered, so these paths will ask again next time.",
    bullets,
    requiresTypedConfirm: false,
    confirmPhrase: phrase,
  };
}
