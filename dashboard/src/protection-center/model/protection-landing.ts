import type { ExtensionCatalogSummary, ExtensionPermission } from "../../extension-controls-api";
import { PROTECTION_CENTER_PERFORMANCE_BUDGETS } from "./protection-performance-budgets";

export type CommandPatternMatch = {
  extension: ExtensionCatalogSummary;
  permission: ExtensionPermission;
  /** Match strength; lower is stronger. 0 names the capability, 2 only mentions it. */
  score: number;
};

export const COMMAND_PATTERN_DISPLAY_LIMIT = 24;

// Ranking bands. A query that appears in the capability's name, label, or
// executable identifies the setting the operator is looking for; a query that
// only appears in prose (for example ".github/workflows" inside a description)
// is an incidental mention and must not outrank the capability it names.
const IDENTITY_MATCH = 0;
const EXAMPLE_MATCH = 1;
const CONTEXT_MATCH = 2;

// Explicit severity order. localeCompare would order the tier names
// alphabetically ("medium" above "critical"), burying the riskiest settings
// at the bottom of the results.
const RISK_TIER_SEVERITY: Record<string, number> = { critical: 3, high: 2, medium: 1, low: 0 };

// Packaged and organization-pushed catalogs speak with the product's voice;
// at equal relevance an extension added locally on this device follows them.
function catalogOriginRank(extension: ExtensionCatalogSummary): number {
  return extension.source === "local-admin" ? 1 : 0;
}

function patternSearchBands(extension: ExtensionCatalogSummary, permission: ExtensionPermission): [string, string, string] {
  return [
    [permission.label, extension.name, extension.extension_id, ...extension.executables].join(" ").toLowerCase(),
    [permission.example_command ?? "", permission.permission_id].join(" ").toLowerCase(),
    [permission.description, permission.family ?? ""].join(" ").toLowerCase(),
  ];
}

function termBand(term: string, bands: [string, string, string]): number {
  if (bands[IDENTITY_MATCH].includes(term)) return IDENTITY_MATCH;
  if (bands[EXAMPLE_MATCH].includes(term)) return EXAMPLE_MATCH;
  return CONTEXT_MATCH;
}

/** The bounded query a pattern search sends: trimmed, lowercased, capped. */
export function commandPatternQuery(rawQuery: string): string {
  const normalized = rawQuery.trim().toLowerCase().slice(0, PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchCharacterCap);
  return normalized.split(/\s+/).filter(Boolean).slice(0, PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchTermCap).join(" ");
}

/**
 * Rank candidate permissions for a query. Candidates come from the catalog's
 * permission search; every query term must still occur in a band.
 */
export function searchCommandPatterns(
  candidates: readonly { extension: ExtensionCatalogSummary; permission: ExtensionPermission }[],
  rawQuery: string,
  limit = COMMAND_PATTERN_DISPLAY_LIMIT,
): CommandPatternMatch[] {
  const query = commandPatternQuery(rawQuery);
  if (!query) return [];
  const terms = query.split(" ");
  const matches: CommandPatternMatch[] = [];
  for (const { extension, permission } of candidates) {
    const bands = patternSearchBands(extension, permission);
    const text = bands.join(" ");
    if (!terms.every((term) => text.includes(term))) continue;
    // The query is as strong as its weakest term: "github export" against a
    // permission whose prose carries "github" and whose example carries
    // "export" scores as a context match.
    const score = Math.max(...terms.map((term) => termBand(term, bands)));
    matches.push({ extension, permission, score });
  }
  return matches
    .sort((left, right) =>
      left.score - right.score ||
      catalogOriginRank(left.extension) - catalogOriginRank(right.extension) ||
      (RISK_TIER_SEVERITY[right.permission.risk_tier] ?? 0) - (RISK_TIER_SEVERITY[left.permission.risk_tier] ?? 0) ||
      left.permission.label.localeCompare(right.permission.label) ||
      left.extension.name.localeCompare(right.extension.name),
    )
    .slice(0, limit);
}
