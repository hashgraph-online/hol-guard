import type { ExtensionCatalogItem, ExtensionPermission } from "../../extension-controls-api";
import { PROTECTION_CENTER_PERFORMANCE_BUDGETS } from "./protection-performance-budgets";

export type CommandPatternMatch = {
  extension: ExtensionCatalogItem;
  permission: ExtensionPermission;
  score: number;
};

export const COMMAND_PATTERN_DISPLAY_LIMIT = 24;

function patternSearchText(extension: ExtensionCatalogItem, permission: ExtensionPermission): string {
  return [
    permission.label,
    permission.description,
    permission.example_command ?? "",
    permission.family ?? "",
    permission.permission_id,
    extension.name,
    extension.extension_id,
    ...extension.executables,
  ].join(" ").toLowerCase();
}

export function searchCommandPatterns(
  extensions: readonly ExtensionCatalogItem[],
  rawQuery: string,
  limit = COMMAND_PATTERN_DISPLAY_LIMIT,
): CommandPatternMatch[] {
  const normalized = rawQuery.trim().toLowerCase().slice(0, PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchCharacterCap);
  if (!normalized) return [];
  const terms = normalized.split(/\s+/).filter(Boolean).slice(0, PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchTermCap);
  const matches: CommandPatternMatch[] = [];
  for (const extension of extensions) {
    for (const permission of extension.permissions) {
      const text = patternSearchText(extension, permission);
      if (terms.every((term) => text.includes(term))) {
        matches.push({ extension, permission, score: terms.length });
      }
    }
  }
  return matches
    .sort((left, right) =>
      right.permission.risk_tier.localeCompare(left.permission.risk_tier) ||
      left.permission.label.localeCompare(right.permission.label) ||
      left.extension.name.localeCompare(right.extension.name),
    )
    .slice(0, limit);
}
