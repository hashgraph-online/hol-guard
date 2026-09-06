import type { ExtensionCatalogItem, ExtensionTrustClass } from "../../extension-controls-api";
import type { LocalCliItem } from "../../local-cli-api";
import {
  PROTECTION_CATEGORIES,
  protectionCategoryIdForExtension,
  type ProtectionCategoryId,
} from "./protection-categories";

export type CatalogKindFilter = "commands" | "mcp";

export type CatalogFilterState = {
  trusts: ExtensionTrustClass[];
  kinds: CatalogKindFilter[];
  areas: ProtectionCategoryId[];
};

export const EMPTY_CATALOG_FILTERS: CatalogFilterState = {
  trusts: [],
  kinds: [],
  areas: [],
};

export const CATALOG_TRUST_FILTERS: readonly ExtensionTrustClass[] = [
  "first-party",
  "trusted-library",
  "external",
];

export const CATALOG_KIND_FILTERS: readonly CatalogKindFilter[] = ["commands", "mcp"];

export function catalogFiltersActive(filters: CatalogFilterState): boolean {
  return filters.trusts.length > 0 || filters.kinds.length > 0 || filters.areas.length > 0;
}

export function catalogTrustLabel(trust: ExtensionTrustClass): string {
  if (trust === "first-party") return "Built in";
  if (trust === "trusted-library") return "Trusted";
  return "External";
}

export function catalogKindLabel(kind: CatalogKindFilter): string {
  if (kind === "mcp") return "MCP";
  return "Commands";
}

export function catalogItemKind(extension: ExtensionCatalogItem): CatalogKindFilter {
  if (extension.surface === "mcp") return "mcp";
  return "commands";
}

export function toggleCatalogFilterValue<T extends string>(selected: readonly T[], value: T): T[] {
  if (selected.includes(value)) return selected.filter((item) => item !== value);
  return [...selected, value];
}

export function catalogItemMatchesFilters(
  extension: ExtensionCatalogItem,
  filters: CatalogFilterState,
): boolean {
  if (filters.trusts.length > 0 && !filters.trusts.includes(extension.trust_class)) return false;
  if (filters.kinds.length > 0 && !filters.kinds.includes(catalogItemKind(extension))) return false;
  if (filters.areas.length > 0) {
    const area = protectionCategoryIdForExtension(extension);
    if (!filters.areas.includes(area)) return false;
  }
  return true;
}

export function filterCatalogExtensions(
  extensions: readonly ExtensionCatalogItem[],
  filters: CatalogFilterState,
): ExtensionCatalogItem[] {
  if (!catalogFiltersActive(filters)) return [...extensions];
  return extensions.filter((extension) => catalogItemMatchesFilters(extension, filters));
}

export function customItemMatchesKind(
  item: Pick<LocalCliItem, "surface">,
  kinds: readonly CatalogKindFilter[],
): boolean {
  if (kinds.length === 0) return true;
  if (item.surface === "mcp") return kinds.includes("mcp");
  return kinds.includes("commands");
}

export function catalogToolUnit(count: number): string {
  if (count === 1) return "tool";
  return "tools";
}

export function catalogFilterCountCopy(visible: number, total: number, filtering: boolean): string {
  if (!filtering) return `${total} ${catalogToolUnit(total)}`;
  return `${visible} of ${total} ${catalogToolUnit(total)}`;
}

export function catalogFilterChipAriaLabel(label: string, count: number): string {
  return `${label}, ${count} ${catalogToolUnit(count)}`;
}

export function populatedCatalogAreas(
  extensions: readonly ExtensionCatalogItem[],
): ProtectionCategoryId[] {
  const present = new Set<ProtectionCategoryId>();
  for (const extension of extensions) {
    present.add(protectionCategoryIdForExtension(extension));
  }
  return PROTECTION_CATEGORIES.map((category) => category.id).filter((id) => present.has(id));
}

export function populatedCatalogAreaOptions(
  extensions: readonly ExtensionCatalogItem[],
): Array<{ id: ProtectionCategoryId; label: string }> {
  const present = new Set(populatedCatalogAreas(extensions));
  return PROTECTION_CATEGORIES
    .filter((category) => present.has(category.id))
    .map((category) => ({ id: category.id, label: category.label }));
}

export function catalogFilterChipCount(
  extensions: readonly ExtensionCatalogItem[],
  filters: CatalogFilterState,
  patch: Partial<CatalogFilterState>,
): number {
  return filterCatalogExtensions(extensions, { ...filters, ...patch }).length;
}
