import type {
  EffectiveExtensionControls,
  ExtensionCatalogItem,
  ExtensionPermission,
  ExtensionRule,
} from "./extension-controls-api";

const EXTENSION_ID_PATTERN = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const RULE_ID_PATTERN = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;

export type ExtensionDetailTab = "overview" | "commands" | "policy" | "test-lab" | "activity";
export type ExtensionDetailRiskFilter = "all" | "low" | "medium" | "high" | "critical";
export type ExtensionDetailStateFilter = "all" | "allowed" | "blocked";
export type ExtensionDetailTriFilter = "all" | "yes" | "no";
export type ExtensionDetailSourceFilter = "all" | "built-in" | "local-admin" | "signed-cloud";
export type ExtensionDetailTypeFilter = "all" | "permission" | "rule";
export type ExtensionDetailSort = "name" | "risk" | "id";

export type ExtensionDetailUrlState = {
  tab: ExtensionDetailTab;
  query: string;
  risk: ExtensionDetailRiskFilter;
  state: ExtensionDetailStateFilter;
  configurable: ExtensionDetailTriFilter;
  source: ExtensionDetailSourceFilter;
  deprecated: ExtensionDetailTriFilter;
  type: ExtensionDetailTypeFilter;
  sort: ExtensionDetailSort;
  ruleId: string | null;
};

export const DEFAULT_EXTENSION_DETAIL_URL_STATE: ExtensionDetailUrlState = {
  tab: "overview",
  query: "",
  risk: "all",
  state: "all",
  configurable: "all",
  source: "all",
  deprecated: "all",
  type: "all",
  sort: "name",
  ruleId: null,
};

export type ExtensionRoute =
  | { kind: "overview" }
  | { kind: "detail"; extensionId: string }
  | { kind: "invalid" };

function oneOf<T extends string>(value: string | null, allowed: readonly T[], fallback: T): T {
  return value !== null && allowed.includes(value as T) ? value as T : fallback;
}

export function parseExtensionRoute(pathname: string): ExtensionRoute {
  if (pathname === "/extensions" || pathname === "/extensions/") return { kind: "overview" };
  if (!pathname.startsWith("/extensions/")) return { kind: "invalid" };
  const encoded = pathname.slice("/extensions/".length);
  if (!encoded || encoded.includes("/")) return { kind: "invalid" };
  try {
    const decoded = decodeURIComponent(encoded).trim().toLowerCase();
    if (!EXTENSION_ID_PATTERN.test(decoded)) return { kind: "invalid" };
    return { kind: "detail", extensionId: decoded };
  } catch {
    return { kind: "invalid" };
  }
}

export function readExtensionDetailUrlState(search: string): ExtensionDetailUrlState {
  const params = new URLSearchParams(search);
  const rawQuery = params.get("q") ?? "";
  const query = rawQuery.slice(0, 160);
  const rawRule = params.get("rule")?.trim().toLowerCase() ?? null;
  const ruleId = rawRule && RULE_ID_PATTERN.test(rawRule) ? rawRule : null;
  return {
    tab: oneOf(params.get("tab"), ["overview", "commands", "policy", "test-lab", "activity"] as const, "overview"),
    query,
    risk: oneOf(params.get("risk"), ["all", "low", "medium", "high", "critical"] as const, "all"),
    state: oneOf(params.get("state"), ["all", "allowed", "blocked"] as const, "all"),
    configurable: oneOf(params.get("configurable"), ["all", "yes", "no"] as const, "all"),
    source: oneOf(params.get("source"), ["all", "built-in", "local-admin", "signed-cloud"] as const, "all"),
    deprecated: oneOf(params.get("deprecated"), ["all", "yes", "no"] as const, "all"),
    type: oneOf(params.get("type"), ["all", "permission", "rule"] as const, "all"),
    sort: oneOf(params.get("sort"), ["name", "risk", "id"] as const, "name"),
    ruleId,
  };
}

export function extensionDetailSearch(state: ExtensionDetailUrlState): string {
  const params = new URLSearchParams();
  if (state.tab !== "overview") params.set("tab", state.tab);
  if (state.query.trim()) params.set("q", state.query.trim().slice(0, 160));
  if (state.risk !== "all") params.set("risk", state.risk);
  if (state.state !== "all") params.set("state", state.state);
  if (state.configurable !== "all") params.set("configurable", state.configurable);
  if (state.source !== "all") params.set("source", state.source);
  if (state.deprecated !== "all") params.set("deprecated", state.deprecated);
  if (state.type !== "all") params.set("type", state.type);
  if (state.sort !== "name") params.set("sort", state.sort);
  if (state.ruleId && RULE_ID_PATTERN.test(state.ruleId)) params.set("rule", state.ruleId);
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}

export function extensionDetailHref(extensionId: string, state = DEFAULT_EXTENSION_DETAIL_URL_STATE): string {
  const canonical = extensionId.trim().toLowerCase();
  if (!EXTENSION_ID_PATTERN.test(canonical)) return "/extensions";
  return `/extensions/${encodeURIComponent(canonical)}${extensionDetailSearch(state)}`;
}

export function canonicalExtensionId(catalog: ExtensionCatalogItem[], candidate: string | null): string | null {
  if (!candidate) return null;
  const normalized = candidate.trim().toLowerCase();
  const direct = catalog.find((extension) => extension.extension_id === normalized);
  if (direct) return direct.extension_id;
  return catalog.find((extension) => extension.aliases.includes(normalized))?.extension_id ?? null;
}

export function explicitControlState(
  effective: EffectiveExtensionControls,
  kind: "extension" | "permission",
  targetId: string,
): "enabled" | "disabled" | null {
  const projected = kind === "extension"
    ? effective.projection?.extensions.find((item) => item.extension_id === targetId)?.local_state
    : effective.projection?.permissions.find((item) => item.permission_id === targetId)?.local_state;
  if (projected) return projected === "inherited" ? null : projected;
  return effective.controls.find(
    (control) => control.target.kind === kind && control.target.target_id === targetId,
  )?.state ?? null;
}

function managedExplicitControlState(
  effective: EffectiveExtensionControls,
  kind: "extension" | "permission",
  targetId: string,
): "enabled" | "disabled" | null {
  const projected = kind === "extension"
    ? effective.projection?.extensions.find((item) => item.extension_id === targetId)?.managed_state
    : effective.projection?.permissions.find((item) => item.permission_id === targetId)?.managed_state;
  if (projected) return projected === "inherited" ? null : projected;
  for (const layer of effective.layers) {
    if (layer.kind !== "signed-cloud") continue;
    const control = layer.controls.find((item) => item.target_kind === kind && item.target_id === targetId);
    if (control) return control.state;
  }
  return null;
}

export function extensionEffectiveState(
  effective: EffectiveExtensionControls,
  extension: ExtensionCatalogItem,
): "enabled" | "disabled" {
  const projected = effective.projection?.extensions.find((item) => item.extension_id === extension.extension_id);
  if (projected) return projected.effective_state === "allowed" ? "enabled" : "disabled";
  if (effective.health !== "protected") return "disabled";
  if (effective.global_lockdown) return "disabled";
  if (extension.required) return "enabled";
  return explicitControlState(effective, "extension", extension.extension_id) ?? "enabled";
}

export function permissionEffectiveState(
  effective: EffectiveExtensionControls,
  extension: ExtensionCatalogItem,
  permission: ExtensionPermission,
): "enabled" | "disabled" {
  const projected = effective.projection?.permissions.find((item) => item.permission_id === permission.permission_id);
  if (projected) return projected.effective_state === "allowed" ? "enabled" : "disabled";
  if (extensionEffectiveState(effective, extension) === "disabled") return "disabled";
  if (!permission.configurable) return permission.default_enabled ? "enabled" : "disabled";
  return explicitControlState(effective, "permission", permission.permission_id) ??
    (permission.default_enabled ? "enabled" : "disabled");
}

export function extensionStateLabel(
  effective: EffectiveExtensionControls,
  extension: ExtensionCatalogItem,
): "Allowed" | "Blocked" | "Required" | "Managed" | "Lockdown" | "Unavailable" {
  if (effective.health !== "protected") return "Unavailable";
  if (effective.global_lockdown) return "Lockdown";
  if (managedExplicitControlState(effective, "extension", extension.extension_id) !== null) return "Managed";
  if (extension.required) return "Required";
  return extensionEffectiveState(effective, extension) === "enabled" ? "Allowed" : "Blocked";
}

export function permissionStateLabel(
  effective: EffectiveExtensionControls,
  extension: ExtensionCatalogItem,
  permission: ExtensionPermission,
): "Allowed" | "Blocked" | "Required" | "Managed" | "Inherited" | "Lockdown" | "Unavailable" {
  if (effective.health !== "protected") return "Unavailable";
  if (effective.global_lockdown) return "Lockdown";
  if (managedExplicitControlState(effective, "permission", permission.permission_id) !== null) return "Managed";
  if (!permission.configurable) return "Required";
  const projected = effective.projection?.permissions.find((item) => item.permission_id === permission.permission_id);
  const localState = projected?.local_state ?? (explicitControlState(effective, "permission", permission.permission_id) ?? "inherited");
  const effectiveState = permissionEffectiveState(effective, extension, permission);
  if (localState === "inherited") return effectiveState === "enabled" ? "Inherited" : "Blocked";
  return effectiveState === "enabled" ? "Allowed" : "Blocked";
}

export function controlProvenance(
  effective: EffectiveExtensionControls,
  kind: "extension" | "permission",
  targetId: string,
): string[] {
  const projected = kind === "extension"
    ? effective.projection?.extensions.find((item) => item.extension_id === targetId)
    : effective.projection?.permissions.find((item) => item.permission_id === targetId);
  if (projected) {
    const sources: string[] = [];
    if (effective.global_lockdown) sources.push("Global lockdown");
    if (projected.managed_state !== "inherited") sources.push("Signed cloud policy");
    if (projected.local_state !== "inherited") sources.push("Local administrator");
    if (sources.length === 0) sources.push("Built-in default");
    return sources;
  }
  const sources: string[] = [];
  if (effective.global_lockdown) sources.push("Global lockdown");
  for (const layer of effective.layers) {
    if (layer.controls.some((control) => control.target_kind === kind && control.target_id === targetId)) {
      sources.push(layer.kind === "signed-cloud" ? "Signed cloud policy" : "Local administrator");
    }
  }
  if (sources.length === 0) sources.push("Built-in default");
  return sources;
}

export function permissionForRule(extension: ExtensionCatalogItem, rule: ExtensionRule): ExtensionPermission | null {
  return extension.permissions.find((permission) => permission.rule_ids.includes(rule.rule_id)) ?? null;
}

export type RelationSummary = {
  dependencies: ExtensionPermission[];
  conflicts: ExtensionPermission[];
  implied: ExtensionPermission[];
  missing: string[];
};

export function permissionRelations(extension: ExtensionCatalogItem, permission: ExtensionPermission): RelationSummary {
  const byId = new Map(extension.permissions.map((item) => [item.permission_id, item]));
  const resolve = (ids: string[]) => ids.map((id) => byId.get(id)).filter((item): item is ExtensionPermission => Boolean(item));
  const referenced = [...permission.dependencies, ...permission.conflicts, ...permission.implied_permissions];
  return {
    dependencies: resolve(permission.dependencies),
    conflicts: resolve(permission.conflicts),
    implied: resolve(permission.implied_permissions),
    missing: referenced.filter((id) => !byId.has(id)),
  };
}

const RISK_RANK = { critical: 4, high: 3, medium: 2, low: 1 } as const;

function queryMatch(values: string[], query: string): boolean {
  const tokens = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return true;
  const haystack = values.join(" ").toLowerCase();
  return tokens.every((token) => haystack.includes(token));
}

export function filterDetailPermissions(
  extension: ExtensionCatalogItem,
  effective: EffectiveExtensionControls,
  state: ExtensionDetailUrlState,
): ExtensionPermission[] {
  if (state.type === "rule") return [];
  const items = extension.permissions.filter((permission) => {
    if (!queryMatch([permission.label, permission.permission_id, permission.description, ...permission.action_classes, ...permission.typed_capabilities, ...permission.rule_ids], state.query)) return false;
    if (state.risk !== "all" && permission.risk_tier !== state.risk) return false;
    const enabled = permissionEffectiveState(effective, extension, permission) === "enabled";
    if (state.state === "allowed" && !enabled) return false;
    if (state.state === "blocked" && enabled) return false;
    if (state.configurable === "yes" && !permission.configurable) return false;
    if (state.configurable === "no" && permission.configurable) return false;
    if (state.source !== "all" && extension.source !== state.source) return false;
    if (state.deprecated === "yes" && !permission.deprecated) return false;
    if (state.deprecated === "no" && permission.deprecated) return false;
    return true;
  });
  return items.sort((left, right) => {
    if (state.sort === "id") return left.permission_id.localeCompare(right.permission_id);
    if (state.sort === "risk") return RISK_RANK[right.risk_tier] - RISK_RANK[left.risk_tier] || left.label.localeCompare(right.label);
    return left.label.localeCompare(right.label);
  });
}

export function filterDetailRules(
  extension: ExtensionCatalogItem,
  effective: EffectiveExtensionControls,
  state: ExtensionDetailUrlState,
): ExtensionRule[] {
  if (state.type === "permission") return [];
  const permissionByRule = new Map<string, ExtensionPermission>();
  for (const permission of extension.permissions) {
    for (const ruleId of permission.rule_ids) {
      if (!permissionByRule.has(ruleId)) permissionByRule.set(ruleId, permission);
    }
  }
  const items = extension.rules.filter((rule) => {
    const permission = permissionByRule.get(rule.rule_id) ?? null;
    if (!queryMatch([rule.title, rule.rule_id, rule.description, rule.matcher_kind, ...rule.action_classes, ...rule.risk_classes, ...(permission ? [permission.label, permission.permission_id] : [])], state.query)) return false;
    if (state.risk !== "all" && rule.severity !== state.risk) return false;
    const enabled = permission ? permissionEffectiveState(effective, extension, permission) === "enabled" : extensionEffectiveState(effective, extension) === "enabled";
    if (state.state === "allowed" && !enabled) return false;
    if (state.state === "blocked" && enabled) return false;
    if (state.configurable !== "all" && permission) {
      if (state.configurable === "yes" && !permission.configurable) return false;
      if (state.configurable === "no" && permission.configurable) return false;
    }
    if (state.source !== "all" && extension.source !== state.source) return false;
    const deprecated = permission?.deprecated ?? false;
    if (state.deprecated === "yes" && !deprecated) return false;
    if (state.deprecated === "no" && deprecated) return false;
    return true;
  });
  return items.sort((left, right) => {
    if (state.sort === "id") return left.rule_id.localeCompare(right.rule_id);
    if (state.sort === "risk") return RISK_RANK[right.severity] - RISK_RANK[left.severity] || left.title.localeCompare(right.title);
    return left.title.localeCompare(right.title);
  });
}

export function treatmentLabel(value: string): string {
  const labels: Record<string, string> = {
    allow: "Allow",
    warn: "Warn",
    review: "Review",
    "require-reapproval": "Require reapproval",
    "sandbox-required": "Require sandbox",
    block: "Block",
    required: "Required",
    enforce: "Enforce",
    monitor: "Monitor",
    disabled: "Disabled",
  };
  return labels[value] ?? value.replaceAll("-", " ");
}
