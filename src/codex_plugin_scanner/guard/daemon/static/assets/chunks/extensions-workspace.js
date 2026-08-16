import { an as fetchExtensionControlApi, r as reactExports, j as jsxRuntimeExports, Z as HiMiniLockClosed, J as HiMiniExclamationTriangle, ao as HiMiniArrowPath, o as HiMiniShieldCheck, ap as HiMiniInformationCircle, aq as isApprovalProofSubmitDisabled, w as HiMiniXMark, ar as ApprovalProofFieldInputs, as as buildApprovalProofCredentials, l as HiMiniCheckCircle, c as HiMiniChevronRight, y as HiMiniChevronDown, ak as HiMiniMagnifyingGlass, N as HiMiniWrenchScrewdriver, at as HiMiniArrowLeft, U as HiMiniClipboardDocumentCheck, V as HiMiniClipboard, au as WorkspacePageHeader } from "../guard-dashboard.js";
import { u as useResolvedApprovalGate, A as ApprovalProofModal } from "./use-resolved-approval-gate.js";
const EXTENSION_ID_PATTERN = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const RULE_ID_PATTERN = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const DEFAULT_EXTENSION_DETAIL_URL_STATE = {
  tab: "overview",
  query: "",
  risk: "all",
  state: "all",
  configurable: "all",
  source: "all",
  deprecated: "all",
  type: "all",
  sort: "name",
  ruleId: null
};
function oneOf(value, allowed, fallback) {
  return value !== null && allowed.includes(value) ? value : fallback;
}
function parseExtensionRoute(pathname) {
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
function readExtensionDetailUrlState(search) {
  const params = new URLSearchParams(search);
  const rawQuery = params.get("q") ?? "";
  const query = rawQuery.slice(0, 160);
  const rawRule = params.get("rule")?.trim().toLowerCase() ?? null;
  const ruleId = rawRule && RULE_ID_PATTERN.test(rawRule) ? rawRule : null;
  return {
    tab: oneOf(params.get("tab"), ["overview", "commands", "policy", "test-lab", "activity"], "overview"),
    query,
    risk: oneOf(params.get("risk"), ["all", "low", "medium", "high", "critical"], "all"),
    state: oneOf(params.get("state"), ["all", "allowed", "blocked"], "all"),
    configurable: oneOf(params.get("configurable"), ["all", "yes", "no"], "all"),
    source: oneOf(params.get("source"), ["all", "built-in", "local-admin", "signed-cloud"], "all"),
    deprecated: oneOf(params.get("deprecated"), ["all", "yes", "no"], "all"),
    type: oneOf(params.get("type"), ["all", "permission", "rule"], "all"),
    sort: oneOf(params.get("sort"), ["name", "risk", "id"], "name"),
    ruleId
  };
}
function extensionDetailSearch(state) {
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
function extensionDetailHref(extensionId, state = DEFAULT_EXTENSION_DETAIL_URL_STATE) {
  const canonical = extensionId.trim().toLowerCase();
  if (!EXTENSION_ID_PATTERN.test(canonical)) return "/extensions";
  return `/extensions/${encodeURIComponent(canonical)}${extensionDetailSearch(state)}`;
}
function canonicalExtensionId(catalog, candidate) {
  if (!candidate) return null;
  const normalized = candidate.trim().toLowerCase();
  const direct = catalog.find((extension2) => extension2.extension_id === normalized);
  if (direct) return direct.extension_id;
  return catalog.find((extension2) => extension2.aliases.includes(normalized))?.extension_id ?? null;
}
function explicitControlState(effective, kind, targetId2) {
  const projected = kind === "extension" ? effective.projection?.extensions.find((item) => item.extension_id === targetId2)?.local_state : effective.projection?.permissions.find((item) => item.permission_id === targetId2)?.local_state;
  if (projected) return projected === "inherited" ? null : projected;
  return effective.controls.find(
    (control) => control.target.kind === kind && control.target.target_id === targetId2
  )?.state ?? null;
}
function managedExplicitControlState(effective, kind, targetId2) {
  const projected = effective.projection?.extensions.find((item) => item.extension_id === targetId2)?.managed_state;
  if (projected) return projected === "inherited" ? null : projected;
  for (const layer of effective.layers) {
    if (layer.kind !== "signed-cloud") continue;
    const control = layer.controls.find((item) => item.target_kind === kind && item.target_id === targetId2);
    if (control) return control.state;
  }
  return null;
}
function extensionEffectiveState(effective, extension2) {
  const projected = effective.projection?.extensions.find((item) => item.extension_id === extension2.extension_id);
  if (projected) return projected.effective_state === "allowed" ? "enabled" : "disabled";
  if (effective.health !== "protected") return "disabled";
  if (effective.global_lockdown) return "disabled";
  if (extension2.required) return "enabled";
  return explicitControlState(effective, "extension", extension2.extension_id) ?? "enabled";
}
function extensionStateLabel(effective, extension2) {
  if (effective.health !== "protected") return "Unavailable";
  if (effective.global_lockdown) return "Lockdown";
  if (managedExplicitControlState(effective, "extension", extension2.extension_id) !== null) return "Managed";
  if (extension2.required) return "Required";
  return extensionEffectiveState(effective, extension2) === "enabled" ? "Allowed" : "Blocked";
}
function controlProvenance(effective, kind, targetId2) {
  const projected = kind === "extension" ? effective.projection?.extensions.find((item) => item.extension_id === targetId2) : effective.projection?.permissions.find((item) => item.permission_id === targetId2);
  if (projected) {
    const sources2 = [];
    if (effective.global_lockdown) sources2.push("Global lockdown");
    if (projected.managed_state !== "inherited") sources2.push("Signed cloud policy");
    if (projected.local_state !== "inherited") sources2.push("Local administrator");
    if (sources2.length === 0) sources2.push("Built-in default");
    return sources2;
  }
  const sources = [];
  if (effective.global_lockdown) sources.push("Global lockdown");
  for (const layer of effective.layers) {
    if (layer.controls.some((control) => control.target_kind === kind && control.target_id === targetId2)) {
      sources.push(layer.kind === "signed-cloud" ? "Signed cloud policy" : "Local administrator");
    }
  }
  if (sources.length === 0) sources.push("Built-in default");
  return sources;
}
function permissionForRule(extension2, rule2) {
  return extension2.permissions.find((permission2) => permission2.rule_ids.includes(rule2.rule_id)) ?? null;
}
function treatmentLabel(value) {
  const labels = {
    allow: "Allow",
    warn: "Warn",
    review: "Review",
    "require-reapproval": "Require reapproval",
    "sandbox-required": "Require sandbox",
    block: "Block",
    required: "Required",
    enforce: "Enforce",
    monitor: "Monitor",
    disabled: "Disabled"
  };
  return labels[value] ?? value.replaceAll("-", " ");
}
function familyHeading(permissions) {
  const examples = permissions.map((permission2) => permission2.example_command).filter((example) => Boolean(example)).map((example) => example.split(/\s+/));
  if (!examples.length) return permissions[0]?.label ?? "";
  const first = examples[0];
  const shared = [];
  for (let index = 0; index < first.length; index += 1) {
    const token = first[index];
    if (examples.every((parts) => parts[index] === token)) shared.push(token);
    else break;
  }
  return shared.length ? shared.join(" ") : permissions[0]?.label ?? "";
}
function groupPermissionsByFamily(permissions) {
  const byFamily = /* @__PURE__ */ new Map();
  const ungrouped = [];
  for (const permission2 of permissions) {
    if (!permission2.family) ungrouped.push(permission2);
    else {
      const members = byFamily.get(permission2.family) ?? [];
      members.push(permission2);
      byFamily.set(permission2.family, members);
    }
  }
  const families = [...byFamily.entries()].map(([family, members]) => ({ family, heading: familyHeading(members), permissions: members })).sort((left, right) => left.family.localeCompare(right.family));
  return { ungrouped, families };
}
const DIGEST$2 = /^[a-f0-9]{64}$/;
const EXTENSION_ID$1 = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const PERMISSION_ID$1 = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const MAX_EXTENSIONS = 512;
const MAX_PERMISSIONS = 4096;
const MAX_REASONS = 64;
function record$3(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`Invalid ${label}`);
  return value;
}
function text(value, label, max = 256) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) throw new Error(`Invalid ${label}`);
  return value;
}
function integer$2(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid ${label}`);
  return value;
}
function boolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`Invalid ${label}`);
  return value;
}
function enumValue$1(value, label, values) {
  const candidate = text(value, label, 64);
  if (!values.includes(candidate)) throw new Error(`Invalid ${label}`);
  return candidate;
}
function id$1(value, label, pattern) {
  const candidate = text(value, label).toLowerCase();
  if (!pattern.test(candidate)) throw new Error(`Invalid ${label}`);
  return candidate;
}
function reasons(value, label) {
  if (!Array.isArray(value) || value.length > MAX_REASONS) throw new Error(`Invalid ${label}`);
  return value.map((item, index) => text(item, `${label}[${index}]`, 128));
}
function extensionItem(value, label) {
  const item = record$3(value, label);
  return {
    extension_id: id$1(item.extension_id, `${label}.extension_id`, EXTENSION_ID$1),
    effective_state: enumValue$1(item.effective_state, `${label}.effective_state`, ["allowed", "blocked"]),
    local_state: enumValue$1(item.local_state, `${label}.local_state`, ["inherited", "enabled", "disabled"]),
    managed_state: enumValue$1(item.managed_state, `${label}.managed_state`, ["inherited", "enabled", "disabled"]),
    required: boolean(item.required, `${label}.required`),
    reason_codes: reasons(item.reason_codes, `${label}.reason_codes`)
  };
}
function permissionItem(value, label) {
  const item = record$3(value, label);
  return {
    permission_id: id$1(item.permission_id, `${label}.permission_id`, PERMISSION_ID$1),
    extension_id: id$1(item.extension_id, `${label}.extension_id`, EXTENSION_ID$1),
    effective_state: enumValue$1(item.effective_state, `${label}.effective_state`, ["allowed", "blocked"]),
    local_state: enumValue$1(item.local_state, `${label}.local_state`, ["inherited", "enabled", "disabled"]),
    managed_state: enumValue$1(item.managed_state, `${label}.managed_state`, ["inherited", "enabled", "disabled"]),
    configurable: boolean(item.configurable, `${label}.configurable`),
    fixed_reason: item.fixed_reason === null ? null : text(item.fixed_reason, `${label}.fixed_reason`, 2048),
    reason_codes: reasons(item.reason_codes, `${label}.reason_codes`)
  };
}
function normalizeEffectiveExtensionControlProjection(value) {
  const root = record$3(value, "extension projection");
  const schemaVersion = text(root.schema_version, "projection.schema_version", 128);
  if (schemaVersion !== "guard.daemon.extension-control-projection.v1") throw new Error("Invalid extension projection schema");
  const digest2 = text(root.catalog_digest, "projection.catalog_digest", 64);
  if (!DIGEST$2.test(digest2)) throw new Error("Invalid projection.catalog_digest");
  if (!Array.isArray(root.extensions) || root.extensions.length > MAX_EXTENSIONS) throw new Error("Invalid projection.extensions");
  if (!Array.isArray(root.permissions) || root.permissions.length > MAX_PERMISSIONS) throw new Error("Invalid projection.permissions");
  const extensions = root.extensions.map((item, index) => extensionItem(item, `projection.extensions[${index}]`));
  const permissions = root.permissions.map((item, index) => permissionItem(item, `projection.permissions[${index}]`));
  if (new Set(extensions.map((item) => item.extension_id)).size !== extensions.length) throw new Error("Duplicate projection extension ID");
  if (new Set(permissions.map((item) => item.permission_id)).size !== permissions.length) throw new Error("Duplicate projection permission ID");
  return {
    schema_version: "guard.daemon.extension-control-projection.v1",
    revision: integer$2(root.revision, "projection.revision"),
    catalog_digest: digest2,
    health: enumValue$1(root.health, "projection.health", ["unenrolled", "protected", "tampered", "degraded-unacknowledged", "degraded-acknowledged", "recovery-required"]),
    extensions,
    permissions
  };
}
const EXTENSION_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const PERMISSION_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const RULE_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const DIGEST$1 = /^[a-f0-9]{64}$/;
const VERSION = /^[1-9][0-9]*\.[0-9]+\.[0-9]+$/;
const EXTENSION_CLIENT_LIMITS = Object.freeze({
  extensions: 256,
  rulesPerExtension: 1024,
  permissionsPerExtension: 1024,
  relationshipIds: 1024,
  controls: 4096,
  layers: 16,
  failures: 256,
  stringLength: 8192
});
class ExtensionControlProtocolError extends Error {
  constructor(message) {
    super(`Invalid extension-control response: ${message}`);
  }
}
function record$2(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ExtensionControlProtocolError(`${label} must be an object`);
  }
  return value;
}
function array(value, label, max) {
  if (!Array.isArray(value)) throw new ExtensionControlProtocolError(`${label} must be an array`);
  if (value.length > max) throw new ExtensionControlProtocolError(`${label} exceeds ${max} items`);
  return value;
}
function string$1(value, label, allowEmpty = false) {
  if (typeof value !== "string") throw new ExtensionControlProtocolError(`${label} must be a string`);
  if (value.length > EXTENSION_CLIENT_LIMITS.stringLength) throw new ExtensionControlProtocolError(`${label} is too long`);
  if (!allowEmpty && value.trim().length === 0) throw new ExtensionControlProtocolError(`${label} is required`);
  return value;
}
function optionalString(value, label) {
  if (value === null) return null;
  return string$1(value, label);
}
function catalogText(value) {
  return typeof value === "string" && value.trim() ? value : null;
}
function bool$1(value, label) {
  if (typeof value !== "boolean") throw new ExtensionControlProtocolError(`${label} must be boolean`);
  return value;
}
function integer$1(value, label, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) {
    throw new ExtensionControlProtocolError(`${label} must be an integer >= ${min}`);
  }
  return value;
}
function enumValue(value, label, values) {
  const candidate = string$1(value, label);
  if (!values.includes(candidate)) throw new ExtensionControlProtocolError(`${label} has unsupported value`);
  return candidate;
}
function id(value, label, pattern) {
  const candidate = string$1(value, label).trim().toLowerCase();
  if (!pattern.test(candidate)) throw new ExtensionControlProtocolError(`${label} is not canonical`);
  return candidate;
}
function digest$1(value, label) {
  const candidate = string$1(value, label).trim().toLowerCase();
  if (!DIGEST$1.test(candidate)) throw new ExtensionControlProtocolError(`${label} must be a SHA-256 digest`);
  return candidate;
}
function version(value, label) {
  const candidate = string$1(value, label);
  if (!VERSION.test(candidate)) throw new ExtensionControlProtocolError(`${label} is not a semantic implementation version`);
  return candidate;
}
function stringList$1(value, label, max = EXTENSION_CLIENT_LIMITS.relationshipIds) {
  return array(value, label, max).map((item, index) => string$1(item, `${label}[${index}]`));
}
function idList$1(value, label, pattern, max = EXTENSION_CLIENT_LIMITS.relationshipIds) {
  const items = array(value, label, max).map((item, index) => id(item, `${label}[${index}]`, pattern));
  if (new Set(items).size !== items.length) throw new ExtensionControlProtocolError(`${label} contains duplicates`);
  return items;
}
function safeVariant(value, label) {
  const item = record$2(value, label);
  return {
    variant_id: string$1(item.variant_id, `${label}.variant_id`),
    title: string$1(item.title, `${label}.title`),
    matcher_kind: string$1(item.matcher_kind, `${label}.matcher_kind`)
  };
}
function rule(value, extensionId, label) {
  const item = record$2(value, label);
  const ruleId = id(item.rule_id, `${label}.rule_id`, RULE_ID);
  if (!ruleId.startsWith(`${extensionId}.`)) throw new ExtensionControlProtocolError(`${label}.rule_id belongs to another extension`);
  const rawVersion = item.rule_version;
  if (!(typeof rawVersion === "string" || Number.isSafeInteger(rawVersion))) {
    throw new ExtensionControlProtocolError(`${label}.rule_version must be string or integer`);
  }
  return {
    rule_id: ruleId,
    rule_version: rawVersion,
    title: string$1(item.title, `${label}.title`),
    description: string$1(item.description, `${label}.description`),
    severity: enumValue(item.severity, `${label}.severity`, ["low", "medium", "high", "critical"]),
    risk_classes: stringList$1(item.risk_classes, `${label}.risk_classes`),
    action_classes: stringList$1(item.action_classes, `${label}.action_classes`),
    safer_alternatives: stringList$1(item.safer_alternatives, `${label}.safer_alternatives`),
    default_mode: enumValue(item.default_mode, `${label}.default_mode`, ["required", "enforce", "review", "monitor", "disabled"]),
    matcher_kind: string$1(item.matcher_kind, `${label}.matcher_kind`),
    safe_variants: array(item.safe_variants, `${label}.safe_variants`, EXTENSION_CLIENT_LIMITS.relationshipIds).map((entry, index) => safeVariant(entry, `${label}.safe_variants[${index}]`)),
    compatibility_fallback: bool$1(item.compatibility_fallback, `${label}.compatibility_fallback`)
  };
}
function permission(value, extensionId, label) {
  const item = record$2(value, label);
  const permissionId = id(item.permission_id, `${label}.permission_id`, PERMISSION_ID);
  const owner = id(item.extension_id, `${label}.extension_id`, EXTENSION_ID);
  if (owner !== extensionId || !permissionId.startsWith(`${extensionId}.permission.`)) {
    throw new ExtensionControlProtocolError(`${label} belongs to another extension`);
  }
  const replacement = item.replacement_permission_id === null ? null : id(item.replacement_permission_id, `${label}.replacement_permission_id`, PERMISSION_ID);
  return {
    permission_id: permissionId,
    schema_version: integer$1(item.schema_version, `${label}.schema_version`, 1),
    extension_id: owner,
    implementation_version: version(item.implementation_version, `${label}.implementation_version`),
    label: string$1(item.label, `${label}.label`),
    description: string$1(item.description, `${label}.description`),
    risk_tier: enumValue(item.risk_tier, `${label}.risk_tier`, ["low", "medium", "high", "critical"]),
    baseline_floor: enumValue(item.baseline_floor, `${label}.baseline_floor`, ["allow", "warn", "review", "require-reapproval", "sandbox-required", "block"]),
    default_enabled: bool$1(item.default_enabled, `${label}.default_enabled`),
    configurable: bool$1(item.configurable, `${label}.configurable`),
    fixed_reason: optionalString(item.fixed_reason, `${label}.fixed_reason`),
    typed_capabilities: stringList$1(item.typed_capabilities, `${label}.typed_capabilities`),
    action_classes: stringList$1(item.action_classes, `${label}.action_classes`),
    rule_ids: idList$1(item.rule_ids, `${label}.rule_ids`, RULE_ID),
    dependencies: idList$1(item.dependencies, `${label}.dependencies`, PERMISSION_ID),
    conflicts: idList$1(item.conflicts, `${label}.conflicts`, PERMISSION_ID),
    implied_permissions: idList$1(item.implied_permissions, `${label}.implied_permissions`, PERMISSION_ID),
    introduced_version: version(item.introduced_version, `${label}.introduced_version`),
    deprecated: bool$1(item.deprecated, `${label}.deprecated`),
    replacement_permission_id: replacement,
    safer_guidance: stringList$1(item.safer_guidance, `${label}.safer_guidance`),
    example_command: catalogText(item.example_command),
    family: catalogText(item.family)
  };
}
function extension(value, label) {
  const item = record$2(value, label);
  const extensionId = id(item.extension_id, `${label}.extension_id`, EXTENSION_ID);
  const rules = array(item.rules, `${label}.rules`, EXTENSION_CLIENT_LIMITS.rulesPerExtension).map((entry, index) => rule(entry, extensionId, `${label}.rules[${index}]`));
  const permissions = array(item.permissions, `${label}.permissions`, EXTENSION_CLIENT_LIMITS.permissionsPerExtension).map((entry, index) => permission(entry, extensionId, `${label}.permissions[${index}]`));
  const ruleIds = rules.map((entry) => entry.rule_id);
  const permissionIds = permissions.map((entry) => entry.permission_id);
  if (new Set(ruleIds).size !== ruleIds.length) throw new ExtensionControlProtocolError(`${label}.rules contains duplicate rule IDs`);
  if (new Set(permissionIds).size !== permissionIds.length) throw new ExtensionControlProtocolError(`${label}.permissions contains duplicate permission IDs`);
  const knownRules = new Set(ruleIds);
  for (const spec of permissions) {
    for (const ruleId of spec.rule_ids) {
      if (!knownRules.has(ruleId)) throw new ExtensionControlProtocolError(`${label} permission references unknown rule ${ruleId}`);
    }
  }
  const ruleCount = integer$1(item.rule_count, `${label}.rule_count`);
  const permissionCount = integer$1(item.permission_count, `${label}.permission_count`);
  if (ruleCount !== rules.length || permissionCount !== permissions.length) {
    throw new ExtensionControlProtocolError(`${label} count metadata does not match payload`);
  }
  return {
    schema_version: integer$1(item.schema_version, `${label}.schema_version`, 1),
    extension_id: extensionId,
    name: string$1(item.name, `${label}.name`),
    description: string$1(item.description, `${label}.description`),
    enabled: bool$1(item.enabled, `${label}.enabled`),
    required: bool$1(item.required, `${label}.required`),
    source: enumValue(item.source, `${label}.source`, ["built-in", "local-admin", "signed-cloud"]),
    version: version(item.version, `${label}.version`),
    aliases: idList$1(item.aliases, `${label}.aliases`, EXTENSION_ID),
    dependencies: idList$1(item.dependencies, `${label}.dependencies`, EXTENSION_ID),
    conflicts: idList$1(item.conflicts, `${label}.conflicts`, EXTENSION_ID),
    delegated_protection: optionalString(item.delegated_protection, `${label}.delegated_protection`),
    ecosystem_ids: stringList$1(item.ecosystem_ids, `${label}.ecosystem_ids`),
    executables: stringList$1(item.executables, `${label}.executables`),
    project_markers: stringList$1(item.project_markers, `${label}.project_markers`),
    reference_urls: stringList$1(item.reference_urls, `${label}.reference_urls`),
    action_classes: stringList$1(item.action_classes, `${label}.action_classes`),
    risk_classes: stringList$1(item.risk_classes, `${label}.risk_classes`),
    safer_alternatives: stringList$1(item.safer_alternatives, `${label}.safer_alternatives`),
    rule_count: ruleCount,
    rules,
    permission_count: permissionCount,
    permissions
  };
}
function normalizeExtensionControlLayer(value, label = "layer") {
  const item = record$2(value, label);
  const controls = array(item.controls, `${label}.controls`, EXTENSION_CLIENT_LIMITS.controls).map((entry, index) => {
    const raw = record$2(entry, `${label}.controls[${index}]`);
    const kind = enumValue(raw.target_kind, `${label}.controls[${index}].target_kind`, ["extension", "permission"]);
    return {
      target_kind: kind,
      target_id: id(raw.target_id, `${label}.controls[${index}].target_id`, kind === "extension" ? EXTENSION_ID : PERMISSION_ID),
      state: enumValue(raw.state, `${label}.controls[${index}].state`, ["enabled", "disabled"])
    };
  });
  const keys = controls.map((control) => `${control.target_kind}:${control.target_id}`);
  if (new Set(keys).size !== keys.length) throw new ExtensionControlProtocolError(`${label}.controls contains duplicate targets`);
  return {
    schema_version: string$1(item.schema_version, `${label}.schema_version`),
    kind: enumValue(item.kind, `${label}.kind`, ["local-admin", "signed-cloud"]),
    catalog_digest: digest$1(item.catalog_digest, `${label}.catalog_digest`),
    global_lockdown: bool$1(item.global_lockdown, `${label}.global_lockdown`),
    controls
  };
}
function normalizeExtensionCatalog(value) {
  const root = record$2(value, "catalog");
  const extensions = array(root.extensions, "catalog.extensions", EXTENSION_CLIENT_LIMITS.extensions).map((entry, index) => extension(entry, `catalog.extensions[${index}]`));
  const ids = extensions.map((entry) => entry.extension_id);
  if (new Set(ids).size !== ids.length) throw new ExtensionControlProtocolError("catalog.extensions contains duplicate extension IDs");
  const limits = root.limits === void 0 ? void 0 : record$2(root.limits, "catalog.limits");
  return {
    schema_version: string$1(root.schema_version, "catalog.schema_version"),
    control_schema_version: root.control_schema_version === void 0 ? void 0 : string$1(root.control_schema_version, "catalog.control_schema_version"),
    catalog_digest: digest$1(root.catalog_digest, "catalog.catalog_digest"),
    extensions,
    limits: limits === void 0 ? void 0 : {
      max_body_bytes: limits.max_body_bytes === void 0 ? void 0 : integer$1(limits.max_body_bytes, "catalog.limits.max_body_bytes", 1),
      max_controls: limits.max_controls === void 0 ? void 0 : integer$1(limits.max_controls, "catalog.limits.max_controls", 1),
      max_observations: limits.max_observations === void 0 ? void 0 : integer$1(limits.max_observations, "catalog.limits.max_observations", 1)
    }
  };
}
function normalizeEffectiveExtensionControls(value) {
  const root = record$2(value, "effective");
  const controls = array(root.controls, "effective.controls", EXTENSION_CLIENT_LIMITS.controls).map((entry, index) => {
    const raw = record$2(entry, `effective.controls[${index}]`);
    const target2 = record$2(raw.target, `effective.controls[${index}].target`);
    const kind = enumValue(target2.kind, `effective.controls[${index}].target.kind`, ["extension", "permission"]);
    return {
      target: {
        kind,
        target_id: id(target2.target_id, `effective.controls[${index}].target.target_id`, kind === "extension" ? EXTENSION_ID : PERMISSION_ID)
      },
      state: enumValue(raw.state, `effective.controls[${index}].state`, ["enabled", "disabled"])
    };
  });
  const keys = controls.map((control) => `${control.target.kind}:${control.target.target_id}`);
  if (new Set(keys).size !== keys.length) throw new ExtensionControlProtocolError("effective.controls contains duplicate targets");
  const layers = array(root.layers, "effective.layers", EXTENSION_CLIENT_LIMITS.layers).map((entry, index) => normalizeExtensionControlLayer(entry, `effective.layers[${index}]`));
  const failures = array(root.failures, "effective.failures", EXTENSION_CLIENT_LIMITS.failures).map((entry, index) => {
    const raw = record$2(entry, `effective.failures[${index}]`);
    return {
      code: string$1(raw.code, `effective.failures[${index}].code`),
      detail: raw.detail === void 0 ? void 0 : string$1(raw.detail, `effective.failures[${index}].detail`, true),
      layer_kind: raw.layer_kind === void 0 ? void 0 : string$1(raw.layer_kind, `effective.failures[${index}].layer_kind`)
    };
  });
  return {
    schema_version: string$1(root.schema_version, "effective.schema_version"),
    health: enumValue(root.health, "effective.health", ["unenrolled", "protected", "tampered", "degraded-unacknowledged", "degraded-acknowledged", "recovery-required"]),
    revision: integer$1(root.revision, "effective.revision"),
    catalog_digest: digest$1(root.catalog_digest, "effective.catalog_digest"),
    global_lockdown: bool$1(root.global_lockdown, "effective.global_lockdown"),
    controls,
    layers,
    failures,
    projection: root.projection === void 0 ? void 0 : normalizeEffectiveExtensionControlProjection(root.projection)
  };
}
const DIGEST = /^[a-f0-9]{64}$/;
const TARGET_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const MAX_CHANGED_TARGETS = 4096;
const MAX_AFFECTED_IDS = 4096;
const MAX_WARNINGS = 64;
const MAX_TEXT = 8192;
function record$1(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`Invalid extension-control ${label}: expected object`);
  return value;
}
function string(value, label, max = MAX_TEXT) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) throw new Error(`Invalid extension-control ${label}`);
  return value;
}
function integer(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid extension-control ${label}`);
  return value;
}
function bool(value, label) {
  if (typeof value !== "boolean") throw new Error(`Invalid extension-control ${label}`);
  return value;
}
function digest(value, label) {
  const candidate = string(value, label, 64);
  if (!DIGEST.test(candidate)) throw new Error(`Invalid extension-control ${label}`);
  return candidate;
}
function targetId(value, label) {
  const candidate = string(value, label, 256);
  if (!TARGET_ID.test(candidate)) throw new Error(`Invalid extension-control ${label}`);
  return candidate;
}
function boundedArray(value, label, max) {
  if (!Array.isArray(value) || value.length > max) throw new Error(`Invalid extension-control ${label}`);
  return value;
}
function idList(value, label) {
  const items = boundedArray(value, label, MAX_AFFECTED_IDS).map((item, index) => targetId(item, `${label}[${index}]`));
  if (new Set(items).size !== items.length) throw new Error(`Invalid extension-control ${label}: duplicate IDs`);
  return items;
}
function optionalIdList(value, label) {
  return value === void 0 ? void 0 : idList(value, label);
}
function optionalStringList(value, label) {
  if (value === void 0) return void 0;
  const items = boundedArray(value, label, MAX_AFFECTED_IDS).map((item, index) => string(item, `${label}[${index}]`, 128));
  if (new Set(items).size !== items.length) throw new Error(`Invalid extension-control ${label}: duplicate values`);
  return items;
}
function warning(value, label) {
  const item = record$1(value, label);
  return {
    code: string(item.code, `${label}.code`, 128),
    message: string(item.message, `${label}.message`, 1024),
    ...item.target_id === void 0 ? {} : { target_id: targetId(item.target_id, `${label}.target_id`) },
    ...item.count === void 0 ? {} : { count: integer(item.count, `${label}.count`) }
  };
}
function target(value, label) {
  const item = record$1(value, label);
  const rawTarget = record$1(item.target, `${label}.target`);
  const kind = string(rawTarget.kind, `${label}.target.kind`, 32);
  if (kind !== "extension" && kind !== "permission") throw new Error(`Invalid extension-control ${label}.target.kind`);
  const beforeExplicit = string(item.before_explicit, `${label}.before_explicit`, 32);
  const afterExplicit = string(item.after_explicit, `${label}.after_explicit`, 32);
  if (!["inherited", "enabled", "disabled"].includes(beforeExplicit) || !["inherited", "enabled", "disabled"].includes(afterExplicit)) throw new Error(`Invalid extension-control ${label} explicit state`);
  const beforeEffective = string(item.before_effective, `${label}.before_effective`, 32);
  const afterEffective = string(item.after_effective, `${label}.after_effective`, 32);
  if (!["allowed", "blocked"].includes(beforeEffective) || !["allowed", "blocked"].includes(afterEffective)) throw new Error(`Invalid extension-control ${label} effective state`);
  const affectedExtensionIds = optionalIdList(item.affected_extension_ids, `${label}.affected_extension_ids`);
  const dependencyPermissionIds = optionalIdList(item.dependency_permission_ids, `${label}.dependency_permission_ids`);
  const impliedPermissionIds = optionalIdList(item.implied_permission_ids, `${label}.implied_permission_ids`);
  const conflictPermissionIds = optionalIdList(item.conflict_permission_ids, `${label}.conflict_permission_ids`);
  const provenance = optionalStringList(item.provenance, `${label}.provenance`);
  return {
    target: { kind, target_id: targetId(rawTarget.target_id, `${label}.target.target_id`) },
    extension_id: targetId(item.extension_id, `${label}.extension_id`),
    label: string(item.label, `${label}.label`, 512),
    before_explicit: beforeExplicit,
    after_explicit: afterExplicit,
    before_effective: beforeEffective,
    after_effective: afterEffective,
    affected_permission_ids: idList(item.affected_permission_ids, `${label}.affected_permission_ids`),
    affected_rule_ids: idList(item.affected_rule_ids, `${label}.affected_rule_ids`),
    ...affectedExtensionIds === void 0 ? {} : { affected_extension_ids: affectedExtensionIds },
    ...dependencyPermissionIds === void 0 ? {} : { dependency_permission_ids: dependencyPermissionIds },
    ...impliedPermissionIds === void 0 ? {} : { implied_permission_ids: impliedPermissionIds },
    ...conflictPermissionIds === void 0 ? {} : { conflict_permission_ids: conflictPermissionIds },
    ...provenance === void 0 ? {} : { provenance },
    warnings: boundedArray(item.warnings, `${label}.warnings`, MAX_WARNINGS).map((entry, index) => warning(entry, `${label}.warnings[${index}]`)),
    ...item.extension_name === void 0 ? {} : { extension_name: string(item.extension_name, `${label}.extension_name`, 512) },
    ...item.baseline_risk === void 0 ? {} : { baseline_risk: string(item.baseline_risk, `${label}.baseline_risk`, 32) },
    ...item.baseline_floor === void 0 ? {} : { baseline_floor: string(item.baseline_floor, `${label}.baseline_floor`, 32) }
  };
}
function normalizeExtensionSemanticPreview(value) {
  const root = record$1(value, "semantic preview");
  if (string(root.schema_version, "semantic_preview.schema_version", 128) !== "guard.daemon.extension-control-semantic-preview.v1") throw new Error("Invalid extension-control semantic preview schema");
  const lockdown = record$1(root.global_lockdown, "semantic_preview.global_lockdown");
  const summary = record$1(root.summary, "semantic_preview.summary");
  const changedTargets = boundedArray(root.changed_targets, "semantic_preview.changed_targets", MAX_CHANGED_TARGETS).map((entry, index) => target(entry, `semantic_preview.changed_targets[${index}]`));
  const changedTargetCount = integer(root.changed_target_count, "semantic_preview.changed_target_count");
  if (changedTargetCount !== changedTargets.length) throw new Error("Invalid extension-control semantic preview target count");
  return {
    schema_version: "guard.daemon.extension-control-semantic-preview.v1",
    global_lockdown: {
      before: bool(lockdown.before, "semantic_preview.global_lockdown.before"),
      after: bool(lockdown.after, "semantic_preview.global_lockdown.after"),
      changed: bool(lockdown.changed, "semantic_preview.global_lockdown.changed")
    },
    changed_target_count: changedTargetCount,
    affected_permission_count: integer(root.affected_permission_count, "semantic_preview.affected_permission_count"),
    affected_rule_count: integer(root.affected_rule_count, "semantic_preview.affected_rule_count"),
    changed_targets: changedTargets,
    ...root.approval_required === void 0 ? {} : { approval_required: bool(root.approval_required, "semantic_preview.approval_required") },
    summary: {
      newly_blocked_permissions: integer(summary.newly_blocked_permissions, "semantic_preview.summary.newly_blocked_permissions"),
      newly_allowed_permissions: integer(summary.newly_allowed_permissions, "semantic_preview.summary.newly_allowed_permissions"),
      effective_change_count: integer(summary.effective_change_count, "semantic_preview.summary.effective_change_count")
    }
  };
}
function normalizeExtensionMutationPreview(value) {
  const root = record$1(value, "mutation preview");
  return {
    schema_version: string(root.schema_version, "preview.schema_version", 128),
    previous_revision: integer(root.previous_revision, "preview.previous_revision"),
    next_revision: integer(root.next_revision, "preview.next_revision"),
    catalog_digest: digest(root.catalog_digest, "preview.catalog_digest"),
    canonical_diff_digest: digest(root.canonical_diff_digest, "preview.canonical_diff_digest"),
    global_lockdown: bool(root.global_lockdown, "preview.global_lockdown"),
    controls: integer(root.controls, "preview.controls"),
    semantic_preview: normalizeExtensionSemanticPreview(root.semantic_preview),
    ...root.proof_id === void 0 ? {} : { proof_id: string(root.proof_id, "preview.proof_id", 256) }
  };
}
function normalizeExtensionMutationApply(value) {
  const root = record$1(value, "mutation apply");
  if (string(root.status, "apply.status", 32) !== "applied") throw new Error("Invalid extension-control apply status");
  return {
    schema_version: string(root.schema_version, "apply.schema_version", 128),
    status: "applied",
    revision: integer(root.revision, "apply.revision"),
    catalog_digest: digest(root.catalog_digest, "apply.catalog_digest")
  };
}
class ExtensionControlApiError extends Error {
  constructor(message, status, code, recoveryAction) {
    super(message);
    this.status = status;
    this.code = code;
    this.recoveryAction = recoveryAction;
  }
  status;
  code;
  recoveryAction;
}
async function request(path, init) {
  const response = await fetchExtensionControlApi(path, init);
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new ExtensionControlApiError(`Guard returned invalid JSON (${response.status})`, response.status);
  }
  if (!response.ok) {
    const error = typeof payload === "object" && payload !== null ? payload : {};
    throw new ExtensionControlApiError(
      typeof error.error === "string" ? error.error : `Request failed (${response.status})`,
      response.status,
      typeof error.error === "string" ? error.error : void 0,
      typeof error.recovery === "object" && error.recovery !== null && typeof error.recovery.action === "string" ? error.recovery.action : void 0
    );
  }
  return payload;
}
async function fetchExtensionCatalog() {
  return normalizeExtensionCatalog(await request("/v1/extension-controls/catalog"));
}
async function fetchEffectiveExtensionControls() {
  const raw = await request("/v1/extension-controls/effective");
  const normalized = normalizeEffectiveExtensionControls(raw);
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return normalized;
  const projectionValue = raw.projection;
  if (projectionValue === void 0) return normalized;
  const projection = normalizeEffectiveExtensionControlProjection(projectionValue);
  if (projection.revision !== normalized.revision || projection.catalog_digest !== normalized.catalog_digest || projection.health !== normalized.health) {
    throw new ExtensionControlApiError("Guard returned an inconsistent extension-control projection", 502);
  }
  return { ...normalized, projection };
}
async function fetchExtensionControlHistory() {
  const raw = await request("/v1/extension-controls/history");
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new ExtensionControlApiError("Guard returned invalid settings history", 502);
  const root = raw;
  if (root.schema_version !== "guard.daemon.extension-control-history.v1") throw new ExtensionControlApiError("Guard returned unsupported settings history", 502);
  if (!Number.isSafeInteger(root.revision) || root.revision < 0 || typeof root.catalog_digest !== "string") throw new ExtensionControlApiError("Guard returned invalid settings history metadata", 502);
  if (!Array.isArray(root.items) || root.items.length > 50) throw new ExtensionControlApiError("Guard returned too much settings history", 502);
  const items = root.items.map((value, index) => {
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new ExtensionControlApiError("Guard returned invalid settings history item", 502);
    const item = value;
    if (!Number.isSafeInteger(item.revision) || !Number.isSafeInteger(item.previous_revision) || typeof item.occurred_at !== "string" || typeof item.catalog_digest !== "string" || !Array.isArray(item.layers)) throw new ExtensionControlApiError("Guard returned invalid settings history item", 502);
    const layers = item.layers.map((layer, layerIndex) => normalizeExtensionControlLayer(layer, `history.items[${index}].layers[${layerIndex}]`));
    return {
      revision: item.revision,
      previous_revision: item.previous_revision,
      occurred_at: item.occurred_at,
      catalog_digest: item.catalog_digest,
      layers
    };
  });
  return {
    schema_version: "guard.daemon.extension-control-history.v1",
    revision: root.revision,
    catalog_digest: root.catalog_digest,
    items
  };
}
async function recoverExtensionControlAuthority(credentials) {
  const raw = await request("/v1/extension-controls/recover-authority", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_nonce: crypto.randomUUID().replaceAll("-", ""),
      ...credentials
    })
  });
  const normalized = normalizeEffectiveExtensionControls(raw);
  if (typeof raw === "object" && raw !== null && !Array.isArray(raw) && raw.projection !== void 0) {
    return { ...normalized, projection: normalizeEffectiveExtensionControlProjection(raw.projection) };
  }
  return normalized;
}
async function acknowledgeDegradedExtensionControlAuthority(credentials) {
  const raw = await request("/v1/extension-controls/acknowledge-degraded", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_nonce: crypto.randomUUID().replaceAll("-", ""),
      ...credentials
    })
  });
  const normalized = normalizeEffectiveExtensionControls(raw);
  if (typeof raw === "object" && raw !== null && !Array.isArray(raw) && raw.projection !== void 0) {
    return { ...normalized, projection: normalizeEffectiveExtensionControlProjection(raw.projection) };
  }
  return normalized;
}
async function previewExtensionMutation(payload) {
  try {
    return normalizeExtensionMutationPreview(await request("/v1/extension-controls/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }));
  } catch (error) {
    if (error instanceof ExtensionControlApiError) throw error;
    throw new ExtensionControlApiError(error instanceof Error ? error.message : "Guard returned an invalid preview response", 502);
  }
}
async function applyExtensionMutation(payload) {
  try {
    return normalizeExtensionMutationApply(await request("/v1/extension-controls/apply", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }));
  } catch (error) {
    if (error instanceof ExtensionControlApiError) throw error;
    throw new ExtensionControlApiError(error instanceof Error ? error.message : "Guard returned an invalid apply response", 502);
  }
}
const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])"
].join(",");
function focusableElements(root) {
  return Array.from(root.querySelectorAll(FOCUSABLE_SELECTOR)).filter(
    (element) => !element.hasAttribute("hidden") && element.getAttribute("aria-hidden") !== "true"
  );
}
function useModalDialog(onClose, canClose = true) {
  const dialogRef = reactExports.useRef(null);
  const closeRef = reactExports.useRef(onClose);
  const canCloseRef = reactExports.useRef(canClose);
  closeRef.current = onClose;
  canCloseRef.current = canClose;
  reactExports.useEffect(() => {
    const root = dialogRef.current;
    if (!root) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const initial = focusableElements(root)[0] ?? root;
    initial.focus();
    const handleKeyDown = (event) => {
      if (event.key === "Escape" && canCloseRef.current) {
        event.preventDefault();
        closeRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = focusableElements(root);
      if (focusable.length === 0) {
        event.preventDefault();
        root.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      if (previous?.isConnected) previous.focus();
    };
  }, []);
  return dialogRef;
}
const PROTECTION_TERMS = {
  pageTitle: "Extensions"
};
function looksLikeUnauthorizedSession(message) {
  const lower = message.trim().toLowerCase();
  if (!lower || lower === "unauthorized" || lower.includes("unauthorized") || lower.includes("session")) return true;
  return /(^|[^0-9])401([^0-9]|$)/.test(lower);
}
function protectionCenterLoadError(message) {
  if (looksLikeUnauthorizedSession(message)) {
    return {
      title: "This view needs a signed local session",
      detail: "Local protection is still running on this device. Open Extensions from the local Guard dashboard and try again after Guard signs this session."
    };
  }
  return {
    title: "Extensions unavailable",
    detail: message.trim() || "Guard could not load protection settings. Local protection continues. Try again."
  };
}
function cloneLayers$1(layers) {
  return layers.map((layer) => ({
    ...layer,
    controls: layer.controls.map((control) => ({ ...control }))
  }));
}
function sortedControls(layer) {
  return {
    ...layer,
    controls: [...layer.controls].sort(
      (left, right) => `${left.target_kind}:${left.target_id}`.localeCompare(`${right.target_kind}:${right.target_id}`)
    )
  };
}
function localPermissionDraftState(layers, permissionId) {
  const local = layers.find((layer) => layer.kind === "local-admin");
  const control = local?.controls.find(
    (item) => item.target_kind === "permission" && item.target_id === permissionId
  );
  if (!control) return "inherit";
  return control.state === "enabled" ? "allow" : "block";
}
function setLocalPermissionDraftState(layers, catalogDigest, permissionId, state) {
  const next = cloneLayers$1(layers);
  let local = next.find((layer) => layer.kind === "local-admin");
  if (!local) {
    local = {
      schema_version: "1.0.0",
      kind: "local-admin",
      catalog_digest: catalogDigest,
      global_lockdown: false,
      controls: []
    };
    next.push(local);
  }
  local.controls = local.controls.filter(
    (control) => control.target_kind !== "permission" || control.target_id !== permissionId
  );
  if (state !== "inherit") {
    local.controls.push({
      target_kind: "permission",
      target_id: permissionId,
      state: state === "allow" ? "enabled" : "disabled"
    });
  }
  const normalized = next.map((layer) => sortedControls(layer));
  normalized.sort((left, right) => left.kind.localeCompare(right.kind));
  return normalized;
}
function canonicalLayerValue(layers) {
  return JSON.stringify(
    [...layers].map((layer) => sortedControls(layer)).sort((left, right) => left.kind.localeCompare(right.kind))
  );
}
function extensionPolicyDraftIsDirty(effective, draftLayers) {
  return canonicalLayerValue(effective.layers) !== canonicalLayerValue(draftLayers);
}
function buildExtensionPolicyDraftMutation(effective, catalogDigest, draftLayers, identity) {
  return {
    previous_revision: effective.revision,
    catalog_digest: catalogDigest,
    layers: cloneLayers$1(draftLayers),
    actor_id: "dashboard-admin",
    idempotency_key: identity.idempotencyKey,
    nonce: identity.nonce
  };
}
function newExtensionPolicyDraftIdentity() {
  return {
    idempotencyKey: crypto.randomUUID().replaceAll("-", ""),
    nonce: crypto.randomUUID().replaceAll("-", "")
  };
}
function isCurrentExtensionPolicyDraft(generation, current) {
  return generation === current;
}
function permissionSuffix(permissionId) {
  const marker = ".permission.";
  const index = permissionId.indexOf(marker);
  return index < 0 ? null : permissionId.slice(index + marker.length);
}
function latestPermissionId(original, oldExtension, latestExtension) {
  if (latestExtension.permissions.some((permission2) => permission2.permission_id === original)) return original;
  if (latestExtension.extension_id !== oldExtension.extension_id && latestExtension.aliases.includes(oldExtension.extension_id)) {
    const suffix = permissionSuffix(original);
    if (!suffix) return null;
    const candidate = `${latestExtension.extension_id}.permission.${suffix}`;
    if (latestExtension.permissions.some((permission2) => permission2.permission_id === candidate)) return candidate;
  }
  return null;
}
function rebaseExtensionPolicyDraft(oldEffective, latestEffective, oldExtension, latestExtension, draftLayers) {
  let rebased = latestEffective.layers.map((layer) => ({ ...layer, controls: layer.controls.map((control) => ({ ...control })) }));
  const conflicts = [];
  const remapped = {};
  for (const permission2 of oldExtension.permissions) {
    const baseState = localPermissionDraftState(oldEffective.layers, permission2.permission_id);
    const requestedState = localPermissionDraftState(draftLayers, permission2.permission_id);
    if (baseState === requestedState) continue;
    const mapped = latestPermissionId(permission2.permission_id, oldExtension, latestExtension);
    if (!mapped) {
      conflicts.push({
        original_permission_id: permission2.permission_id,
        latest_permission_id: null,
        kind: "removed",
        base_state: baseState,
        latest_state: "inherit",
        requested_state: requestedState
      });
      continue;
    }
    remapped[permission2.permission_id] = mapped;
    const latestState = localPermissionDraftState(latestEffective.layers, mapped);
    if (latestState !== baseState && latestState !== requestedState) {
      conflicts.push({
        original_permission_id: permission2.permission_id,
        latest_permission_id: mapped,
        kind: "overlap",
        base_state: baseState,
        latest_state: latestState,
        requested_state: requestedState
      });
      continue;
    }
    rebased = setLocalPermissionDraftState(rebased, latestEffective.catalog_digest, mapped, requestedState);
  }
  return { draft_layers: rebased, conflicts, remapped_permission_ids: remapped };
}
function keepExtensionPolicyRebaseConflicts(result, latestEffective) {
  let layers = result.draft_layers;
  for (const conflict of result.conflicts) {
    if (conflict.kind !== "overlap" || !conflict.latest_permission_id) continue;
    layers = setLocalPermissionDraftState(
      layers,
      latestEffective.catalog_digest,
      conflict.latest_permission_id,
      conflict.requested_state
    );
  }
  return layers;
}
function cloneLayers(effective) {
  return effective.layers.map((layer) => ({ ...layer, controls: layer.controls.map((control) => ({ ...control })) }));
}
function useExtensionPolicyDraft(props) {
  const [baseEffective, setBaseEffective] = reactExports.useState(props.effective);
  const [draftLayers, setDraftLayers] = reactExports.useState(() => cloneLayers(props.effective));
  const [identity, setIdentity] = reactExports.useState(() => newExtensionPolicyDraftIdentity());
  const [preview, setPreview] = reactExports.useState(null);
  const [previewBusy, setPreviewBusy] = reactExports.useState(false);
  const [applyBusy, setApplyBusy] = reactExports.useState(false);
  const [approvalOpen, setApprovalOpen] = reactExports.useState(false);
  const [reviewOpen, setReviewOpen] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [stale, setStale] = reactExports.useState(false);
  const [pendingRebase, setPendingRebase] = reactExports.useState(null);
  const [refreshRequired, setRefreshRequired] = reactExports.useState(false);
  const [lastApplied, setLastApplied] = reactExports.useState(null);
  const draftGeneration = reactExports.useRef(0);
  const { onRefresh } = props;
  const dirty = reactExports.useMemo(() => extensionPolicyDraftIsDirty(baseEffective, draftLayers), [baseEffective, draftLayers]);
  reactExports.useEffect(() => {
    draftGeneration.current += 1;
    setBaseEffective(props.effective);
    setDraftLayers(cloneLayers(props.effective));
    setIdentity(newExtensionPolicyDraftIdentity());
    setRefreshRequired(false);
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [props.effective.revision, props.effective.catalog_digest]);
  const changeCountFor = reactExports.useCallback((permissionIds) => {
    return permissionIds.filter(
      (permissionId) => localPermissionDraftState(baseEffective.layers, permissionId) !== localPermissionDraftState(draftLayers, permissionId)
    ).length;
  }, [baseEffective, draftLayers]);
  const changedPermissionCount = reactExports.useMemo(
    () => changeCountFor(
      baseEffective.layers.flatMap((layer) => layer.controls).map((control) => control.target_kind === "permission" ? control.target_id : null).filter((id2) => Boolean(id2))
    ),
    [baseEffective, changeCountFor]
  );
  const resetDraft = reactExports.useCallback(() => {
    draftGeneration.current += 1;
    setDraftLayers(cloneLayers(baseEffective));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [baseEffective]);
  const setPermissionState = reactExports.useCallback((permissionId, state) => {
    draftGeneration.current += 1;
    setDraftLayers((current) => setLocalPermissionDraftState(current, baseEffective.catalog_digest, permissionId, state));
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
  }, [baseEffective.catalog_digest]);
  const mutation = reactExports.useCallback(
    () => buildExtensionPolicyDraftMutation(baseEffective, baseEffective.catalog_digest, draftLayers, identity),
    [baseEffective, draftLayers, identity]
  );
  const handleApiError = reactExports.useCallback((caught, fallback) => {
    if (caught instanceof ExtensionControlApiError && ["revision_conflict", "catalog_conflict", "authority_conflict"].includes(caught.code ?? "")) {
      setStale(true);
      setError("The authoritative extension policy changed while this draft was open. Rebase the draft before applying; Guard will not silently overwrite security policy.");
      return;
    }
    setError(caught instanceof Error ? caught.message : fallback);
  }, []);
  const runPreview = reactExports.useCallback(async () => {
    if (!dirty) return;
    const generation = draftGeneration.current;
    setPreviewBusy(true);
    setError(null);
    setStale(false);
    try {
      const next = await previewExtensionMutation(mutation());
      if (!isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) return;
      setPreview(next);
      setReviewOpen(true);
    } catch (caught) {
      if (isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) handleApiError(caught, "Guard could not preview this draft.");
    } finally {
      setPreviewBusy(false);
    }
  }, [dirty, handleApiError, mutation]);
  const apply = reactExports.useCallback(async (credentials) => {
    if (!preview || !dirty || stale) return;
    setApplyBusy(true);
    setError(null);
    try {
      const base = mutation();
      const appliedLayersBefore = cloneLayers(baseEffective);
      const proofPreview = await previewExtensionMutation({ ...base, ...credentials, session_nonce: crypto.randomUUID().replaceAll("-", "") });
      if (!proofPreview.proof_id) throw new Error("Guard did not issue an approval proof for this exact draft.");
      if (proofPreview.canonical_diff_digest !== preview.canonical_diff_digest) throw new Error("The policy draft changed after preview. Preview it again before applying.");
      const applied = await applyExtensionMutation({ ...base, proof_id: proofPreview.proof_id });
      setApprovalOpen(false);
      setPreview(null);
      setReviewOpen(false);
      setError(null);
      setStale(false);
      if (applied.revision <= baseEffective.revision) throw new Error("Guard did not advance the committed extension-control revision.");
      const changedPermissionIds = baseEffective.layers.flatMap((layer) => layer.controls).concat(draftLayers.flatMap((layer) => layer.controls)).map((control) => control.target_kind === "permission" ? control.target_id : null).filter((id2) => Boolean(id2));
      const previouslyRequested = new Set(
        draftLayers.flatMap((layer) => layer.controls).map((control) => control.target_kind === "permission" ? control.target_id : null).filter((id2) => Boolean(id2))
      );
      setLastApplied({
        revision: applied.revision,
        previousLayers: appliedLayersBefore,
        changedPermissionIds: [...new Set(changedPermissionIds)].filter((id2) => previouslyRequested.has(id2) || localPermissionDraftState(baseEffective.layers, id2) !== localPermissionDraftState(draftLayers, id2))
      });
      draftGeneration.current += 1;
      setDraftLayers(cloneLayers(baseEffective));
      setIdentity(newExtensionPolicyDraftIdentity());
      setRefreshRequired(true);
      try {
        await onRefresh();
      } catch {
        setError("The policy was applied, but Guard could not refresh the latest state. Refresh this page to confirm the committed policy.");
      }
    } catch (caught) {
      handleApiError(caught, "Guard could not apply this draft.");
    } finally {
      setApplyBusy(false);
    }
  }, [baseEffective.revision, dirty, handleApiError, mutation, onRefresh, preview, stale]);
  const rebaseDraft = reactExports.useCallback(async (oldExtensions) => {
    const generation = draftGeneration.current;
    setPreviewBusy(true);
    setError(null);
    try {
      const [latestCatalog, latestEffective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      const pairs = oldExtensions.map((oldExtension) => {
        const exact = latestCatalog.extensions.find((item) => item.extension_id === oldExtension.extension_id);
        if (exact) return { oldExtension, latestExtension: exact };
        const aliasMatches = latestCatalog.extensions.filter((item) => item.aliases.includes(oldExtension.extension_id));
        return aliasMatches.length === 1 ? { oldExtension, latestExtension: aliasMatches[0] } : null;
      }).filter((pair) => Boolean(pair));
      if (!pairs.length) {
        setError("These extensions no longer exist in the authoritative catalog. Discard the draft and refresh before continuing.");
        return;
      }
      if (!isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) {
        setError("The draft changed while Guard was loading current policy. Rebase again to preserve the latest edits.");
        return;
      }
      const chained = pairs.reduce((result2, { oldExtension, latestExtension }) => {
        const next = rebaseExtensionPolicyDraft(
          baseEffective,
          latestEffective,
          oldExtension,
          latestExtension,
          result2 ? result2.draft_layers : draftLayers
        );
        return {
          draft_layers: next.draft_layers,
          conflicts: [...result2?.conflicts ?? [], ...next.conflicts],
          remapped_permission_ids: { ...result2?.remapped_permission_ids ?? {}, ...next.remapped_permission_ids }
        };
      }, null);
      if (!chained) {
        setError("Guard could not rebase this draft against the current catalog.");
        return;
      }
      const result = chained;
      setBaseEffective(latestEffective);
      setIdentity(newExtensionPolicyDraftIdentity());
      setPreview(null);
      setReviewOpen(false);
      if (result.conflicts.length) {
        setPendingRebase({ result, latestEffective, latestExtensions: pairs.map((pair) => pair.latestExtension) });
        setDraftLayers(result.draft_layers);
        setStale(true);
        setError("The latest policy overlaps this draft. Choose whether to keep your overlapping changes or use current authoritative values. Removed permissions cannot be restored.");
      } else {
        setDraftLayers(result.draft_layers);
        setPendingRebase(null);
        setStale(false);
        setError(null);
      }
    } catch (caught) {
      if (isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) handleApiError(caught, "Guard could not rebase this draft.");
    } finally {
      setPreviewBusy(false);
    }
  }, [baseEffective, draftLayers]);
  const keepConflicts = reactExports.useCallback(() => {
    if (!pendingRebase) return;
    setDraftLayers(keepExtensionPolicyRebaseConflicts(pendingRebase.result, pendingRebase.latestEffective));
    setPendingRebase(null);
    setStale(false);
    setError(null);
    setIdentity(newExtensionPolicyDraftIdentity());
  }, [pendingRebase]);
  const useCurrent = reactExports.useCallback(() => {
    if (!pendingRebase) return;
    setDraftLayers(cloneLayers(pendingRebase.latestEffective));
    setPendingRebase(null);
    setStale(false);
    setError(null);
    setPreview(null);
    setIdentity(newExtensionPolicyDraftIdentity());
  }, [pendingRebase]);
  const applyProfile = reactExports.useCallback((permissions, profile) => {
    if (profile === "custom") return;
    draftGeneration.current += 1;
    let next = cloneLayers(baseEffective);
    for (const permission2 of permissions) {
      if (!permission2.configurable) continue;
      const state = profile === "recommended" ? "inherit" : "block";
      next = setLocalPermissionDraftState(next, baseEffective.catalog_digest, permission2.permission_id, state);
    }
    setDraftLayers(next);
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
  }, [baseEffective]);
  const useHistoricalDraft = reactExports.useCallback((historicalLayers) => {
    draftGeneration.current += 1;
    const historicalLocal = historicalLayers.find((layer) => layer.kind === "local-admin");
    const next = baseEffective.layers.flatMap((layer) => layer.kind === "local-admin" ? historicalLocal ? [historicalLocal] : [] : [layer]);
    if (historicalLocal && !baseEffective.layers.some((layer) => layer.kind === "local-admin")) next.push(historicalLocal);
    setDraftLayers(next);
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [baseEffective.layers]);
  const undoLastApplied = reactExports.useCallback(() => {
    if (!lastApplied) return false;
    draftGeneration.current += 1;
    setDraftLayers(cloneLayers({ ...baseEffective, layers: lastApplied.previousLayers }));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
    return true;
  }, [baseEffective, lastApplied]);
  return {
    baseEffective,
    draftLayers,
    dirty,
    preview,
    previewBusy,
    applyBusy,
    reviewOpen,
    approvalOpen,
    error,
    stale,
    pendingRebase,
    refreshRequired,
    lastApplied,
    undoLastApplied,
    changedPermissionCount,
    setReviewOpen,
    setApprovalOpen,
    permissionState: reactExports.useCallback((permissionId) => localPermissionDraftState(draftLayers, permissionId), [draftLayers]),
    changeCountFor,
    setPermissionState,
    resetDraft,
    runPreview,
    apply,
    rebaseDraft,
    keepConflicts,
    useCurrent,
    applyProfile,
    useHistoricalDraft
  };
}
function ProtectionSettingsHistory(props) {
  const [items, setItems] = reactExports.useState([]);
  const [loading, setLoading] = reactExports.useState(true);
  const [error, setError] = reactExports.useState(null);
  reactExports.useEffect(() => {
    let active = true;
    setLoading(true);
    fetchExtensionControlHistory().then((history) => {
      if (!active) return;
      setItems(history.items.filter((item) => item.catalog_digest === props.catalogDigest));
      setError(null);
    }).catch(() => {
      if (active) setError("Local settings history is unavailable until Guard verifies settings integrity.");
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [props.catalogDigest]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-sm font-semibold text-brand-dark", children: "Settings history" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs leading-5 text-brand-dark/80", children: "Guard verifies the authenticated local history before showing it. Restoring a version only prepares the device layer as a draft. Current organization policy stays in force, and nothing changes until you review and approve it." }),
    loading ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-brand-dark/70", children: "Loading verified history…" }) : error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-amber-950", children: error }) : items.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 space-y-2", children: items.slice(0, 10).map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-2 py-2 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm font-medium text-brand-dark", children: [
          "Device settings revision ",
          item.revision
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("time", { className: "text-xs text-brand-dark/70", dateTime: item.occurred_at, children: new Date(item.occurred_at).toLocaleString() })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.disabled, onClick: () => props.onUse(item.layers, item.revision), className: "min-h-10 px-1 text-xs font-semibold text-brand-blue disabled:opacity-40", children: "Use this version as draft" })
    ] }, item.revision)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-brand-dark/70", children: "No earlier authenticated device settings are available yet." })
  ] });
}
const RISK_TONE = {
  critical: "border-red-200 bg-red-50 text-red-950",
  high: "border-orange-200 bg-orange-50 text-orange-950",
  medium: "border-amber-200 bg-amber-50 text-amber-950",
  low: "border-[rgba(63,65,116,0.16)] text-brand-dark"
};
function Pill(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${props.tone ?? "border-[rgba(63,65,116,0.16)] text-brand-dark"}`, children: props.children });
}
function managedPermissionState(effective, permissionId) {
  const projected = effective.projection?.permissions.find((item) => item.permission_id === permissionId)?.managed_state;
  if (projected && projected !== "inherited") return projected;
  for (const layer of effective.layers) {
    if (layer.kind !== "signed-cloud") continue;
    const control = layer.controls.find((item) => item.target_kind === "permission" && item.target_id === permissionId);
    if (control) return control.state;
  }
  return null;
}
function extensionPolicyRadioTabStop(choices, state, groupDisabled) {
  if (groupDisabled) return -1;
  const selected = choices.findIndex((choice) => choice.value === state && !choice.disabled);
  return selected >= 0 ? selected : choices.findIndex((choice) => !choice.disabled);
}
function nextExtensionPolicyRadioIndex(choices, index, key, groupDisabled) {
  if (groupDisabled || !["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(key)) return -1;
  const direction = key === "ArrowLeft" || key === "ArrowUp" ? -1 : 1;
  for (let offset = 1; offset <= choices.length; offset += 1) {
    const next = (index + direction * offset + choices.length) % choices.length;
    if (!choices[next]?.disabled) return next;
  }
  return -1;
}
function DraftControl(props) {
  const managed = managedPermissionState(props.effective, props.permission.permission_id);
  const choices = [
    { value: "inherit", label: "Recommended" },
    { value: "allow", label: "Allow", disabled: managed === "disabled" },
    { value: "block", label: "Block" }
  ];
  const tabStopIndex = extensionPolicyRadioTabStop(choices, props.state, props.disabled);
  const chooseAdjacent = (event, index) => {
    const next = nextExtensionPolicyRadioIndex(choices, index, event.key, props.disabled);
    if (next < 0) return;
    event.preventDefault();
    props.onChange(choices[next].value);
    event.currentTarget.parentElement?.querySelectorAll('[role="radio"]')[next]?.focus();
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "radiogroup", "aria-label": `${props.permission.label} protection setting`, className: "guard-segmented", children: choices.map((choice, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      role: "radio",
      "aria-checked": props.state === choice.value,
      tabIndex: !props.disabled && index === tabStopIndex ? 0 : -1,
      disabled: props.disabled || choice.disabled,
      title: choice.disabled ? "Your organization already blocks this capability; this device cannot weaken it." : void 0,
      onKeyDown: (event) => chooseAdjacent(event, index),
      onClick: () => props.onChange(choice.value),
      className: "disabled:cursor-not-allowed disabled:opacity-45",
      children: choice.label
    },
    choice.value
  )) });
}
function PermissionPolicyRow(props) {
  const managed = managedPermissionState(props.effective, props.permission.permission_id);
  const provenance = controlProvenance(props.effective, "permission", props.permission.permission_id);
  const example = props.permission.example_command ?? (props.extension.executables[0]?.trim() || props.permission.label);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { id: `pattern-${props.permission.permission_id}`, className: "guard-pattern-row", "data-permission-id": props.permission.permission_id, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: props.permission.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-pattern-example mt-1", children: example }),
      !props.permission.configurable ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs leading-5 text-brand-dark", children: [
        "Why this cannot be changed: ",
        props.permission.fixed_reason ?? "Guard marks this safety permission as immutable."
      ] }) : null,
      managed === "disabled" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 flex items-start gap-2 text-xs leading-5 text-indigo-950", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "mt-0.5 size-4 shrink-0" }),
        "Your organization blocks this capability. You can keep the organization setting or add a local block, but this device cannot weaken it."
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-2 text-xs text-brand-dark", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer font-semibold", children: "Technical setting details" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-wrap gap-x-4 gap-y-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            "Minimum protection: ",
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: treatmentLabel(props.permission.baseline_floor) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            props.permission.rule_ids.length,
            " governed rule",
            props.permission.rule_ids.length === 1 ? "" : "s"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            "Managed by: ",
            provenance.join(" · ")
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-[11px] text-brand-dark/80", children: props.permission.permission_id })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      DraftControl,
      {
        permission: props.permission,
        effective: props.effective,
        state: props.draftState,
        disabled: props.disabled || !props.permission.configurable || props.effective.health !== "protected",
        onChange: props.onChange
      }
    )
  ] });
}
function PreviewPanel(props) {
  const semantic = props.preview.semantic_preview;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Protection review" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-1 text-lg font-semibold text-brand-dark", children: "What will change" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          semantic.changed_target_count,
          " target",
          semantic.changed_target_count === 1 ? "" : "s"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          semantic.affected_permission_count,
          " permissions"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          semantic.affected_rule_count,
          " rules"
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-4 grid gap-3 sm:grid-cols-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Newly blocked settings" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-2xl font-semibold text-brand-dark", children: semantic.summary.newly_blocked_permissions })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Newly allowed settings" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-2xl font-semibold text-brand-dark", children: semantic.summary.newly_allowed_permissions })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Settings changing" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-2xl font-semibold text-brand-dark", children: semantic.summary.effective_change_count })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-3", children: semantic.changed_targets.map((target2) => /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "border-b border-[rgba(63,65,116,0.12)] py-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-brand-dark", children: target2.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          target2.before_explicit,
          " → ",
          target2.after_explicit
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          target2.before_effective,
          " → ",
          target2.after_effective
        ] }),
        target2.baseline_risk ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { tone: RISK_TONE[target2.baseline_risk], children: [
          target2.baseline_risk,
          " baseline"
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 text-xs text-brand-dark/80", children: [
        "Affects ",
        target2.affected_permission_ids.length,
        " permission",
        target2.affected_permission_ids.length === 1 ? "" : "s",
        " and ",
        target2.affected_rule_ids.length,
        " rule",
        target2.affected_rule_ids.length === 1 ? "" : "s",
        "."
      ] }),
      target2.affected_rule_ids.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-xs font-semibold text-brand-blue", children: "Developer details" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 max-h-40 overflow-auto", children: target2.affected_rule_ids.map((id2) => /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "block break-all text-[11px] text-brand-dark/80", children: id2 }, id2)) })
      ] }) : null,
      target2.warnings.map((warning2, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 flex items-start gap-2 text-xs leading-5 text-amber-950", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-4 shrink-0" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("strong", { children: [
            warning2.code,
            ":"
          ] }),
          " ",
          warning2.message
        ] })
      ] }, `${warning2.code}-${index}`))
    ] }, `${target2.target.kind}:${target2.target.target_id}`)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-xs font-semibold text-brand-dark/80", children: "Developer change identity" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-[11px] text-brand-dark/80", children: props.preview.canonical_diff_digest })
    ] })
  ] });
}
function PolicyReviewSheet(props) {
  const ref = useModalDialog(props.onClose, !props.busy);
  const [password, setPassword] = reactExports.useState("");
  const [totpCode, setTotpCode] = reactExports.useState("");
  const count = props.preview.semantic_preview.changed_target_count;
  const submitDisabled = isApprovalProofSubmitDisabled(props.approvalGate, { approvalPassword: password, approvalTotpCode: totpCode }, props.busy);
  const handleSubmit = (event) => {
    event.preventDefault();
    if (submitDisabled) return;
    props.onApply(buildApprovalProofCredentials(props.approvalGate, { approvalPassword: password, approvalTotpCode: totpCode }));
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 bg-brand-dark/40", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "form",
    {
      ref,
      tabIndex: -1,
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "extension-policy-review-title",
      onSubmit: handleSubmit,
      className: "absolute inset-y-0 right-0 flex w-full max-w-2xl flex-col overflow-y-auto bg-[var(--surface-1)] p-5 focus:outline-none sm:p-6",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Protection review" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("h2", { id: "extension-policy-review-title", className: "mt-1 text-xl font-semibold text-brand-dark", children: [
              "Review and apply ",
              count,
              " protection setting change",
              count === 1 ? "" : "s"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, "aria-label": "Close protection review", onClick: props.onClose, className: "grid size-11 place-items-center rounded-full text-brand-dark disabled:opacity-50", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 flex-1", children: /* @__PURE__ */ jsxRuntimeExports.jsx(PreviewPanel, { preview: props.preview }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 border-t border-[rgba(63,65,116,0.12)] pt-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Authenticate this exact change" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-5 text-brand-dark/75", children: "Guard uses a one-time local proof and rejects the apply if the reviewed settings changed." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
            ApprovalProofFieldInputs,
            {
              approvalGate: props.approvalGate,
              approvalPassword: password,
              approvalTotpCode: totpCode,
              onApprovalPasswordChange: (event) => setPassword(event.target.value),
              onApprovalTotpCodeChange: (event) => setTotpCode(event.target.value)
            }
          ) }),
          props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 text-sm text-red-950", children: props.error }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sticky bottom-0 mt-4 flex flex-wrap justify-end gap-2 bg-[var(--surface-1)] pb-1 pt-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onClose, className: "min-h-11 rounded-xl border border-[rgba(63,65,116,0.2)] px-4 text-sm font-semibold text-brand-dark", children: "Continue editing" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: submitDisabled, className: "min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-[#f4f7fb] disabled:opacity-40", children: props.busy ? "Applying…" : `Apply ${count} reviewed change${count === 1 ? "" : "s"}` })
          ] })
        ] })
      ]
    }
  ) });
}
function AppliedPolicyToast(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", "data-testid": "extension-policy-applied-toast", className: "mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-medium text-emerald-950", children: [
      "Applied · revision ",
      props.revision
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onViewHistory, className: "min-h-11 rounded-xl border border-emerald-300 bg-white/70 px-3 text-sm font-semibold text-emerald-950", children: "View history" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onUndo, className: "min-h-11 rounded-xl bg-emerald-800 px-3 text-sm font-semibold text-white", children: "Undo" })
    ] })
  ] });
}
function ExtensionPolicyPanel(props) {
  const [policyExtension, setPolicyExtension] = reactExports.useState(props.extension);
  const draft = useExtensionPolicyDraft({ effective: props.effective, onRefresh: props.onRefresh });
  const {
    baseEffective,
    dirty,
    preview,
    previewBusy,
    applyBusy,
    reviewOpen,
    error,
    stale,
    pendingRebase,
    refreshRequired,
    lastApplied,
    undoLastApplied,
    setReviewOpen,
    setPermissionState,
    resetDraft,
    runPreview,
    apply,
    rebaseDraft,
    keepConflicts,
    useCurrent,
    applyProfile,
    useHistoricalDraft,
    permissionState
  } = draft;
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  reactExports.useEffect(() => {
    props.onDirtyChange?.(dirty);
  }, [dirty, props.onDirtyChange]);
  reactExports.useEffect(() => {
    const beforeUnload = (event) => {
      if (!dirty) return;
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => window.removeEventListener("beforeunload", beforeUnload);
  }, [dirty]);
  reactExports.useEffect(() => {
    setPolicyExtension(props.extension);
    resetDraft();
  }, [props.extension.extension_id]);
  reactExports.useEffect(() => {
    if (!reviewOpen) return;
    void resolveApprovalGate({ failClosed: true }).catch(() => {
    });
  }, [reviewOpen, resolveApprovalGate]);
  const managedCount = policyExtension.permissions.filter((permission2) => managedPermissionState(baseEffective, permission2.permission_id) !== null).length;
  const changeCount = draft.changeCountFor(policyExtension.permissions.map((permission2) => permission2.permission_id));
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "extension-policy-editor", "aria-labelledby": "extension-policy-heading", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "extension-policy-heading", className: "text-lg font-semibold text-brand-dark", children: "Protection settings" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-brand-dark/80", children: "Recommended follows Guard defaults. Allow is available only where built-in safety and organization policy still permit it. Block is a stricter local floor." }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: baseEffective.health !== "protected" || refreshRequired, onClick: () => applyProfile(policyExtension.permissions, "recommended"), className: "min-h-10 px-1 text-xs font-semibold text-brand-blue disabled:opacity-40", children: "Recommended" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: baseEffective.health !== "protected" || refreshRequired, onClick: () => applyProfile(policyExtension.permissions, "stricter"), className: "min-h-10 px-1 text-xs font-semibold text-brand-dark disabled:opacity-40", children: "Stricter" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: true, className: "min-h-10 px-1 text-xs font-semibold text-brand-dark/55", children: "Custom" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "extension-settings-history", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionSettingsHistory, { catalogDigest: baseEffective.catalog_digest, disabled: baseEffective.health !== "protected" || refreshRequired, onUse: (layers) => useHistoricalDraft(layers) }) }),
    baseEffective.global_lockdown ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "status", className: "mt-4 flex gap-2 text-sm text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "mt-0.5 size-4 shrink-0" }),
      "Emergency Lockdown remains dominant. You can prepare a local draft, but matching commands stay blocked while lockdown is active."
    ] }) : null,
    baseEffective.health !== "protected" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "alert", className: "mt-4 flex gap-2 text-sm text-amber-950", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-4 shrink-0" }),
      "Settings cannot be changed until Guard verifies local settings integrity."
    ] }) : null,
    managedCount ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 text-sm text-indigo-950", children: [
      managedCount,
      " setting",
      managedCount === 1 ? " is" : "s are",
      " managed by your organization. This device can add stricter blocks but cannot weaken an organization block."
    ] }) : null,
    lastApplied ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      AppliedPolicyToast,
      {
        revision: lastApplied.revision,
        onUndo: () => {
          undoLastApplied();
        },
        onViewHistory: () => {
          document.getElementById("extension-settings-history")?.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }
    ) : refreshRequired ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "status", className: "mt-4 text-sm text-blue-950", children: "Settings applied. Editing stays locked until Guard reloads the current protected state." }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: (() => {
      const { ungrouped, families } = groupPermissionsByFamily(policyExtension.permissions);
      const renderRow = (permission2) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        PermissionPolicyRow,
        {
          permission: permission2,
          extension: policyExtension,
          effective: baseEffective,
          draftState: permissionState(permission2.permission_id),
          disabled: refreshRequired,
          onChange: (state) => setPermissionState(permission2.permission_id, state)
        },
        permission2.permission_id
      );
      return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        ungrouped.map(renderRow),
        families.map((group) => /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": `${group.heading} variants`, className: "guard-pattern-family", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { className: "guard-pattern-family-heading", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: group.heading }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
              group.permissions.length,
              " variant",
              group.permissions.length === 1 ? "" : "s"
            ] })
          ] }),
          group.permissions.map(renderRow)
        ] }, group.family))
      ] });
    })() }),
    dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-review-bar", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm text-brand-dark", children: [
        changeCount,
        " unsaved setting change",
        changeCount === 1 ? "" : "s",
        "."
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: previewBusy || applyBusy, onClick: resetDraft, className: "min-h-11 rounded-xl border border-[rgba(63,65,116,0.2)] px-4 text-sm font-semibold text-brand-dark", children: "Reset changes" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", disabled: previewBusy || applyBusy || baseEffective.health !== "protected" || stale, onClick: () => {
          void runPreview();
        }, className: "inline-flex min-h-11 items-center gap-2 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-[#f4f7fb] disabled:opacity-40", children: [
          previewBusy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4 animate-spin motion-reduce:animate-none" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-4" }),
          "Review ",
          changeCount,
          " change",
          changeCount === 1 ? "" : "s"
        ] })
      ] })
    ] }) }) : null,
    error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "alert", className: "mt-4 text-sm text-red-950", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-5 shrink-0" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: error })
      ] }),
      stale && !pendingRebase ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: previewBusy, onClick: () => {
        void rebaseDraft([policyExtension]);
      }, className: "mt-3 min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-[#f4f7fb]", children: "Update draft with latest protection" }) : null,
      pendingRebase ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-2", children: pendingRebase.result.conflicts.map((conflict) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "text-xs text-brand-dark", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all", children: conflict.original_permission_id }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1", children: conflict.kind === "removed" ? "Target removed from the current catalog." : `Current ${conflict.latest_state}; your draft requests ${conflict.requested_state}.` })
        ] }, conflict.original_permission_id)) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: keepConflicts, className: "min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-[#f4f7fb]", children: "Keep my compatible changes" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: useCurrent, className: "min-h-11 rounded-xl border border-red-300 px-4 text-sm font-semibold text-red-950", children: "Use current protection" })
        ] })
      ] }) : null
    ] }) : dirty && !preview ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex items-start gap-3 text-sm text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 size-5 shrink-0" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Review is required before approval. Guard calculates the real outcome from current protections, dependencies, organization settings, and Emergency Lockdown before anything can change." })
    ] }) : null,
    reviewOpen && preview ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyReviewSheet,
      {
        preview,
        approvalGate: resolvedApprovalGate,
        busy: applyBusy,
        error,
        onClose: () => {
          if (!applyBusy) setReviewOpen(false);
        },
        onApply: (credentials) => {
          void apply(credentials);
        }
      }
    ) : null
  ] });
}
const PROTECTION_CENTER_PERFORMANCE_BUDGETS = Object.freeze({
  simpleRuleRenderCap: 500,
  recentDecisionCap: 20,
  humanSearchCharacterCap: 160,
  humanSearchTermCap: 8,
  developerRelationshipCap: 1024
});
function patternSearchText(extension2, permission2) {
  return [
    permission2.label,
    permission2.description,
    permission2.example_command ?? "",
    permission2.family ?? "",
    permission2.permission_id,
    extension2.name,
    extension2.extension_id,
    ...extension2.executables
  ].join(" ").toLowerCase();
}
function searchCommandPatterns(extensions, rawQuery, limit = 24) {
  const normalized = rawQuery.trim().toLowerCase().slice(0, PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchCharacterCap);
  if (!normalized) return [];
  const terms = normalized.split(/\s+/).filter(Boolean).slice(0, PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchTermCap);
  const matches = [];
  for (const extension2 of extensions) {
    for (const permission2 of extension2.permissions) {
      const text2 = patternSearchText(extension2, permission2);
      if (terms.every((term) => text2.includes(term))) {
        matches.push({ extension: extension2, permission: permission2, score: terms.length });
      }
    }
  }
  return matches.sort(
    (left, right) => right.permission.risk_tier.localeCompare(left.permission.risk_tier) || left.permission.label.localeCompare(right.permission.label) || left.extension.name.localeCompare(right.extension.name)
  ).slice(0, limit);
}
const EXTENSION_PANEL_CLASS = "guard-extensions-panel p-5 sm:p-6";
const EXTENSION_CHIP_CLASS = "guard-extensions-chip";
const EXTENSION_ROW_CLASS = "guard-extensions-row";
function ProtectionStatusHero(props) {
  const safe = props.status.tone === "safe";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "protection-status-heading", className: "guard-status-bar", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-status-bar-icon", "data-tone": props.status.tone, "aria-hidden": "true", children: safe ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-4" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "size-4" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-400", children: "Local protection" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-0.5 flex flex-wrap items-baseline gap-x-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-status-heading", className: "text-sm font-semibold text-brand-dark", children: props.status.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm leading-5 text-brand-dark/70", children: props.status.summary })
      ] })
    ] }),
    props.status.primaryActionLabel && props.onPrimaryAction ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        "aria-busy": props.busy,
        disabled: props.busy,
        onClick: props.onPrimaryAction,
        className: "min-h-11 shrink-0 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white shadow-sm hover:bg-brand-dark disabled:cursor-wait disabled:opacity-60",
        children: props.busy ? "Working…" : props.status.primaryActionLabel
      }
    ) : safe ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex min-h-9 shrink-0 items-center gap-1.5 self-center rounded-full border border-emerald-200 bg-[#e8f7ee] px-3 text-xs font-semibold text-emerald-800", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "size-3.5" }),
      "No action required"
    ] }) : null,
    props.children ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "w-full border-t border-[rgba(63,65,116,0.08)] pt-2", children: props.children }) : null
  ] });
}
function ProtectionDecisionBadge({ result }) {
  const label = result === "allowed" ? "Allowed" : result === "ask-first" ? "Ask first" : "Blocked";
  const classes = result === "allowed" ? "border-emerald-200 bg-emerald-50 text-emerald-800" : result === "ask-first" ? "border-amber-200 bg-amber-50 text-amber-800" : "border-red-200 bg-red-50 text-red-800";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${classes}`, children: label });
}
function ProtectionModuleRow(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onOpen, className: `${EXTENSION_ROW_CLASS} motion-reduce:transition-none`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-brand-dark", children: props.name }),
        props.required ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold text-brand-dark/55", children: "Required" }) : null,
        props.managed ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold text-brand-dark/55", children: "Managed" }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 block truncate text-sm text-brand-dark/70", children: props.behavior })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "size-5 shrink-0 text-brand-dark/35", "aria-hidden": "true" })
  ] });
}
function TechnicalDetails(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: `${EXTENSION_PANEL_CLASS}`, "data-testid": props.testId, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer list-none text-sm font-semibold text-brand-dark", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-2", children: [
      props.title ?? "Technical details",
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "size-4", "aria-hidden": "true" })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 text-sm text-brand-dark/80", children: props.children })
  ] });
}
function InlineError({ message }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800", children: message });
}
function PatternSearchConsole(props) {
  const [query, setQuery] = reactExports.useState("");
  const [focused, setFocused] = reactExports.useState(false);
  const inputRef = reactExports.useRef(null);
  const draft = useExtensionPolicyDraft({ effective: props.effective, onRefresh: props.onRefresh });
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const {
    baseEffective,
    dirty,
    preview,
    previewBusy,
    applyBusy,
    reviewOpen,
    error,
    stale,
    refreshRequired,
    lastApplied,
    undoLastApplied,
    setReviewOpen,
    setPermissionState,
    resetDraft,
    runPreview,
    apply,
    permissionState,
    changeCountFor
  } = draft;
  reactExports.useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key !== "/" || event.defaultPrevented) return;
      const target2 = event.target;
      if (target2 && (target2.tagName === "INPUT" || target2.tagName === "TEXTAREA" || target2.isContentEditable)) return;
      event.preventDefault();
      inputRef.current?.focus();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);
  const matches = reactExports.useMemo(() => searchCommandPatterns(props.catalog, query), [props.catalog, query]);
  const toolMatches = reactExports.useMemo(() => {
    const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return [];
    return props.catalog.filter((extension2) => {
      const text2 = [extension2.name, extension2.extension_id, ...extension2.executables, ...extension2.aliases].join(" ").toLowerCase();
      return terms.every((term) => text2.includes(term));
    });
  }, [props.catalog, query]);
  const grouped = reactExports.useMemo(() => {
    const groups = /* @__PURE__ */ new Map();
    for (const match of matches) {
      const group = groups.get(match.extension.extension_id) ?? { extension: match.extension, permissionIds: [] };
      group.permissionIds.push(match.permission.permission_id);
      groups.set(match.extension.extension_id, group);
    }
    return [...groups.values()];
  }, [matches]);
  const involvedPermissions = reactExports.useMemo(() => matches.map((match) => match.permission), [matches]);
  const changeCount = changeCountFor(involvedPermissions.map((permission2) => permission2.permission_id));
  const showResults = query.trim().length > 0;
  reactExports.useEffect(() => {
    if (!reviewOpen) return;
    void resolveApprovalGate({ failClosed: true }).catch(() => {
    });
  }, [reviewOpen, resolveApprovalGate]);
  const managedCount = involvedPermissions.filter(
    (permission2) => managedPermissionState(baseEffective, permission2.permission_id) !== null
  ).length;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "pattern-search-heading", className: "mt-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "pattern-search-heading", className: "sr-only", children: "Search command patterns" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "relative block", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Search command patterns" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-brand-dark/55", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          ref: inputRef,
          type: "search",
          value: query,
          onFocus: () => setFocused(true),
          onChange: (event) => setQuery(event.target.value.slice(0, 160)),
          placeholder: 'Search any command Guard watches — "squash", "git push --force", "kubectl"…',
          "aria-describedby": "pattern-search-hint",
          className: "min-h-12 w-full rounded-2xl border border-[rgba(63,65,116,0.14)] bg-white/85 py-2.5 pl-9 pr-3 text-sm text-brand-dark shadow-sm focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100"
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: "pattern-search-hint", className: `mt-2 text-xs text-brand-dark/60 ${focused || showResults ? "" : "sr-only"}`, children: "Matches patterns across every tool. Press / to focus search from anywhere on this page." }),
    showResults ? matches.length || toolMatches.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3", children: [
      grouped.map((group) => /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": `${group.extension.name} patterns`, className: "guard-pattern-family", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { className: "guard-pattern-family-heading", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: group.extension.executables[0] ?? group.extension.extension_id }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: group.extension.name })
        ] }),
        group.permissionIds.map((permissionId) => {
          const permission2 = group.extension.permissions.find((item) => item.permission_id === permissionId);
          if (!permission2) return null;
          return /* @__PURE__ */ jsxRuntimeExports.jsx(
            PermissionPolicyRow,
            {
              permission: permission2,
              extension: group.extension,
              effective: baseEffective,
              draftState: permissionState(permission2.permission_id),
              disabled: refreshRequired,
              onChange: (state) => setPermissionState(permission2.permission_id, state)
            },
            permission2.permission_id
          );
        })
      ] }, group.extension.extension_id)),
      toolMatches.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Matching tools", className: "guard-pattern-family", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "guard-pattern-family-heading", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Tools" }) }),
        toolMatches.map((extension2) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          ProtectionModuleRow,
          {
            name: extension2.name,
            description: extension2.description,
            behavior: extension2.executables.join(" · "),
            required: extension2.required,
            onOpen: () => props.onOpenExtension(extension2)
          },
          extension2.extension_id
        ))
      ] }) : null,
      managedCount ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 text-xs text-indigo-950", children: [
        managedCount,
        " matched setting",
        managedCount === 1 ? "" : "s are",
        " managed by your organization and cannot be weakened on this device."
      ] }) : null,
      dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-review-bar", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm text-brand-dark", children: [
          changeCount,
          " unsaved setting change",
          changeCount === 1 ? "" : "s",
          "."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: previewBusy || applyBusy, onClick: resetDraft, className: "min-h-11 rounded-xl border border-[rgba(63,65,116,0.2)] px-4 text-sm font-semibold text-brand-dark", children: "Reset changes" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", disabled: previewBusy || applyBusy || baseEffective.health !== "protected" || stale, onClick: () => {
            void runPreview();
          }, className: "inline-flex min-h-11 items-center gap-2 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-[#f4f7fb] disabled:opacity-40", children: [
            previewBusy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4 animate-spin motion-reduce:animate-none" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-4" }),
            "Review ",
            changeCount,
            " change",
            changeCount === 1 ? "" : "s"
          ] })
        ] })
      ] }) }) : null,
      lastApplied ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        AppliedPolicyToast,
        {
          revision: lastApplied.revision,
          onUndo: () => {
            undoLastApplied();
          },
          onViewHistory: () => {
            document.getElementById("pattern-search-heading")?.scrollIntoView({ behavior: "smooth", block: "start" });
          }
        }
      ) : null,
      error ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "alert", className: "mt-4 text-sm text-red-950", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-5 shrink-0" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: error })
      ] }) }) : dirty && !preview ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex items-start gap-3 text-sm text-brand-dark", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 size-5 shrink-0" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Review is required before approval. Guard calculates the real outcome from current protections, dependencies, organization settings, and Emergency Lockdown before anything can change." })
      ] }) : null
    ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-brand-dark/75", children: "No command patterns or tools match this search." }) : null,
    reviewOpen && preview ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyReviewSheet,
      {
        preview,
        approvalGate: resolvedApprovalGate,
        busy: applyBusy,
        error,
        onClose: () => {
          if (!applyBusy) setReviewOpen(false);
        },
        onApply: (credentials) => {
          void apply(credentials);
        }
      }
    ) : null
  ] });
}
function ProtectionRepairCard(props) {
  const repairable = props.effective.health === "tampered" || props.effective.health === "recovery-required";
  const [open, setOpen] = reactExports.useState(false);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  if (!repairable) return null;
  const begin = async () => {
    try {
      await resolveApprovalGate({ failClosed: true });
      setError(null);
      setOpen(true);
    } catch {
      setError("Guard could not load the local approval gate. Repair was not started.");
    }
  };
  const repair = async (credentials) => {
    setBusy(true);
    setError(null);
    try {
      await recoverExtensionControlAuthority(credentials);
      setOpen(false);
      await props.onRefresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Guard could not repair settings integrity.");
    } finally {
      setBusy(false);
    }
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "protection-repair-heading", className: "guard-extensions-panel guard-extensions-tone-attention mt-5 p-5 sm:p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniWrenchScrewdriver, { className: "mt-0.5 size-5 shrink-0 text-amber-800", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-repair-heading", className: "font-semibold text-amber-950", children: "Repair protection settings integrity" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-6 text-amber-900", children: "Guard is staying fail-safe because the authenticated local settings state cannot be trusted. Repair rebuilds a protected local authority after explicit approval. Organization policy is not weakened." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: () => {
          void begin();
        }, className: "mt-4 min-h-11 rounded-xl bg-amber-900 px-4 text-sm font-semibold text-white", children: "Repair safely" }),
        error && !open ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 text-sm text-red-800", children: error }) : null
      ] })
    ] }),
    open ? /* @__PURE__ */ jsxRuntimeExports.jsx(ApprovalProofModal, { title: "Repair protection settings", detail: "Authenticate this local recovery. Guard will rebuild settings integrity fail-safe and then reload the current protected state.", confirmLabel: "Repair settings", approvalGate: resolvedApprovalGate, busy, error, onCancel: () => {
      if (!busy) setOpen(false);
    }, onConfirm: (credentials) => {
      void repair(credentials);
    } }) : null
  ] });
}
const DECISIONS = /* @__PURE__ */ new Set(["allowed", "ask-first", "blocked"]);
const MINIMUM_ACTIONS = /* @__PURE__ */ new Set(["allow", "monitor", "review", "block"]);
const SEVERITIES = /* @__PURE__ */ new Set(["low", "medium", "high", "critical"]);
function record(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("Guard returned an invalid Test Lab response");
  return value;
}
function boundedString(value, field, limit = 512) {
  if (typeof value !== "string" || !value.trim() || value.length > limit) throw new Error(`Guard returned an invalid ${field}`);
  return value;
}
function stringList(value, field, limit) {
  if (!Array.isArray(value) || value.length > limit || !value.every((item) => typeof item === "string" && item.length <= 320)) {
    throw new Error(`Guard returned an invalid ${field}`);
  }
  return [...value];
}
function normalizeProtectionTestResult(value) {
  const raw = record(value);
  if (raw.schema_version !== "guard.daemon.extension-control-test.v1") throw new Error("Guard returned an unsupported Test Lab response");
  if (typeof raw.decision !== "string" || !DECISIONS.has(raw.decision)) throw new Error("Guard returned an invalid Test Lab decision");
  if (typeof raw.minimum_action !== "string" || !MINIMUM_ACTIONS.has(raw.minimum_action)) throw new Error("Guard returned an invalid Test Lab action");
  if (typeof raw.matched !== "boolean" || typeof raw.module_matched !== "boolean" || typeof raw.other_protection_matched !== "boolean") {
    throw new Error("Guard returned invalid Test Lab match state");
  }
  if (!Array.isArray(raw.matches) || raw.matches.length > 32) throw new Error("Guard returned too many Test Lab matches");
  const matches = raw.matches.map((item) => {
    const match = record(item);
    if (typeof match.severity !== "string" || !SEVERITIES.has(match.severity)) throw new Error("Guard returned an invalid Test Lab severity");
    return {
      extension_id: boundedString(match.extension_id, "extension ID", 256),
      extension_name: boundedString(match.extension_name, "extension name", 120),
      rule_id: boundedString(match.rule_id, "rule ID", 256),
      permission_id: typeof match.permission_id === "string" && match.permission_id.trim() ? match.permission_id : null,
      rule_title: boundedString(match.rule_title, "rule title", 160),
      description: boundedString(match.description, "rule description", 320),
      severity: match.severity,
      risk_classes: stringList(match.risk_classes, "risk classes", 16)
    };
  });
  if (typeof raw.revision !== "number" || !Number.isSafeInteger(raw.revision) || raw.revision < 0) throw new Error("Guard returned an invalid Test Lab revision");
  return {
    schema_version: "guard.daemon.extension-control-test.v1",
    decision: raw.decision,
    minimum_action: raw.minimum_action,
    matched: raw.matched,
    module_matched: raw.module_matched,
    other_protection_matched: raw.other_protection_matched,
    explanation: boundedString(raw.explanation, "Test Lab explanation", 320),
    matches,
    safer_alternatives: stringList(raw.safer_alternatives, "safer alternatives", 8),
    authority_health: boundedString(raw.authority_health, "authority health", 64),
    revision: raw.revision,
    catalog_digest: boundedString(raw.catalog_digest, "catalog digest", 128)
  };
}
async function testProtectionCommand(extensionId, command) {
  const response = await fetchExtensionControlApi("/v1/extension-controls/test", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ extension_id: extensionId, command })
  });
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Guard returned invalid JSON (${response.status})`);
  }
  if (!response.ok) {
    const raw = typeof payload === "object" && payload !== null && !Array.isArray(payload) ? payload : {};
    throw new Error(typeof raw.error === "string" ? raw.error.replaceAll("_", " ") : `Test Lab request failed (${response.status})`);
  }
  return normalizeProtectionTestResult(payload);
}
function safeExamples(extension2) {
  const executable = extension2.executables[0];
  const examples = extension2.extension_id === "command.git" ? ["git status", "git reset --hard HEAD~1", "git push --force-with-lease"] : executable ? [`${executable} --help`] : [];
  return examples.slice(0, 3);
}
function resultTitle(result) {
  if (result.decision === "blocked") return "Guard would block this";
  if (result.decision === "ask-first") return "Guard would ask first";
  return "Guard would allow this";
}
function ProtectionTestLab({ extension: extension2 }) {
  const [command, setCommand] = reactExports.useState("");
  const [result, setResult] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const examples = reactExports.useMemo(() => safeExamples(extension2), [extension2]);
  const run = async () => {
    const candidate = command.trim();
    if (!candidate || busy) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await testProtectionCommand(extension2.extension_id, candidate));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Test Lab could not evaluate this command.");
    } finally {
      setBusy(false);
    }
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "protection-test-lab-heading", className: "mt-10 rounded-2xl border border-slate-200 bg-white p-5 sm:p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-baseline justify-between gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-test-lab-heading", className: "text-lg font-semibold tracking-tight text-brand-dark", children: "Test Lab" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Nothing is executed. The check runs locally and is not saved." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-sm text-slate-500", children: [
      "See how Guard would handle a ",
      extension2.name,
      " command without running it."
    ] }),
    examples.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 flex flex-wrap gap-2", children: examples.map((example) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: busy, onClick: () => {
      setCommand(example);
      setResult(null);
      setError(null);
    }, className: `${EXTENSION_CHIP_CLASS} disabled:cursor-not-allowed disabled:opacity-50`, children: example }, example)) }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-col gap-2 sm:flex-row", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          value: command,
          disabled: busy,
          onChange: (event) => {
            setCommand(event.target.value.slice(0, 4096));
            setResult(null);
            setError(null);
          },
          onKeyDown: (event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              void run();
            }
          },
          maxLength: 4096,
          spellCheck: false,
          autoComplete: "off",
          "aria-label": "Command to check",
          placeholder: "Paste a command Guard stopped, like git reset --hard HEAD~1",
          className: "min-h-11 w-full flex-1 rounded-xl border border-slate-200 bg-white px-3 font-mono text-sm text-brand-dark placeholder:font-sans placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: () => {
        void run();
      }, disabled: busy || !command.trim(), className: "min-h-11 shrink-0 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50", children: busy ? "Checking…" : "Check safely" })
    ] }),
    error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-800", children: error }) : null,
    result ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", className: "mt-5 rounded-xl bg-slate-50 p-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionDecisionBadge, { result: result.decision }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-brand-dark", children: resultTitle(result) }),
        result.decision === "allowed" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "size-5 text-emerald-700", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "size-5 text-amber-700", "aria-hidden": "true" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm leading-6 text-brand-dark/80", children: result.explanation }),
      result.matches.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.14em] text-slate-400", children: "Protection rules involved" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 space-y-2", children: result.matches.slice(0, 6).map((match) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl bg-white p-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-brand-dark", children: match.rule_title }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs font-semibold capitalize text-brand-dark/55", children: [
              match.severity,
              " risk"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-5 text-brand-dark/70", children: match.description })
        ] }, `${match.extension_id}:${match.rule_id}`)) })
      ] }) : null,
      result.safer_alternatives.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.14em] text-slate-400", children: "Safer alternatives" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 list-disc space-y-1 pl-5 text-sm text-brand-dark/80", children: result.safer_alternatives.map((alternative) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: alternative }, alternative)) })
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-xs text-slate-500", children: "This result uses the current local protection state. It is a read-only evaluation and does not create an approval or receipt." })
    ] }) : null
  ] });
}
function sourceForTarget(effective, targetKind, targetId2) {
  for (const layer of effective.layers) {
    if (!layer.controls.some((control) => control.target_kind === targetKind && control.target_id === targetId2)) continue;
    return layer.kind === "signed-cloud" ? "organization" : "device";
  }
  return "built-in";
}
function requiredLine(extension2) {
  if (!extension2.required) return null;
  return "This tool stays on. Individual command patterns below can follow recommended settings or be blocked on this device.";
}
function DeveloperModuleDetails(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(TechnicalDetails, { title: "Developer details", testId: "protection-more-detail", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-brand-dark", children: "Canonical module" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-3 grid gap-3 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Extension ID" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all text-xs", children: props.extension.extension_id }) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Version" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "text-sm", children: props.extension.version })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Catalog digest" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all text-xs", children: props.catalogDigest }) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Provenance" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "text-sm", children: controlProvenance(props.effective, "extension", props.extension.extension_id).join(" · ") })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-brand-dark", children: "Detections" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 max-h-96 overflow-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "min-w-full text-left text-xs", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { className: "sticky top-0 bg-[var(--surface-1)] text-brand-dark/80", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-3 py-2", children: "Detection" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-3 py-2", children: "Severity" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-3 py-2", children: "Matcher" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-3 py-2", children: "Default" })
        ] }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { children: props.extension.rules.map((rule2) => /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "border-t border-[rgba(63,65,116,0.08)]", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("td", { className: "px-3 py-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-medium text-brand-dark/80", children: rule2.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all text-[10px] text-brand-dark/80", children: rule2.rule_id })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-3 py-2", children: rule2.severity }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-3 py-2", children: rule2.matcher_kind }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-3 py-2", children: treatmentLabel(rule2.default_mode) })
        ] }, rule2.rule_id)) })
      ] }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-brand-dark", children: "Protection setting identifiers" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 space-y-2", children: props.extension.permissions.map((permission2) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "py-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-sm font-medium text-brand-dark/80", children: permission2.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-1 block break-all text-[11px] text-brand-dark/80", children: permission2.permission_id }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1 text-xs text-brand-dark/80", children: permission2.action_classes.join(", ") || "No action classes" })
      ] }, permission2.permission_id)) })
    ] })
  ] }) });
}
function ProtectionModuleDetail(props) {
  const [policyDirty, setPolicyDirty] = reactExports.useState(false);
  reactExports.useEffect(() => {
    let highlightTimer = 0;
    let highlighted = null;
    const clearHighlight = () => {
      if (highlightTimer) window.clearTimeout(highlightTimer);
      highlightTimer = 0;
      highlighted?.classList.remove("guard-pattern-row-highlight");
      highlighted = null;
    };
    const highlight = () => {
      const anchor = window.location.hash;
      let rowId = null;
      let ruleId = null;
      if (anchor.startsWith("#pattern-")) {
        rowId = anchor.slice(1);
      } else if (anchor.startsWith("#rule-")) {
        ruleId = anchor.slice("#rule-".length);
      } else {
        const fragment = anchor.startsWith("#") ? anchor.slice(1) : anchor;
        const requested = new URLSearchParams(fragment).get("rule");
        if (requested) ruleId = requested;
      }
      if (ruleId) {
        const rule2 = props.extension.rules.find((item) => item.rule_id === ruleId);
        const permission2 = rule2 ? permissionForRule(props.extension, rule2) : null;
        rowId = permission2 ? `pattern-${permission2.permission_id}` : null;
      }
      clearHighlight();
      if (!rowId) return;
      const row = document.getElementById(rowId);
      if (!row) return;
      row.scrollIntoView({ behavior: "smooth", block: "center" });
      row.classList.add("guard-pattern-row-highlight");
      highlighted = row;
      highlightTimer = window.setTimeout(clearHighlight, 2400);
    };
    highlight();
    window.addEventListener("hashchange", highlight);
    return () => {
      window.removeEventListener("hashchange", highlight);
      clearHighlight();
    };
  }, [props.extension.extension_id, props.extension.rules]);
  const requiredNote = requiredLine(props.extension);
  const extensionEnabled = !props.effective.layers.some(
    (layer) => layer.controls.some((control) => control.target_kind === "extension" && control.target_id === props.extension.extension_id && control.state === "disabled")
  );
  const orgManaged = sourceForTarget(props.effective, "extension", props.extension.extension_id) === "organization";
  const handleBack = () => {
    if (policyDirty && !window.confirm("Discard your unreviewed protection setting changes?")) return;
    props.onBack();
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { "data-testid": "protection-module-detail", className: "w-full", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: handleBack, className: "inline-flex min-h-11 items-center gap-2 rounded-lg px-1 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowLeft, { className: "size-4", "aria-hidden": "true" }),
      "Extensions"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "mt-4 border-b border-slate-200 pb-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-xs font-semibold tracking-[0.14em] text-slate-400", children: props.extension.executables.join(" · ") }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "mt-2 text-2xl font-semibold tracking-tight text-brand-dark", children: props.extension.name }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-slate-500", children: props.extension.description }),
      requiredNote ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 max-w-2xl text-sm leading-6 text-brand-dark/80", children: requiredNote }) : null,
      props.extension.required ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark/70", children: "This protection is required by Guard and cannot be turned off." }) : props.onRequestExtensionChange ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            role: "switch",
            "aria-checked": extensionEnabled,
            disabled: props.effective.health !== "protected",
            onClick: () => props.onRequestExtensionChange?.(props.extension, !extensionEnabled),
            className: "guard-tool-switch",
            "data-testid": "extension-availability-switch",
            children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-tool-switch-knob" })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Commands available" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-5 text-brand-dark/75", children: extensionEnabled ? "Matching commands follow the protection settings below. Turn off to block every command this tool owns on this device." : "Every command this tool owns is blocked on this device. Turn on to follow the protection settings below." })
        ] })
      ] }) : null,
      orgManaged ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-brand-dark/80", children: "Your organization controls part of this protection. Local changes cannot weaken organization policy." }) : null,
      props.effective.global_lockdown ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "status", className: "mt-4 flex gap-2 text-sm text-brand-dark", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "mt-0.5 size-4 shrink-0" }),
        "Emergency Lockdown currently controls this module. Matching optional actions remain blocked."
      ] }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionRepairCard, { effective: props.effective, onRefresh: props.onRefresh }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionPolicyPanel,
      {
        extension: props.extension,
        effective: props.effective,
        catalogDigest: props.catalogDigest,
        onRefresh: props.onRefresh,
        onDirtyChange: setPolicyDirty
      }
    ) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-10", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionTestLab, { extension: props.extension }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-8", children: /* @__PURE__ */ jsxRuntimeExports.jsx(DeveloperModuleDetails, { extension: props.extension, effective: props.effective, catalogDigest: props.catalogDigest }) })
  ] });
}
function deriveProtectionStatus(effective) {
  if (effective.global_lockdown) {
    return {
      status: "lockdown",
      title: "Emergency Lockdown active",
      summary: "Guard is blocking matching optional actions until you review and end lockdown.",
      tone: "danger",
      primaryAction: "review-lockdown",
      primaryActionLabel: "Review lockdown"
    };
  }
  switch (effective.health) {
    case "protected":
      return {
        status: "protected",
        title: "Protected",
        summary: "Guard is actively applying the trusted protection settings on this device.",
        tone: "safe",
        primaryAction: "none",
        primaryActionLabel: null
      };
    case "unenrolled":
      return {
        status: "finish-setup",
        title: "Finish setup",
        summary: "Complete local setup so Guard can protect and verify settings on this device.",
        tone: "attention",
        primaryAction: "finish-setup",
        primaryActionLabel: "Show setup steps"
      };
    case "tampered":
    case "recovery-required":
      return {
        status: "needs-repair",
        title: "Needs repair",
        summary: "Guard detected a problem with trusted protection settings and is staying fail-safe until they are repaired.",
        tone: "danger",
        primaryAction: "repair",
        primaryActionLabel: "Repair protection"
      };
    case "degraded-unacknowledged":
      return {
        status: "limited",
        title: "Protection limited",
        summary: "Guard is staying fail-safe because it cannot fully verify protection settings. Repair is recommended.",
        tone: "attention",
        primaryAction: "repair",
        primaryActionLabel: "Restore protection"
      };
    case "degraded-acknowledged":
      return {
        status: "limited",
        title: "Protection limited",
        summary: "Guard is still staying fail-safe. The earlier acknowledgement did not restore trusted protection.",
        tone: "attention",
        primaryAction: "retry-repair",
        primaryActionLabel: "Try repair again"
      };
    default:
      return {
        status: "unavailable",
        title: "Protection status unavailable",
        summary: "Guard could not verify the current protection state. Refresh before making any protection changes.",
        tone: "neutral",
        primaryAction: "refresh",
        primaryActionLabel: "Check again"
      };
  }
}
function currentExtensionRouteState() {
  return {
    route: parseExtensionRoute(window.location.pathname),
    detail: readExtensionDetailUrlState(window.location.search)
  };
}
function extensionRecoveryAction(health) {
  if (health === "protected") return null;
  if (health === "tampered" || health === "recovery-required") {
    return {
      title: "Repair extension controls",
      actionLabel: "Repair now",
      copyLabel: "Copy repair command",
      description: "Guard locked these settings after detecting damaged authority data. Authenticate on this device to rebuild trusted authority.",
      command: "hol-guard command controls recover-authority"
    };
  }
  if (health === "degraded-unacknowledged") {
    return {
      title: "Acknowledge degraded extension controls",
      actionLabel: "Acknowledge degraded state",
      copyLabel: "Copy status command",
      description: "Guard is failing closed because extension-control authority is degraded. Authenticate to acknowledge the degraded state. Acknowledgement does not restore protected authority.",
      command: "hol-guard status"
    };
  }
  if (health === "degraded-acknowledged") {
    return {
      title: "Degraded extension controls acknowledged",
      copyLabel: "Copy status command",
      description: "Guard remains fail-closed while extension-control authority is degraded. Restore protected authority before changing extension policy.",
      command: "hol-guard status"
    };
  }
  return {
    title: "Finish local enrollment",
    copyLabel: "Copy enrollment command",
    description: "Authenticate in this device's terminal to protect extension settings, then check again.",
    command: "hol-guard command controls enroll"
  };
}
function requiresExtensionRecoveryApproval(error) {
  return error instanceof ExtensionControlApiError && (error.code === "approval_required" || error.code?.startsWith("approval_gate_") === true);
}
function randomToken() {
  return crypto.randomUUID().replaceAll("-", "");
}
function buildExtensionMutation(state, change) {
  const layers = structuredClone(state.effective.layers);
  let local = layers.find((layer) => layer.kind === "local-admin");
  if (!local) {
    local = {
      schema_version: "1.0.0",
      kind: "local-admin",
      catalog_digest: state.catalog.catalog_digest,
      global_lockdown: false,
      controls: []
    };
    layers.push(local);
  }
  if ("globalLockdown" in change) {
    local.global_lockdown = change.globalLockdown;
  } else {
    local.controls = local.controls.filter(
      (control) => control.target_kind !== "extension" || control.target_id !== change.extension.extension_id
    );
    local.controls.push({
      target_kind: "extension",
      target_id: change.extension.extension_id,
      state: change.enabled ? "enabled" : "disabled"
    });
    local.controls.sort(
      (left, right) => `${left.target_kind}:${left.target_id}`.localeCompare(`${right.target_kind}:${right.target_id}`)
    );
  }
  return {
    previous_revision: state.effective.revision,
    catalog_digest: state.catalog.catalog_digest,
    layers,
    actor_id: "dashboard-admin",
    idempotency_key: randomToken(),
    nonce: randomToken()
  };
}
function ExtensionStatusBanner(props) {
  const [copyState, setCopyState] = reactExports.useState("idle");
  const recovery = extensionRecoveryAction(props.effective.health);
  const handleCopy = reactExports.useCallback(async () => {
    if (!recovery) return;
    try {
      await navigator.clipboard.writeText(recovery.command);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }, [recovery]);
  if (props.effective.health === "protected") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-5 shrink-0", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Protected authority" }),
        " · revision ",
        props.effective.revision
      ] })
    ] });
  }
  const repairable = props.effective.health === "tampered" || props.effective.health === "recovery-required" || props.effective.health === "degraded-unacknowledged";
  const busyLabel = props.effective.health === "degraded-unacknowledged" ? "Acknowledging…" : "Repairing…";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-2xl border border-amber-200 bg-amber-50 p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 inline-flex size-9 shrink-0 items-center justify-center rounded-full bg-amber-100 text-amber-800", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "size-5", "aria-hidden": "true" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-amber-950", children: recovery?.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-6 text-amber-950", children: recovery?.description }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center gap-2", children: [
        repairable && props.onRecover ? /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", "aria-busy": props.busy, disabled: props.busy, onClick: props.onRecover, className: "inline-flex min-h-11 items-center gap-2 rounded-lg bg-brand-blue px-4 py-2 text-sm font-semibold text-white disabled:opacity-60", children: [
          props.busy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4 animate-spin motion-reduce:animate-none", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-4", "aria-hidden": "true" }),
          props.busy ? busyLabel : recovery?.actionLabel
        ] }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onRetry, className: "inline-flex min-h-11 items-center gap-2 rounded-lg border border-amber-300 bg-white px-3 py-2 text-sm font-semibold text-amber-950 hover:bg-amber-100", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4", "aria-hidden": "true" }),
          "Check again"
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 border-t border-amber-200 pt-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-amber-900", children: "Command-line fallback" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-col gap-2 sm:flex-row sm:items-center", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "min-w-0 flex-1 overflow-x-auto rounded-lg border border-amber-200 bg-white px-3 py-2 text-xs text-amber-950", children: recovery?.command }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: handleCopy, className: "inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-amber-300 bg-white px-3 py-2 text-sm font-semibold text-brand-blue", children: [
            copyState === "copied" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocumentCheck, { className: "size-4", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboard, { className: "size-4", "aria-hidden": "true" }),
            copyState === "copied" ? "Copied" : recovery?.copyLabel
          ] })
        ] }),
        copyState === "failed" ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { role: "status", className: "mt-2 block text-sm text-red-800", children: "Copy failed. Select the command above." }) : null
      ] }),
      props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 text-sm font-medium text-red-800", children: props.error }) : null,
      props.status ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm font-medium text-amber-950", children: props.status }) : null
    ] })
  ] }) });
}
function ReviewModal(props) {
  const [password, setPassword] = reactExports.useState("");
  const [totp, setTotp] = reactExports.useState("");
  const dialogRef = useModalDialog(props.onCancel, !props.busy);
  const title = "globalLockdown" in props.change ? `${props.change.globalLockdown ? "Enable" : "Disable"} Emergency Lockdown` : `${props.change.enabled ? "Permit" : "Block"} ${props.change.extension.name}`;
  const current = "globalLockdown" in props.change ? props.change.globalLockdown ? "Off" : "Active" : props.change.enabled ? "Blocked" : "Allowed";
  const requested = "globalLockdown" in props.change ? props.change.globalLockdown ? "Active" : "Off" : props.change.enabled ? "Allowed within Guard safety rules" : "Blocked";
  const handleSubmit = reactExports.useCallback((event) => {
    event.preventDefault();
    props.onConfirm(buildApprovalProofCredentials(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }));
  }, [password, props, totp]);
  const submitDisabled = isApprovalProofSubmitDisabled(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }, props.busy);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { ref: dialogRef, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "protection-review-title", onSubmit: handleSubmit, className: "w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl focus:outline-none", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Review protection change" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-review-title", className: "mt-2 text-xl font-semibold text-brand-dark", children: title })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onCancel, "aria-label": "Close review", className: "grid size-11 place-items-center rounded-full text-brand-dark hover:bg-white/70 disabled:opacity-50", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 grid grid-cols-[1fr_auto_1fr] items-center gap-3 rounded-2xl bg-[rgba(85,153,254,0.08)] p-4 text-sm text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Current" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "→" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Requested" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: current }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", {}),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: requested })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-sm leading-6 text-brand-dark", children: "Guard's built-in minimum safety rules and organization policy remain active. This change does not disable detection." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ApprovalProofFieldInputs, { approvalGate: props.approvalGate, approvalPassword: password, approvalTotpCode: totp, onApprovalPasswordChange: (event) => setPassword(event.target.value), onApprovalTotpCodeChange: (event) => setTotp(event.target.value) }) }),
    props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-4 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800", children: props.error }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex justify-end gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onCancel, className: "min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark hover:bg-white/70 disabled:opacity-50", children: "Cancel" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: submitDisabled, className: "min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white hover:bg-brand-dark disabled:opacity-60", children: props.busy ? "Verifying…" : "Confirm change" })
    ] })
  ] }) });
}
function sourceIsManaged(effective, extensionId) {
  return effective.layers.some((layer) => layer.kind === "signed-cloud" && layer.controls.some((control) => control.target_kind === "extension" && control.target_id === extensionId));
}
function ProtectionCenterWorkspace() {
  const [state, setState] = reactExports.useState({ kind: "loading" });
  const [routeState, setRouteState] = reactExports.useState(() => currentExtensionRouteState());
  const [pending, setPending] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [mutationError, setMutationError] = reactExports.useState(null);
  const [recoveryApprovalOpen, setRecoveryApprovalOpen] = reactExports.useState(false);
  const [recoveryBusy, setRecoveryBusy] = reactExports.useState(false);
  const [recoveryError, setRecoveryError] = reactExports.useState(null);
  const [recoveryStatus, setRecoveryStatus] = reactExports.useState(null);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const aliasRedirected = reactExports.useRef(null);
  const load = reactExports.useCallback(async () => {
    setState((current) => current.kind === "ready" ? current : { kind: "loading" });
    try {
      const [catalog, effective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      if (catalog.catalog_digest !== effective.catalog_digest) throw new Error("Protection data changed while Guard was loading. Check again before making changes.");
      setState({ kind: "ready", catalog, effective });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : "Extensions are unavailable" });
    }
  }, []);
  reactExports.useEffect(() => {
    void load();
  }, [load]);
  reactExports.useEffect(() => {
    const onPopState = () => setRouteState(currentExtensionRouteState());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  const catalogExtensions = reactExports.useMemo(() => state.kind === "ready" ? [...state.catalog.extensions].sort((a, b) => a.name.localeCompare(b.name)) : [], [state]);
  const requestedExtensionId = routeState.route.kind === "detail" ? routeState.route.extensionId : null;
  const canonicalSelected = reactExports.useMemo(() => canonicalExtensionId(catalogExtensions, requestedExtensionId), [catalogExtensions, requestedExtensionId]);
  const selectedExtension = reactExports.useMemo(() => catalogExtensions.find((item) => item.extension_id === canonicalSelected) ?? null, [catalogExtensions, canonicalSelected]);
  reactExports.useEffect(() => {
    if (state.kind !== "ready" || routeState.route.kind !== "detail" || !canonicalSelected) return;
    if (routeState.route.extensionId === canonicalSelected) return;
    const key = `${routeState.route.extensionId}->${canonicalSelected}`;
    if (aliasRedirected.current === key) return;
    aliasRedirected.current = key;
    const href = extensionDetailHref(canonicalSelected, routeState.detail);
    window.history.replaceState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail: routeState.detail });
  }, [canonicalSelected, routeState, state]);
  const openExtension = reactExports.useCallback((extension2) => {
    const href = extensionDetailHref(extension2.extension_id, DEFAULT_EXTENSION_DETAIL_URL_STATE);
    window.history.pushState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: extension2.extension_id }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const closeExtension = reactExports.useCallback(() => {
    window.history.pushState({}, "", "/extensions");
    setRouteState({ route: { kind: "overview" }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  reactExports.useCallback((next) => {
    if (!canonicalSelected) return;
    const href = extensionDetailHref(canonicalSelected, next);
    window.history.pushState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail: next });
  }, [canonicalSelected]);
  const requestChange = reactExports.useCallback((change) => {
    setMutationError(null);
    void resolveApprovalGate({ failClosed: true }).then(() => setPending(change)).catch(() => setMutationError("Guard could not load local approval settings. Check the local connection and try again."));
  }, [resolveApprovalGate]);
  const confirm = reactExports.useCallback(async (credentials) => {
    if (state.kind !== "ready" || !pending) return;
    setBusy(true);
    setMutationError(null);
    try {
      const payload = buildExtensionMutation(state, pending);
      Object.assign(payload, credentials);
      payload.session_nonce = randomToken();
      const preview = await previewExtensionMutation(payload);
      if (typeof preview.proof_id !== "string") throw new Error("Guard did not issue a one-use proof for this protection change.");
      payload.proof_id = preview.proof_id;
      await applyExtensionMutation(payload);
      setPending(null);
      await load();
    } catch (error) {
      const recovery = error instanceof ExtensionControlApiError ? error.recoveryAction : void 0;
      setMutationError(`${error instanceof Error ? error.message : "Protection change failed"}${recovery ? ` · ${recovery}` : ""}`);
    } finally {
      setBusy(false);
    }
  }, [load, pending, state]);
  const recover = reactExports.useCallback(async (credentials) => {
    const acknowledgingDegraded = state.kind === "ready" && state.effective.health === "degraded-unacknowledged";
    setRecoveryBusy(true);
    setRecoveryError(null);
    setRecoveryStatus(acknowledgingDegraded ? "Confirming the limited state…" : "Repairing local protection…");
    try {
      const effective = acknowledgingDegraded ? await acknowledgeDegradedExtensionControlAuthority(credentials) : await recoverExtensionControlAuthority(credentials);
      if (acknowledgingDegraded) {
        if (effective.health !== "degraded-acknowledged") throw new Error("Guard could not confirm the limited state.");
        setRecoveryStatus("The limited state is acknowledged. Guard remains fail-safe until trusted protection can be restored.");
      } else {
        if (effective.health !== "protected") throw new Error("Guard could not verify repaired protection.");
        setRecoveryStatus("Local protection repaired and verified.");
      }
      if (state.kind === "ready") setState({ ...state, effective });
      setRecoveryApprovalOpen(false);
    } catch (error) {
      if (!credentials && requiresExtensionRecoveryApproval(error)) {
        try {
          await resolveApprovalGate({ failClosed: true });
          setRecoveryApprovalOpen(true);
          setRecoveryStatus(null);
        } catch {
          setRecoveryError("Guard could not load local approval settings. Check the local connection and try again.");
          setRecoveryStatus(null);
        }
      } else {
        setRecoveryError(error instanceof Error ? error.message : "Guard could not repair local protection.");
        setRecoveryStatus(null);
      }
    } finally {
      setRecoveryBusy(false);
    }
  }, [resolveApprovalGate, state]);
  if (state.kind === "loading") return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid min-h-[60vh] place-items-center", "aria-busy": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-7 animate-spin text-brand-blue motion-reduce:animate-none", "aria-label": "Loading Extensions" }) });
  if (state.kind === "error") {
    const loadError = protectionCenterLoadError(state.message);
    return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mx-auto max-w-4xl", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${EXTENSION_PANEL_CLASS} guard-extensions-tone-danger`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-xl font-semibold text-red-950", children: loadError.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-2 text-sm text-red-800", children: loadError.detail }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs font-medium text-red-900", children: "Local protection continues on this device." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: load, className: "mt-4 min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-white", children: "Try again" })
    ] }) });
  }
  const recoveryModal = recoveryApprovalOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx(
    ApprovalProofModal,
    {
      title: state.effective.health === "degraded-unacknowledged" ? "Confirm limited protection state" : "Repair local protection",
      detail: state.effective.health === "degraded-unacknowledged" ? "Authenticate this acknowledgement on your device. It does not restore full protection." : "Authenticate this repair on your device. Guard uses the proof once and does not store it.",
      confirmLabel: state.effective.health === "degraded-unacknowledged" ? "Acknowledge limited state" : "Repair protection",
      approvalGate: resolvedApprovalGate,
      busy: recoveryBusy,
      error: recoveryError,
      onCancel: () => {
        if (!recoveryBusy) setRecoveryApprovalOpen(false);
      },
      onConfirm: (credentials) => {
        void recover(credentials);
      }
    }
  ) : null;
  if (routeState.route.kind === "detail" && selectedExtension) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionModuleDetail, { extension: selectedExtension, effective: state.effective, catalogDigest: state.catalog.catalog_digest, onBack: closeExtension, onRefresh: load, onRequestExtensionChange: (extension2, enabled) => requestChange({ extension: { extension_id: extension2.extension_id, name: extension2.name }, enabled }) }),
      pending ? /* @__PURE__ */ jsxRuntimeExports.jsx(ReviewModal, { change: pending, busy, error: mutationError, approvalGate: resolvedApprovalGate, onCancel: () => {
        if (!busy) setPending(null);
      }, onConfirm: confirm }) : null,
      recoveryModal
    ] });
  }
  if (routeState.route.kind === "detail" || routeState.route.kind === "invalid") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mx-auto max-w-4xl", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${EXTENSION_PANEL_CLASS} guard-extensions-tone-attention`, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "font-semibold text-amber-950", children: "Extension not found" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-amber-900", children: "This link does not match an extension in the current Guard catalog." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: closeExtension, className: "mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white", children: "Back to Extensions" })
      ] }) }),
      recoveryModal
    ] });
  }
  const status = deriveProtectionStatus(state.effective);
  const healthBroken = state.effective.health !== "protected";
  const handlePrimaryStatusAction = () => {
    if (status.primaryAction === "repair" || status.primaryAction === "retry-repair") {
      void recover();
    } else if (status.primaryAction === "review-lockdown") {
      requestChange({ globalLockdown: false });
    }
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "w-full", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      WorkspacePageHeader,
      {
        eyebrow: "On this device",
        title: PROTECTION_TERMS.pageTitle,
        description: "Pick a tool to see the commands Guard watches and change how they're handled."
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      ProtectionStatusHero,
      {
        status,
        busy: recoveryBusy,
        onPrimaryAction: status.primaryAction === "none" || status.primaryAction === "finish-setup" ? () => document.getElementById("extension-recovery-panel")?.scrollIntoView({ behavior: "smooth", block: "start" }) : handlePrimaryStatusAction
      }
    ) }),
    healthBroken ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", id: "extension-recovery-panel", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionStatusBanner, { busy: recoveryBusy, effective: state.effective, error: recoveryError, status: recoveryStatus, onRecover: () => {
      void recover();
    }, onRetry: load }) }) : null,
    mutationError && !pending ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineError, { message: mutationError }) }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(PatternSearchConsole, { catalog: catalogExtensions, effective: state.effective, onRefresh: load, onOpenExtension: openExtension }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-10", "aria-labelledby": "all-tools-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "all-tools-heading", className: "text-xl font-semibold tracking-tight text-brand-dark", children: "All tools" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Every tool Guard can watch on this device. Open one to adjust its command patterns." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-brand-dark/70", children: [
          catalogExtensions.length,
          " tools"
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: catalogExtensions.map((extension2) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        ProtectionModuleRow,
        {
          name: extension2.name,
          description: extension2.description,
          behavior: extensionStateLabel(state.effective, extension2),
          required: extension2.required,
          managed: sourceIsManaged(state.effective, extension2.extension_id),
          onOpen: () => openExtension(extension2)
        },
        extension2.extension_id
      )) })
    ] }),
    pending ? /* @__PURE__ */ jsxRuntimeExports.jsx(ReviewModal, { change: pending, busy, error: mutationError, approvalGate: resolvedApprovalGate, onCancel: () => {
      if (!busy) setPending(null);
    }, onConfirm: confirm }) : null,
    recoveryModal
  ] });
}
export {
  ExtensionStatusBanner,
  ProtectionCenterWorkspace as ExtensionsWorkspace,
  ReviewModal,
  buildExtensionMutation,
  currentExtensionRouteState,
  extensionRecoveryAction,
  requiresExtensionRecoveryApproval
};
