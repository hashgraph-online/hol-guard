import type {
  EffectiveExtensionControls,
  ExtensionCatalogItem,
  ExtensionCatalogResponse,
  ExtensionControlLayer,
  ExtensionPermission,
  ExtensionRule,
  ExtensionRuleSafeVariant,
} from "./extension-controls-api";
import { normalizeEffectiveExtensionControlProjection } from "./extension-control-projection-normalize";

const EXTENSION_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const PERMISSION_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const RULE_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const DIGEST = /^[a-f0-9]{64}$/;
const VERSION = /^[1-9][0-9]*\.[0-9]+\.[0-9]+$/;

export const EXTENSION_CLIENT_LIMITS = Object.freeze({
  extensions: 512,
  rulesPerExtension: 1024,
  permissionsPerExtension: 512,
  relationshipIds: 1024,
  controls: 1024,
  layers: 2,
  failures: 256,
  stringLength: 8192,
});

export class ExtensionControlProtocolError extends Error {
  constructor(message: string) {
    super(`Invalid extension-control response: ${message}`);
  }
}

type RecordValue = Record<string, unknown>;

function record(value: unknown, label: string): RecordValue {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ExtensionControlProtocolError(`${label} must be an object`);
  }
  return value as RecordValue;
}

function array(value: unknown, label: string, max: number): unknown[] {
  if (!Array.isArray(value)) throw new ExtensionControlProtocolError(`${label} must be an array`);
  if (value.length > max) throw new ExtensionControlProtocolError(`${label} exceeds ${max} items`);
  return value;
}

function string(value: unknown, label: string, allowEmpty = false): string {
  if (typeof value !== "string") throw new ExtensionControlProtocolError(`${label} must be a string`);
  if (value.length > EXTENSION_CLIENT_LIMITS.stringLength) throw new ExtensionControlProtocolError(`${label} is too long`);
  if (!allowEmpty && value.trim().length === 0) throw new ExtensionControlProtocolError(`${label} is required`);
  return value;
}

function optionalString(value: unknown, label: string): string | null {
  if (value === null) return null;
  return string(value, label);
}

function catalogText(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function bool(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new ExtensionControlProtocolError(`${label} must be boolean`);
  return value;
}

function integer(value: unknown, label: string, min = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < min) {
    throw new ExtensionControlProtocolError(`${label} must be an integer >= ${min}`);
  }
  return value as number;
}

function enumValue<T extends string>(value: unknown, label: string, values: readonly T[]): T {
  const candidate = string(value, label);
  if (!values.includes(candidate as T)) throw new ExtensionControlProtocolError(`${label} has unsupported value`);
  return candidate as T;
}

function id(value: unknown, label: string, pattern: RegExp): string {
  const candidate = string(value, label).trim().toLowerCase();
  if (!pattern.test(candidate)) throw new ExtensionControlProtocolError(`${label} is not canonical`);
  return candidate;
}

function digest(value: unknown, label: string): string {
  const candidate = string(value, label).trim().toLowerCase();
  if (!DIGEST.test(candidate)) throw new ExtensionControlProtocolError(`${label} must be a SHA-256 digest`);
  return candidate;
}

function version(value: unknown, label: string): string {
  const candidate = string(value, label);
  if (!VERSION.test(candidate)) throw new ExtensionControlProtocolError(`${label} is not a semantic implementation version`);
  return candidate;
}

function stringList(value: unknown, label: string, max = EXTENSION_CLIENT_LIMITS.relationshipIds): string[] {
  return array(value, label, max).map((item, index) => string(item, `${label}[${index}]`));
}

function idList(value: unknown, label: string, pattern: RegExp, max = EXTENSION_CLIENT_LIMITS.relationshipIds): string[] {
  const items = array(value, label, max).map((item, index) => id(item, `${label}[${index}]`, pattern));
  if (new Set(items).size !== items.length) throw new ExtensionControlProtocolError(`${label} contains duplicates`);
  return items;
}

function safeVariant(value: unknown, label: string): ExtensionRuleSafeVariant {
  const item = record(value, label);
  return {
    variant_id: string(item.variant_id, `${label}.variant_id`),
    title: string(item.title, `${label}.title`),
    matcher_kind: string(item.matcher_kind, `${label}.matcher_kind`),
  };
}

function rule(value: unknown, extensionId: string, label: string): ExtensionRule {
  const item = record(value, label);
  const ruleId = id(item.rule_id, `${label}.rule_id`, RULE_ID);
  if (!ruleId.startsWith(`${extensionId}.`)) throw new ExtensionControlProtocolError(`${label}.rule_id belongs to another extension`);
  const rawVersion = item.rule_version;
  if (!(typeof rawVersion === "string" || Number.isSafeInteger(rawVersion))) {
    throw new ExtensionControlProtocolError(`${label}.rule_version must be string or integer`);
  }
  return {
    rule_id: ruleId,
    rule_version: rawVersion as string | number,
    title: string(item.title, `${label}.title`),
    description: string(item.description, `${label}.description`),
    severity: enumValue(item.severity, `${label}.severity`, ["low", "medium", "high", "critical"] as const),
    risk_classes: stringList(item.risk_classes, `${label}.risk_classes`),
    action_classes: stringList(item.action_classes, `${label}.action_classes`),
    safer_alternatives: stringList(item.safer_alternatives, `${label}.safer_alternatives`),
    default_mode: enumValue(item.default_mode, `${label}.default_mode`, ["required", "enforce", "review", "monitor", "disabled"] as const),
    matcher_kind: string(item.matcher_kind, `${label}.matcher_kind`),
    safe_variants: array(item.safe_variants, `${label}.safe_variants`, EXTENSION_CLIENT_LIMITS.relationshipIds).map((entry, index) => safeVariant(entry, `${label}.safe_variants[${index}]`)),
    compatibility_fallback: bool(item.compatibility_fallback, `${label}.compatibility_fallback`),
  };
}

function permission(value: unknown, extensionId: string, label: string): ExtensionPermission {
  const item = record(value, label);
  const permissionId = id(item.permission_id, `${label}.permission_id`, PERMISSION_ID);
  const owner = id(item.extension_id, `${label}.extension_id`, EXTENSION_ID);
  if (owner !== extensionId || !permissionId.startsWith(`${extensionId}.permission.`)) {
    throw new ExtensionControlProtocolError(`${label} belongs to another extension`);
  }
  const replacement = item.replacement_permission_id === null ? null : id(item.replacement_permission_id, `${label}.replacement_permission_id`, PERMISSION_ID);
  return {
    permission_id: permissionId,
    schema_version: integer(item.schema_version, `${label}.schema_version`, 1),
    extension_id: owner,
    implementation_version: version(item.implementation_version, `${label}.implementation_version`),
    label: string(item.label, `${label}.label`),
    description: string(item.description, `${label}.description`),
    risk_tier: enumValue(item.risk_tier, `${label}.risk_tier`, ["low", "medium", "high", "critical"] as const),
    baseline_floor: enumValue(item.baseline_floor, `${label}.baseline_floor`, ["allow", "warn", "review", "require-reapproval", "sandbox-required", "block"] as const),
    default_enabled: bool(item.default_enabled, `${label}.default_enabled`),
    configurable: bool(item.configurable, `${label}.configurable`),
    fixed_reason: optionalString(item.fixed_reason, `${label}.fixed_reason`),
    typed_capabilities: stringList(item.typed_capabilities, `${label}.typed_capabilities`),
    action_classes: stringList(item.action_classes, `${label}.action_classes`),
    rule_ids: idList(item.rule_ids, `${label}.rule_ids`, RULE_ID),
    dependencies: idList(item.dependencies, `${label}.dependencies`, PERMISSION_ID),
    conflicts: idList(item.conflicts, `${label}.conflicts`, PERMISSION_ID),
    implied_permissions: idList(item.implied_permissions, `${label}.implied_permissions`, PERMISSION_ID),
    introduced_version: version(item.introduced_version, `${label}.introduced_version`),
    deprecated: bool(item.deprecated, `${label}.deprecated`),
    replacement_permission_id: replacement,
    safer_guidance: stringList(item.safer_guidance, `${label}.safer_guidance`),
    example_command: catalogText(item.example_command),
    family: catalogText(item.family),
  };
}

function extension(value: unknown, label: string): ExtensionCatalogItem {
  const item = record(value, label);
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
  const ruleCount = integer(item.rule_count, `${label}.rule_count`);
  const permissionCount = integer(item.permission_count, `${label}.permission_count`);
  if (ruleCount !== rules.length || permissionCount !== permissions.length) {
    throw new ExtensionControlProtocolError(`${label} count metadata does not match payload`);
  }
  return {
    schema_version: integer(item.schema_version, `${label}.schema_version`, 1),
    extension_id: extensionId,
    name: string(item.name, `${label}.name`),
    description: string(item.description, `${label}.description`),
    enabled: bool(item.enabled, `${label}.enabled`),
    required: bool(item.required, `${label}.required`),
    source: enumValue(item.source, `${label}.source`, ["built-in", "local-admin", "signed-cloud"] as const),
    version: version(item.version, `${label}.version`),
    aliases: idList(item.aliases, `${label}.aliases`, EXTENSION_ID),
    dependencies: idList(item.dependencies, `${label}.dependencies`, EXTENSION_ID),
    conflicts: idList(item.conflicts, `${label}.conflicts`, EXTENSION_ID),
    delegated_protection: optionalString(item.delegated_protection, `${label}.delegated_protection`),
    ecosystem_ids: stringList(item.ecosystem_ids, `${label}.ecosystem_ids`),
    executables: stringList(item.executables, `${label}.executables`),
    project_markers: stringList(item.project_markers, `${label}.project_markers`),
    reference_urls: stringList(item.reference_urls, `${label}.reference_urls`),
    action_classes: stringList(item.action_classes, `${label}.action_classes`),
    risk_classes: stringList(item.risk_classes, `${label}.risk_classes`),
    safer_alternatives: stringList(item.safer_alternatives, `${label}.safer_alternatives`),
    rule_count: ruleCount,
    rules,
    permission_count: permissionCount,
    permissions,
  };
}

export function normalizeExtensionControlLayer(value: unknown, label = "layer"): ExtensionControlLayer {
  const item = record(value, label);
  const controls = array(item.controls, `${label}.controls`, EXTENSION_CLIENT_LIMITS.controls).map((entry, index) => {
    const raw = record(entry, `${label}.controls[${index}]`);
    const kind = enumValue(raw.target_kind, `${label}.controls[${index}].target_kind`, ["extension", "permission"] as const);
    return {
      target_kind: kind,
      target_id: id(raw.target_id, `${label}.controls[${index}].target_id`, kind === "extension" ? EXTENSION_ID : PERMISSION_ID),
      state: enumValue(raw.state, `${label}.controls[${index}].state`, ["enabled", "disabled"] as const),
    };
  });
  const keys = controls.map((control) => `${control.target_kind}:${control.target_id}`);
  if (new Set(keys).size !== keys.length) throw new ExtensionControlProtocolError(`${label}.controls contains duplicate targets`);
  return {
    schema_version: string(item.schema_version, `${label}.schema_version`),
    kind: enumValue(item.kind, `${label}.kind`, ["local-admin", "signed-cloud"] as const),
    catalog_digest: digest(item.catalog_digest, `${label}.catalog_digest`),
    global_lockdown: bool(item.global_lockdown, `${label}.global_lockdown`),
    controls,
  };
}

export function normalizeExtensionCatalog(value: unknown): ExtensionCatalogResponse {
  const root = record(value, "catalog");
  const extensions = array(root.extensions, "catalog.extensions", EXTENSION_CLIENT_LIMITS.extensions).map((entry, index) => extension(entry, `catalog.extensions[${index}]`));
  const ids = extensions.map((entry) => entry.extension_id);
  if (new Set(ids).size !== ids.length) throw new ExtensionControlProtocolError("catalog.extensions contains duplicate extension IDs");
  const limits = root.limits === undefined ? undefined : record(root.limits, "catalog.limits");
  return {
    schema_version: string(root.schema_version, "catalog.schema_version"),
    control_schema_version: root.control_schema_version === undefined ? undefined : string(root.control_schema_version, "catalog.control_schema_version"),
    catalog_digest: digest(root.catalog_digest, "catalog.catalog_digest"),
    extensions,
    limits: limits === undefined ? undefined : {
      max_body_bytes: limits.max_body_bytes === undefined ? undefined : integer(limits.max_body_bytes, "catalog.limits.max_body_bytes", 1),
      max_controls: limits.max_controls === undefined ? undefined : integer(limits.max_controls, "catalog.limits.max_controls", 1),
      max_observations: limits.max_observations === undefined ? undefined : integer(limits.max_observations, "catalog.limits.max_observations", 1),
    },
  };
}

export function normalizeEffectiveExtensionControls(value: unknown): EffectiveExtensionControls {
  const root = record(value, "effective");
  const controls = array(root.controls, "effective.controls", EXTENSION_CLIENT_LIMITS.controls).map((entry, index) => {
    const raw = record(entry, `effective.controls[${index}]`);
    const target = record(raw.target, `effective.controls[${index}].target`);
    const kind = enumValue(target.kind, `effective.controls[${index}].target.kind`, ["extension", "permission"] as const);
    return {
      target: {
        kind,
        target_id: id(target.target_id, `effective.controls[${index}].target.target_id`, kind === "extension" ? EXTENSION_ID : PERMISSION_ID),
      },
      state: enumValue(raw.state, `effective.controls[${index}].state`, ["enabled", "disabled"] as const),
    };
  });
  const keys = controls.map((control) => `${control.target.kind}:${control.target.target_id}`);
  if (new Set(keys).size !== keys.length) throw new ExtensionControlProtocolError("effective.controls contains duplicate targets");
  const layers = array(root.layers, "effective.layers", EXTENSION_CLIENT_LIMITS.layers).map((entry, index) => normalizeExtensionControlLayer(entry, `effective.layers[${index}]`));
  const failures = array(root.failures, "effective.failures", EXTENSION_CLIENT_LIMITS.failures).map((entry, index) => {
    const raw = record(entry, `effective.failures[${index}]`);
    return {
      code: string(raw.code, `effective.failures[${index}].code`),
      detail: raw.detail === undefined ? undefined : string(raw.detail, `effective.failures[${index}].detail`, true),
      layer_kind: raw.layer_kind === undefined ? undefined : string(raw.layer_kind, `effective.failures[${index}].layer_kind`),
    };
  });
  return {
    schema_version: string(root.schema_version, "effective.schema_version"),
    health: enumValue(root.health, "effective.health", ["unenrolled", "protected", "tampered", "degraded-unacknowledged", "degraded-acknowledged", "recovery-required"] as const),
    revision: integer(root.revision, "effective.revision"),
    catalog_digest: digest(root.catalog_digest, "effective.catalog_digest"),
    global_lockdown: bool(root.global_lockdown, "effective.global_lockdown"),
    controls,
    layers,
    failures,
    projection: root.projection === undefined ? undefined : normalizeEffectiveExtensionControlProjection(root.projection),
  };
}
