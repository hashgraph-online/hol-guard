import type {
  EffectiveExtensionControlProjection,
  EffectiveExtensionProjectionItem,
  EffectivePermissionProjectionItem,
} from "./extension-controls-api";

const DIGEST = /^[a-f0-9]{64}$/;
const EXTENSION_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const PERMISSION_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const MAX_EXTENSIONS = 512;
const MAX_PERMISSIONS = 4096;
const MAX_REASONS = 64;

type UnknownRecord = Record<string, unknown>;

function record(value: unknown, label: string): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`Invalid ${label}`);
  return value as UnknownRecord;
}

function text(value: unknown, label: string, max = 256): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) throw new Error(`Invalid ${label}`);
  return value;
}

function integer(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new Error(`Invalid ${label}`);
  return value as number;
}

function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`Invalid ${label}`);
  return value;
}

function enumValue<T extends string>(value: unknown, label: string, values: readonly T[]): T {
  const candidate = text(value, label, 64);
  if (!values.includes(candidate as T)) throw new Error(`Invalid ${label}`);
  return candidate as T;
}

function id(value: unknown, label: string, pattern: RegExp): string {
  const candidate = text(value, label).toLowerCase();
  if (!pattern.test(candidate)) throw new Error(`Invalid ${label}`);
  return candidate;
}

function reasons(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length > MAX_REASONS) throw new Error(`Invalid ${label}`);
  return value.map((item, index) => text(item, `${label}[${index}]`, 128));
}

function extensionItem(value: unknown, label: string): EffectiveExtensionProjectionItem {
  const item = record(value, label);
  return {
    extension_id: id(item.extension_id, `${label}.extension_id`, EXTENSION_ID),
    effective_state: enumValue(item.effective_state, `${label}.effective_state`, ["allowed", "blocked"] as const),
    local_state: enumValue(item.local_state, `${label}.local_state`, ["inherited", "enabled", "disabled"] as const),
    managed_state: enumValue(item.managed_state, `${label}.managed_state`, ["inherited", "enabled", "disabled"] as const),
    required: boolean(item.required, `${label}.required`),
    reason_codes: reasons(item.reason_codes, `${label}.reason_codes`),
  };
}

function permissionItem(value: unknown, label: string): EffectivePermissionProjectionItem {
  const item = record(value, label);
  return {
    permission_id: id(item.permission_id, `${label}.permission_id`, PERMISSION_ID),
    extension_id: id(item.extension_id, `${label}.extension_id`, EXTENSION_ID),
    effective_state: enumValue(item.effective_state, `${label}.effective_state`, ["allowed", "blocked"] as const),
    local_state: enumValue(item.local_state, `${label}.local_state`, ["inherited", "enabled", "disabled"] as const),
    managed_state: enumValue(item.managed_state, `${label}.managed_state`, ["inherited", "enabled", "disabled"] as const),
    configurable: boolean(item.configurable, `${label}.configurable`),
    fixed_reason: item.fixed_reason === null ? null : text(item.fixed_reason, `${label}.fixed_reason`, 2048),
    reason_codes: reasons(item.reason_codes, `${label}.reason_codes`),
  };
}

export function normalizeEffectiveExtensionControlProjection(value: unknown): EffectiveExtensionControlProjection {
  const root = record(value, "extension projection");
  const schemaVersion = text(root.schema_version, "projection.schema_version", 128);
  if (schemaVersion !== "guard.daemon.extension-control-projection.v1") throw new Error("Invalid extension projection schema");
  const digest = text(root.catalog_digest, "projection.catalog_digest", 64);
  if (!DIGEST.test(digest)) throw new Error("Invalid projection.catalog_digest");
  if (!Array.isArray(root.extensions) || root.extensions.length > MAX_EXTENSIONS) throw new Error("Invalid projection.extensions");
  if (!Array.isArray(root.permissions) || root.permissions.length > MAX_PERMISSIONS) throw new Error("Invalid projection.permissions");
  const extensions = root.extensions.map((item, index) => extensionItem(item, `projection.extensions[${index}]`));
  const permissions = root.permissions.map((item, index) => permissionItem(item, `projection.permissions[${index}]`));
  if (new Set(extensions.map((item) => item.extension_id)).size !== extensions.length) throw new Error("Duplicate projection extension ID");
  if (new Set(permissions.map((item) => item.permission_id)).size !== permissions.length) throw new Error("Duplicate projection permission ID");
  return {
    schema_version: "guard.daemon.extension-control-projection.v1",
    revision: integer(root.revision, "projection.revision"),
    catalog_digest: digest,
    health: enumValue(root.health, "projection.health", ["unenrolled", "protected", "tampered", "degraded-unacknowledged", "degraded-acknowledged", "recovery-required"] as const),
    extensions,
    permissions,
  };
}
