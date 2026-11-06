import type {
  ExtensionMutationApplyResponse,
  ExtensionMutationPreview,
  ExtensionSemanticPreview,
  ExtensionSemanticPreviewTarget,
  ExtensionSemanticPreviewWarning,
} from "./extension-controls-api";

const DIGEST = /^[a-f0-9]{64}$/;
const TARGET_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const MAX_CHANGED_TARGETS = 4096;
const MAX_AFFECTED_IDS = 4096;
const MAX_WARNINGS = 64;
const MAX_TEXT = 8192;

type UnknownRecord = Record<string, unknown>;

function record(value: unknown, label: string): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`Invalid extension-control ${label}: expected object`);
  return value as UnknownRecord;
}

function string(value: unknown, label: string, max = MAX_TEXT): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) throw new Error(`Invalid extension-control ${label}`);
  return value;
}

function integer(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new Error(`Invalid extension-control ${label}`);
  return value as number;
}

function bool(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`Invalid extension-control ${label}`);
  return value;
}

function digest(value: unknown, label: string): string {
  const candidate = string(value, label, 64);
  if (!DIGEST.test(candidate)) throw new Error(`Invalid extension-control ${label}`);
  return candidate;
}

function targetId(value: unknown, label: string): string {
  const candidate = string(value, label, 256);
  if (!TARGET_ID.test(candidate)) throw new Error(`Invalid extension-control ${label}`);
  return candidate;
}

function boundedArray(value: unknown, label: string, max: number): unknown[] {
  if (!Array.isArray(value) || value.length > max) throw new Error(`Invalid extension-control ${label}`);
  return value;
}

function idList(value: unknown, label: string): string[] {
  const items = boundedArray(value, label, MAX_AFFECTED_IDS).map((item, index) => targetId(item, `${label}[${index}]`));
  if (new Set(items).size !== items.length) throw new Error(`Invalid extension-control ${label}: duplicate IDs`);
  return items;
}

function optionalIdList(value: unknown, label: string): string[] | undefined {
  return value === undefined ? undefined : idList(value, label);
}

function optionalStringList(value: unknown, label: string): string[] | undefined {
  if (value === undefined) return undefined;
  const items = boundedArray(value, label, MAX_AFFECTED_IDS).map((item, index) => string(item, `${label}[${index}]`, 128));
  if (new Set(items).size !== items.length) throw new Error(`Invalid extension-control ${label}: duplicate values`);
  return items;
}

function warning(value: unknown, label: string): ExtensionSemanticPreviewWarning {
  const item = record(value, label);
  return {
    code: string(item.code, `${label}.code`, 128),
    message: string(item.message, `${label}.message`, 1024),
    ...(item.target_id === undefined ? {} : { target_id: targetId(item.target_id, `${label}.target_id`) }),
    ...(item.count === undefined ? {} : { count: integer(item.count, `${label}.count`) }),
  };
}

function target(value: unknown, label: string): ExtensionSemanticPreviewTarget {
  const item = record(value, label);
  const rawTarget = record(item.target, `${label}.target`);
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
    before_explicit: beforeExplicit as ExtensionSemanticPreviewTarget["before_explicit"],
    after_explicit: afterExplicit as ExtensionSemanticPreviewTarget["after_explicit"],
    before_effective: beforeEffective as ExtensionSemanticPreviewTarget["before_effective"],
    after_effective: afterEffective as ExtensionSemanticPreviewTarget["after_effective"],
    affected_permission_ids: idList(item.affected_permission_ids, `${label}.affected_permission_ids`),
    affected_rule_ids: idList(item.affected_rule_ids, `${label}.affected_rule_ids`),
    ...(affectedExtensionIds === undefined ? {} : { affected_extension_ids: affectedExtensionIds }),
    ...(dependencyPermissionIds === undefined ? {} : { dependency_permission_ids: dependencyPermissionIds }),
    ...(impliedPermissionIds === undefined ? {} : { implied_permission_ids: impliedPermissionIds }),
    ...(conflictPermissionIds === undefined ? {} : { conflict_permission_ids: conflictPermissionIds }),
    ...(provenance === undefined ? {} : { provenance }),
    warnings: boundedArray(item.warnings, `${label}.warnings`, MAX_WARNINGS).map((entry, index) => warning(entry, `${label}.warnings[${index}]`)),
    ...(item.extension_name === undefined ? {} : { extension_name: string(item.extension_name, `${label}.extension_name`, 512) }),
    ...(item.baseline_risk === undefined ? {} : { baseline_risk: string(item.baseline_risk, `${label}.baseline_risk`, 32) }),
    ...(item.baseline_floor === undefined ? {} : { baseline_floor: string(item.baseline_floor, `${label}.baseline_floor`, 32) }),
  };
}

export function normalizeExtensionSemanticPreview(value: unknown): ExtensionSemanticPreview {
  const root = record(value, "semantic preview");
  if (string(root.schema_version, "semantic_preview.schema_version", 128) !== "guard.daemon.extension-control-semantic-preview.v1") throw new Error("Invalid extension-control semantic preview schema");
  const lockdown = record(root.global_lockdown, "semantic_preview.global_lockdown");
  const summary = record(root.summary, "semantic_preview.summary");
  const changedTargets = boundedArray(root.changed_targets, "semantic_preview.changed_targets", MAX_CHANGED_TARGETS).map((entry, index) => target(entry, `semantic_preview.changed_targets[${index}]`));
  const changedTargetCount = integer(root.changed_target_count, "semantic_preview.changed_target_count");
  if (changedTargetCount !== changedTargets.length) throw new Error("Invalid extension-control semantic preview target count");
  return {
    schema_version: "guard.daemon.extension-control-semantic-preview.v1",
    global_lockdown: {
      before: bool(lockdown.before, "semantic_preview.global_lockdown.before"),
      after: bool(lockdown.after, "semantic_preview.global_lockdown.after"),
      changed: bool(lockdown.changed, "semantic_preview.global_lockdown.changed"),
    },
    changed_target_count: changedTargetCount,
    affected_permission_count: integer(root.affected_permission_count, "semantic_preview.affected_permission_count"),
    affected_rule_count: integer(root.affected_rule_count, "semantic_preview.affected_rule_count"),
    changed_targets: changedTargets,
    ...(root.approval_required === undefined ? {} : { approval_required: bool(root.approval_required, "semantic_preview.approval_required") }),
    summary: {
      newly_blocked_permissions: integer(summary.newly_blocked_permissions, "semantic_preview.summary.newly_blocked_permissions"),
      newly_allowed_permissions: integer(summary.newly_allowed_permissions, "semantic_preview.summary.newly_allowed_permissions"),
      effective_change_count: integer(summary.effective_change_count, "semantic_preview.summary.effective_change_count"),
    },
  };
}

export function normalizeExtensionMutationPreview(value: unknown): ExtensionMutationPreview {
  const root = record(value, "mutation preview");
  return {
    schema_version: string(root.schema_version, "preview.schema_version", 128),
    previous_revision: integer(root.previous_revision, "preview.previous_revision"),
    next_revision: integer(root.next_revision, "preview.next_revision"),
    catalog_digest: digest(root.catalog_digest, "preview.catalog_digest"),
    canonical_diff_digest: digest(root.canonical_diff_digest, "preview.canonical_diff_digest"),
    global_lockdown: bool(root.global_lockdown, "preview.global_lockdown"),
    controls: integer(root.controls, "preview.controls"),
    semantic_preview: normalizeExtensionSemanticPreview(root.semantic_preview),
    ...(root.proof_id === undefined ? {} : { proof_id: string(root.proof_id, "preview.proof_id", 256) }),
  };
}

export function normalizeExtensionMutationApply(value: unknown): ExtensionMutationApplyResponse {
  const root = record(value, "mutation apply");
  if (string(root.status, "apply.status", 32) !== "applied") throw new Error("Invalid extension-control apply status");
  return {
    schema_version: string(root.schema_version, "apply.schema_version", 128),
    status: "applied",
    revision: integer(root.revision, "apply.revision"),
    catalog_digest: digest(root.catalog_digest, "apply.catalog_digest"),
  };
}
