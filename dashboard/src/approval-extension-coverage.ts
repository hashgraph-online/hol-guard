import {
  APPROVAL_EXTENSION_COVERAGE_SCHEMA,
  type GuardApprovalExtensionCoverage,
  type GuardCoveredExtension,
  type GuardCoveredPermission,
  type GuardCoveredRule,
  type GuardCoveredSegment,
} from "./approval-extension-coverage-types";

const MAX_SEGMENTS = 12;
// The stored hint carries up to this many ids per step, so anything less would
// drop links the daemon meant to deliver.
const MAX_PER_SEGMENT = 12;
const MAX_SEGMENT_INDEX = 255;
const CATALOG_ID = /^command\.[A-Za-z0-9._-]{1,248}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const EXECUTABLE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedText(value: unknown, limit: number): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.replace(/\s+/g, " ").trim();
  return normalized ? normalized.slice(0, limit) : null;
}

function catalogId(value: unknown): string | null {
  return typeof value === "string" && CATALOG_ID.test(value) ? value : null;
}

function normalizeExtension(raw: unknown): GuardCoveredExtension | null {
  if (!isRecord(raw)) return null;
  const extensionId = catalogId(raw.extension_id);
  const name = boundedText(raw.name, 120);
  if (extensionId === null || name === null) return null;
  const focus = raw.focus_rule_id === null || raw.focus_rule_id === undefined ? null : catalogId(raw.focus_rule_id);
  if (raw.focus_rule_id !== null && raw.focus_rule_id !== undefined && focus === null) return null;
  return { extension_id: extensionId, name, focus_rule_id: focus };
}

function normalizeRule(raw: unknown): GuardCoveredRule | null {
  if (!isRecord(raw)) return null;
  const ruleId = catalogId(raw.rule_id);
  const title = boundedText(raw.title, 120);
  const severity = boundedText(raw.severity, 32);
  if (ruleId === null || title === null || severity === null) return null;
  return { rule_id: ruleId, title, severity };
}

function normalizePermission(raw: unknown): GuardCoveredPermission | null {
  if (!isRecord(raw)) return null;
  const permissionId = catalogId(raw.permission_id);
  const label = boundedText(raw.label, 120);
  if (permissionId === null || label === null || typeof raw.configurable !== "boolean") return null;
  return { permission_id: permissionId, label, configurable: raw.configurable };
}

function normalizeList<T>(raw: unknown, normalize: (item: unknown) => T | null): readonly T[] | null {
  if (!Array.isArray(raw)) return null;
  const items = raw.map(normalize);
  // One malformed entry means the payload is not the one the daemon builds.
  if (items.some((item) => item === null)) return null;
  return (items as T[]).slice(0, MAX_PER_SEGMENT);
}

function normalizeSegment(raw: unknown): GuardCoveredSegment | null {
  if (!isRecord(raw)) return null;
  const { index } = raw;
  if (typeof index !== "number" || !Number.isInteger(index) || index < 0 || index > MAX_SEGMENT_INDEX) return null;
  const executable =
    raw.executable === null || raw.executable === undefined
      ? null
      : typeof raw.executable === "string" && EXECUTABLE.test(raw.executable)
        ? raw.executable
        : undefined;
  if (executable === undefined) return null;
  const extensions = normalizeList(raw.extensions, normalizeExtension);
  const rules = normalizeList(raw.rules, normalizeRule);
  const permissions = normalizeList(raw.permissions, normalizePermission);
  if (extensions === null || rules === null || permissions === null || extensions.length === 0) return null;
  return { index, executable, extensions, rules, permissions };
}

/** Strictly validate the daemon coverage payload; any malformed field drops the whole card. */
export function normalizeApprovalExtensionCoverage(raw: unknown): GuardApprovalExtensionCoverage | null {
  if (!isRecord(raw) || raw.schema !== APPROVAL_EXTENSION_COVERAGE_SCHEMA) return null;
  if (typeof raw.catalog_digest !== "string" || !DIGEST.test(raw.catalog_digest)) return null;
  if (typeof raw.compound !== "boolean" || !Array.isArray(raw.segments)) return null;
  if (raw.segments.length === 0) return null;
  // A daemon that delivers more steps than this card renders is still telling
  // the truth about the ones it renders, so show those rather than nothing.
  const segments = raw.segments.slice(0, MAX_SEGMENTS).map(normalizeSegment);
  if (segments.some((segment) => segment === null)) return null;
  return {
    schema: APPROVAL_EXTENSION_COVERAGE_SCHEMA,
    catalog_digest: raw.catalog_digest,
    segments: (segments as GuardCoveredSegment[]).slice().sort((left, right) => left.index - right.index),
    compound: raw.compound,
  };
}

/** The one sentence that keeps a covered step from reading as a covered command. */
export function coverageScopeLine(coverage: GuardApprovalExtensionCoverage): string | null {
  if (!coverage.compound) return null;
  return "Allowing a step here settles that step only. The rest of this command still comes back for review.";
}

export function coverageStepLabel(segment: GuardCoveredSegment): string {
  const step = `Step ${segment.index + 1}`;
  return segment.executable === null ? step : `${step} · ${segment.executable}`;
}
