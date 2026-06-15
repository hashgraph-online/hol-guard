import type { GuardCloudException } from "./guard-types";
import type { GuardCloudExceptionRequestItem } from "./guard-api";

export const CLOUD_EXCEPTION_EXPIRING_SOON_DAYS = 7;

export type CloudExceptionSummary = {
  activeCount: number;
  pendingCount: number;
  expiringSoonCount: number;
  ackFailureCount: number;
};

export type CloudExceptionGroups = {
  active: GuardCloudException[];
  pending: GuardCloudExceptionRequestItem[];
  expiringSoon: GuardCloudException[];
  ackFailures: GuardCloudException[];
};

export function parseCloudExceptionTimestamp(value: string | null | undefined): Date | null {
  if (!value || !value.trim()) {
    return null;
  }
  const normalized = value.replace("Z", "+00:00");
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export function resolveCloudExceptionExpiryValue(item: GuardCloudException): string | null {
  const expiry = item.expiry?.trim();
  if (expiry) {
    return expiry;
  }
  const legacyExpiry = item.expires_at?.trim();
  return legacyExpiry || null;
}

export function resolveCloudExceptionExpiryTimestamp(item: GuardCloudException): Date | null {
  return parseCloudExceptionTimestamp(resolveCloudExceptionExpiryValue(item));
}

export function isCloudExceptionActive(item: GuardCloudException, now: Date = new Date()): boolean {
  const expiry = resolveCloudExceptionExpiryTimestamp(item);
  if (expiry === null) {
    return false;
  }
  return expiry.getTime() > now.getTime();
}

export function isCloudExceptionExpiringSoon(
  item: GuardCloudException,
  now: Date = new Date(),
  withinDays: number = CLOUD_EXCEPTION_EXPIRING_SOON_DAYS,
): boolean {
  if (!isCloudExceptionActive(item, now)) {
    return false;
  }
  const expiry = resolveCloudExceptionExpiryTimestamp(item);
  if (expiry === null) {
    return false;
  }
  const thresholdMs = now.getTime() + withinDays * 24 * 60 * 60 * 1000;
  return expiry.getTime() <= thresholdMs;
}

export function isCloudExceptionAckFailure(item: GuardCloudException): boolean {
  return item.ack_status === "failed" || item.ack_status === "offline";
}

export function resolveCloudExceptionScopeTarget(item: GuardCloudException): string | null {
  if (typeof item.artifact_id === "string" && item.artifact_id.trim()) {
    return item.artifact_id.trim();
  }
  if (item.scope === "artifact" && item.id.startsWith("artifact:")) {
    return item.id.slice("artifact:".length);
  }
  if (typeof item.publisher === "string" && item.publisher.trim()) {
    return item.publisher.trim();
  }
  if (item.scope === "publisher" && item.id.startsWith("publisher:")) {
    return item.id.slice("publisher:".length);
  }
  if (item.harness) {
    return item.harness;
  }
  if (item.scope === "harness" && item.id.startsWith("harness:")) {
    return item.id.slice("harness:".length);
  }
  return item.id;
}

export function resolveCloudExceptionHeadline(item: GuardCloudException): string {
  const target = resolveCloudExceptionScopeTarget(item);
  if (item.scope === "artifact" && target) {
    return target;
  }
  if (item.scope === "publisher" && target) {
    return `Publisher ${target}`;
  }
  if (item.scope === "harness" && target) {
    return `${target} harness`;
  }
  if (item.scope === "workspace") {
    return "Workspace scope";
  }
  if (item.scope === "global") {
    return "Global risk acceptance";
  }
  return item.id;
}

export function resolvePersonDisplayLabel(value: string | null | undefined): string {
  if (!value || !value.trim()) {
    return "Unknown";
  }
  const trimmed = value.trim();
  if (trimmed.includes("@")) {
    const localPart = trimmed.split("@")[0] ?? trimmed;
    return localPart.replace(/[._-]+/g, " ").trim() || trimmed;
  }
  return trimmed;
}

export function resolvePersonInitials(value: string | null | undefined): string {
  const label = resolvePersonDisplayLabel(value);
  const parts = label.split(/\s+/).filter(Boolean);
  if (parts.length >= 2) {
    return `${parts[0]?.[0] ?? ""}${parts[1]?.[0] ?? ""}`.toUpperCase();
  }
  return label.slice(0, 2).toUpperCase();
}

export function resolveCloudExceptionBlastRadius(scope: GuardCloudException["scope"]): {
  label: string;
  detail: string;
  tone: "narrow" | "medium" | "wide";
} {
  if (scope === "artifact") {
    return {
      label: "Narrow",
      detail: "Applies to one artifact fingerprint only.",
      tone: "narrow",
    };
  }
  if (scope === "publisher") {
    return {
      label: "Medium",
      detail: "Applies to packages and plugins from one publisher.",
      tone: "medium",
    };
  }
  if (scope === "harness") {
    return {
      label: "Medium",
      detail: "Applies across one harness on this device.",
      tone: "medium",
    };
  }
  if (scope === "workspace") {
    return {
      label: "Wide",
      detail: "Applies within the current project workspace.",
      tone: "wide",
    };
  }
  return {
    label: "Wide",
    detail: "Applies as a global Cloud risk acceptance.",
    tone: "wide",
  };
}

export function resolveCloudExceptionWhyCopy(item: GuardCloudException): string {
  if (item.rejection_reason?.trim()) {
    return item.rejection_reason.trim();
  }
  const blast = resolveCloudExceptionBlastRadius(item.scope);
  return `Cloud-approved risk acceptance (${blast.detail.toLowerCase()}) synced from a signed policy bundle.`;
}

export function resolveCloudExceptionEffectLabel(effect: GuardCloudException["effect"]): string {
  if (effect === "allow") {
    return "Allow temporarily";
  }
  return effect;
}

export function resolveCloudExceptionEvidenceUrl(item: GuardCloudException): string | null {
  const receiptId = item.source_receipt_id?.trim();
  if (!receiptId) {
    return null;
  }
  return `/evidence?search=${encodeURIComponent(receiptId)}`;
}

export function resolveCloudExceptionScopePath(item: GuardCloudException): string | null {
  const target = resolveCloudExceptionScopeTarget(item);
  if (!target) {
    return null;
  }
  if (item.scope === "workspace" || item.scope === "publisher") {
    return target;
  }
  return null;
}

export function summarizeCloudExceptions(
  exceptions: GuardCloudException[],
  pendingRequests: GuardCloudExceptionRequestItem[],
  now: Date = new Date(),
): CloudExceptionSummary {
  const active = exceptions.filter((item) => isCloudExceptionActive(item, now));
  const expiringSoon = active.filter((item) => isCloudExceptionExpiringSoon(item, now));
  const ackFailures = active.filter((item) => isCloudExceptionAckFailure(item));
  const pending = pendingRequests.filter((item) => item.status === "pending");
  return {
    activeCount: active.length,
    pendingCount: pending.length,
    expiringSoonCount: expiringSoon.length,
    ackFailureCount: ackFailures.length,
  };
}

export function groupCloudExceptions(
  exceptions: GuardCloudException[],
  pendingRequests: GuardCloudExceptionRequestItem[],
  now: Date = new Date(),
): CloudExceptionGroups {
  const active = exceptions
    .filter((item) => isCloudExceptionActive(item, now))
    .sort((left, right) => {
      const leftExpiry = resolveCloudExceptionExpiryTimestamp(left)?.getTime() ?? Number.MAX_SAFE_INTEGER;
      const rightExpiry = resolveCloudExceptionExpiryTimestamp(right)?.getTime() ?? Number.MAX_SAFE_INTEGER;
      return leftExpiry - rightExpiry;
    });
  const pending = pendingRequests
    .filter((item) => item.status === "pending")
    .sort(
      (left, right) =>
        (parseCloudExceptionTimestamp(right.requestedAt)?.getTime() ?? 0) -
        (parseCloudExceptionTimestamp(left.requestedAt)?.getTime() ?? 0),
    );
  const expiringSoon = active.filter((item) => isCloudExceptionExpiringSoon(item, now));
  const ackFailures = active.filter((item) => isCloudExceptionAckFailure(item));
  return { active, pending, expiringSoon, ackFailures };
}
