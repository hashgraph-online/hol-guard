import { GUARD_ACTIONS } from "./guard-types";
import type { GuardAction, GuardDecisionV2Action } from "./guard-types";

export type GuardActionDisposition = "allowed" | "reviewed" | "blocked";
export type GuardActionTone = "success" | "warning" | "info" | "attention";

export const AUTHORITATIVE_DECISION_INCONSISTENT = "authoritative_decision_inconsistent";

export type GuardActionPresentation = Readonly<{
  action: GuardAction;
  disposition: GuardActionDisposition;
  label: string;
  copy: string;
  tone: GuardActionTone;
  allowsLaunch: boolean;
}>;

const ACTION_PRESENTATIONS: Readonly<Record<GuardAction, GuardActionPresentation>> = {
  allow: {
    action: "allow",
    disposition: "allowed",
    label: "Allowed",
    copy: "allowed",
    tone: "success",
    allowsLaunch: true,
  },
  warn: {
    action: "warn",
    disposition: "allowed",
    label: "Allowed with warning",
    copy: "allowed with a warning",
    tone: "warning",
    allowsLaunch: true,
  },
  review: {
    action: "review",
    disposition: "reviewed",
    label: "Needs review",
    copy: "paused for review",
    tone: "info",
    allowsLaunch: false,
  },
  "require-reapproval": {
    action: "require-reapproval",
    disposition: "reviewed",
    label: "Needs fresh approval",
    copy: "paused for fresh approval",
    tone: "info",
    allowsLaunch: false,
  },
  "sandbox-required": {
    action: "sandbox-required",
    disposition: "reviewed",
    label: "Sandbox required",
    copy: "paused until sandbox requirements are met",
    tone: "info",
    allowsLaunch: false,
  },
  block: {
    action: "block",
    disposition: "blocked",
    label: "Stopped",
    copy: "blocked",
    tone: "attention",
    allowsLaunch: false,
  },
};

export function isGuardAction(value: unknown): value is GuardAction {
  return typeof value === "string" && GUARD_ACTIONS.some((action) => action === value);
}

export function isRecognizedGuardActionInput(value: unknown): boolean {
  return value === "ask" || isGuardAction(value);
}

export function isActionBearingKey(key: string): boolean {
  const separated = key.replace(/([a-z0-9])([A-Z])/g, "$1 $2");
  const tokens = separated.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  return tokens.join("") === "preexecutionresult" ||
    tokens.some((token) => token === "action" || token === "actions");
}

/**
 * Normalize an action received through a legacy string API boundary.
 *
 * Older receipt payloads used product-level `ask`; it maps to the exact
 * enforcement action `review`. Unknown future or malformed values also map to
 * review so the dashboard never presents an unrecognized action as allowed.
 */
export function normalizeGuardAction(value: unknown): GuardAction {
  if (value === "ask") return "review";
  return isGuardAction(value) ? value : "review";
}

/** The single source of display and analytics semantics for Guard actions. */
export function guardActionPresentation(value: unknown): GuardActionPresentation {
  return ACTION_PRESENTATIONS[normalizeGuardAction(value)];
}

export function mostRestrictiveGuardAction(...values: unknown[]): GuardAction {
  if (values.length === 0) return "review";
  const rank = new Map<GuardAction, number>(GUARD_ACTIONS.map((action, index) => [action, index]));
  return values
    .map(normalizeGuardAction)
    .reduce((strongest, candidate) =>
      (rank.get(candidate) ?? 0) > (rank.get(strongest) ?? 0) ? candidate : strongest
    );
}

export function guardActionDisposition(value: unknown): GuardActionDisposition {
  return guardActionPresentation(value).disposition;
}

/** Map the six exact enforcement actions to the product-facing V2 action. */
export function guardDecisionV2Action(value: unknown): GuardDecisionV2Action {
  switch (normalizeGuardAction(value)) {
    case "allow":
      return "allow";
    case "warn":
      return "warn";
    case "block":
      return "block";
    case "review":
    case "require-reapproval":
    case "sandbox-required":
      return "ask";
  }
}

/** Build a grammatically complete activity phrase without losing action detail. */
export function guardActionActivityCopy(value: unknown, subject: string, object: string): string {
  switch (normalizeGuardAction(value)) {
    case "allow":
      return `${subject} allowed ${object}`;
    case "warn":
      return `${subject} allowed ${object} with a warning`;
    case "review":
      return `${subject} paused ${object} for review`;
    case "require-reapproval":
      return `${subject} paused ${object} for fresh approval`;
    case "sandbox-required":
      return `${subject} paused ${object} until sandbox requirements are met`;
    case "block":
      return `${subject} blocked ${object}`;
  }
}

export function isAllowedGuardAction(value: unknown): boolean {
  return guardActionDisposition(value) === "allowed";
}

export function isBlockedGuardAction(value: unknown): boolean {
  return guardActionDisposition(value) === "blocked";
}
