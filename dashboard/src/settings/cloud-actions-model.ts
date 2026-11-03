/**
 * What Settings shows about Cloud actions sign-ins on this computer.
 *
 * The daemon reports each saved sign-in (workspace, Guard Cloud site, when it
 * was made and when it ends) and the last answer Guard Cloud gave about it.
 * Everything here is read from that report and parsed defensively: an
 * unexpected shape becomes "not readable" instead of a guessed state. Signing
 * in to Cloud actions never changes how Guard protects this computer, so none
 * of these states may be presented as a protection problem.
 */

export const CLOUD_ACTIONS_STATUS_SCHEMA = "guard.cloud-actions.local-status.v1";

const MAX_SIGN_INS = 32;
const MAX_MESSAGE_CHARS = 240;
const PROFILE_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;
// Workspace IDs are placed in a copyable command, so only plain ID characters are accepted.
const WORKSPACE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SITE_PATTERN = /^[A-Za-z0-9.-]{1,253}(?::\d{1,5})?$/;

export type CloudActionsTone = "good" | "neutral" | "attention";

export type CloudActionsCheck = {
  checkedAt: string | null;
  stale: boolean;
  message: string | null;
};

export type CloudActionsSignIn = {
  profile: string;
  workspace: string | null;
  site: string | null;
  signedInAt: string | null;
  expiresAt: string | null;
  state: string;
  check: CloudActionsCheck;
};

export type CloudActionsStatus = {
  generatedAt: string | null;
  staleAfterSeconds: number;
  nextCheckAllowedAt: string | null;
  signIns: CloudActionsSignIn[];
};

export type CloudActionsStateCopy = {
  label: string;
  tone: CloudActionsTone;
  /** What the member can do next, or null when nothing is needed. */
  remedy: string | null;
  /** Whether signing in again is the way forward. */
  signInAgain: boolean;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown, pattern?: RegExp): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (pattern && !pattern.test(trimmed)) return null;
  return trimmed;
}

function moment(value: unknown): string | null {
  const raw = text(value);
  return raw !== null && Number.isFinite(Date.parse(raw)) ? raw : null;
}

function normalizeCheck(value: unknown): CloudActionsCheck {
  if (!isRecord(value) || value["state"] === "not_checked") {
    return { checkedAt: null, stale: false, message: null };
  }
  const checkedAt = moment(value["checked_at"]);
  const connection = isRecord(value["connection"]) ? value["connection"] : null;
  const service = isRecord(value["service"]) ? value["service"] : null;
  // The connection answer is the more specific one once the service check passed.
  const source = service && service["state"] !== "current" ? service : connection;
  const message = text(source?.["message"]);
  return {
    checkedAt,
    stale: checkedAt === null || value["stale"] === true,
    message: message === null ? null : message.slice(0, MAX_MESSAGE_CHARS),
  };
}

function normalizeSignIn(value: unknown): CloudActionsSignIn | null {
  if (!isRecord(value)) return null;
  const profile = text(value["profile"], PROFILE_PATTERN);
  const state = text(value["state"], /^[a-z_]{1,40}$/);
  if (profile === null || state === null) return null;
  return {
    profile,
    workspace: text(value["workspace"], WORKSPACE_PATTERN),
    site: text(value["site"], SITE_PATTERN),
    signedInAt: moment(value["signed_in_at"]),
    expiresAt: moment(value["expires_at"]),
    state,
    check: normalizeCheck(value["check"]),
  };
}

export function normalizeCloudActionsStatus(payload: unknown): CloudActionsStatus | null {
  if (!isRecord(payload) || payload["schema"] !== CLOUD_ACTIONS_STATUS_SCHEMA) return null;
  const rows = Array.isArray(payload["sign_ins"]) ? payload["sign_ins"].slice(0, MAX_SIGN_INS) : null;
  if (rows === null) return null;
  const staleAfter = payload["stale_after_seconds"];
  return {
    generatedAt: moment(payload["generated_at"]),
    staleAfterSeconds: typeof staleAfter === "number" && Number.isFinite(staleAfter) && staleAfter > 0 ? staleAfter : 300,
    nextCheckAllowedAt: moment(payload["next_check_allowed_at"]),
    signIns: rows.map(normalizeSignIn).filter((row): row is CloudActionsSignIn => row !== null),
  };
}

const STATE_COPY: Record<string, CloudActionsStateCopy> = {
  connected: { label: "Connected", tone: "good", remedy: null, signInAgain: false },
  current: { label: "Connected", tone: "good", remedy: null, signInAgain: false },
  not_checked: {
    label: "Not checked yet",
    tone: "neutral",
    remedy: "Select Check now to ask Guard Cloud about this sign-in.",
    signInAgain: false,
  },
  offline: {
    label: "Guard Cloud not reachable",
    tone: "neutral",
    remedy: "Check this computer's internet connection, then check again.",
    signInAgain: false,
  },
  not_turned_on: {
    label: "Not turned on",
    tone: "neutral",
    remedy: "Cloud actions are not turned on for this Guard Cloud. Nothing on this computer needs changing.",
    signInAgain: false,
  },
  sign_in_expired: {
    label: "Sign-in ended",
    tone: "attention",
    remedy: "This sign-in has ended. Sign in again to keep using Cloud actions.",
    signInAgain: true,
  },
  sign_in_again: {
    label: "Sign in again",
    tone: "attention",
    remedy: "Guard Cloud no longer accepts this sign-in. Sign in again to keep using Cloud actions.",
    signInAgain: true,
  },
  changed: {
    label: "Sign in again",
    tone: "attention",
    remedy: "Guard Cloud changed what Cloud actions offer. Sign in again to pick up the change.",
    signInAgain: true,
  },
  not_permitted: {
    label: "No access",
    tone: "attention",
    remedy: "This member may not use Cloud actions in this workspace. Ask a workspace owner for access.",
    signInAgain: false,
  },
  workspace_mismatch: {
    label: "Workspace refused",
    tone: "attention",
    remedy: "Guard Cloud refused this workspace. Sign in again with a workspace you belong to.",
    signInAgain: true,
  },
  unexpected_answer: {
    label: "Unexpected answer",
    tone: "neutral",
    remedy: "Guard Cloud gave an answer Guard did not expect. Check again in a few minutes.",
    signInAgain: false,
  },
  profile_damaged: {
    label: "Needs repair",
    tone: "attention",
    remedy: "This saved sign-in cannot be read. Sign out of it, then sign in again.",
    signInAgain: true,
  },
};

const UNKNOWN_STATE: CloudActionsStateCopy = {
  label: "Unknown",
  tone: "neutral",
  remedy: "Check again, or update Guard if this keeps happening.",
  signInAgain: false,
};

export function cloudActionsStateCopy(state: string): CloudActionsStateCopy {
  return STATE_COPY[state] ?? UNKNOWN_STATE;
}

export function cloudActionsSignInCommand(signIn: Pick<CloudActionsSignIn, "profile" | "workspace">): string {
  let command = "hol-guard cloud-actions login";
  if (signIn.workspace !== null) command += ` --cloud-workspace ${signIn.workspace}`;
  if (signIn.profile !== "default") command += ` --profile ${signIn.profile}`;
  return command;
}

export function cloudActionsSignOutCommand(signIn: Pick<CloudActionsSignIn, "profile">): string {
  return signIn.profile === "default"
    ? "hol-guard cloud-actions logout"
    : `hol-guard cloud-actions logout --profile ${signIn.profile}`;
}

function elapsedCopy(seconds: number): string {
  if (seconds < 60) return "less than a minute ago";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return minutes === 1 ? "1 minute ago" : `${minutes} minutes ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return hours === 1 ? "1 hour ago" : `${hours} hours ago`;
  const days = Math.floor(hours / 24);
  return `${days} days ago`;
}

/** When Guard Cloud last answered, labelled as out of date once the answer is old. */
export function cloudActionsCheckedCopy(check: CloudActionsCheck, now: Date): string {
  if (check.checkedAt === null) return "Not checked yet";
  const seconds = Math.max(0, (now.getTime() - Date.parse(check.checkedAt)) / 1000);
  const when = `Checked ${elapsedCopy(seconds)}`;
  return check.stale ? `${when}. This answer may be out of date.` : when;
}

export function cloudActionsRetryAfterSeconds(nextCheckAllowedAt: string | null, now: Date): number {
  if (nextCheckAllowedAt === null) return 0;
  const seconds = Math.ceil((Date.parse(nextCheckAllowedAt) - now.getTime()) / 1000);
  return Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds, 60) : 0;
}

export function cloudActionsSummary(status: CloudActionsStatus): string {
  const count = status.signIns.length;
  if (count === 0) return "No AI tool on this computer is signed in to Cloud actions.";
  const needsAttention = status.signIns.filter((row) => cloudActionsStateCopy(row.state).tone === "attention").length;
  const signedIn = count === 1 ? "1 sign-in" : `${count} sign-ins`;
  if (needsAttention === 0) return `${signedIn} on this computer.`;
  return `${signedIn} on this computer. ${needsAttention === 1 ? "1 needs" : `${needsAttention} need`} attention.`;
}
