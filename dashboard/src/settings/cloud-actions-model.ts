/**
 * What Settings shows about Cloud actions on this computer.
 *
 * Cloud actions use this computer's `hol-guard connect` connection; there is
 * no separate sign-in. The daemon reports that connection (workspace, Guard
 * Cloud site, whether Cloud actions were left on when it connected) and the
 * last answer Guard Cloud gave about Cloud actions. Everything here is read
 * from that report and parsed defensively: an unexpected shape becomes "not
 * readable" instead of a guessed state. Cloud actions never change how Guard
 * protects this computer, so none of these states may be presented as a
 * protection problem.
 */

export const CLOUD_ACTIONS_STATUS_SCHEMA = "guard.cloud-actions.local-status.v2";
export const CLOUD_ACTIONS_CONNECT_COMMAND = "hol-guard connect";

const MAX_MESSAGE_CHARS = 240;
// Workspace IDs are placed in a copyable command, so only plain ID characters are accepted.
const WORKSPACE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SITE_PATTERN = /^[A-Za-z0-9.-]{1,253}(?::\d{1,5})?$/;
// Guard Cloud is reached over https; plain http is only accepted for this computer.
const CLOUD_URL_PATTERN = /^(?:https:\/\/[A-Za-z0-9.-]{1,253}|http:\/\/(?:127\.0\.0\.1|localhost|host\.docker\.internal))(?::\d{1,5})?$/;
// Guard Cloud's pages sit at the site itself or under one short path such as /points.
const CLOUD_BASE_PATH_PATTERN = /^(?:\/[a-z0-9-]{1,32})?$/;

export type CloudActionsTone = "good" | "neutral" | "attention";

/** Whether Cloud actions were left on when this computer connected; "unknown" when Guard Cloud did not say. */
export type CloudActionsSetting = "on" | "off" | "unknown";

export type CloudActionsCheck = {
  /** The service answer's state code, or "not_checked". */
  state: string;
  checkedAt: string | null;
  stale: boolean;
  message: string | null;
};

export type CloudActionsConnection = {
  setting: CloudActionsSetting;
  workspace: string | null;
  site: string | null;
  /** Where Guard Cloud's pages live for this connection; null when Guard does not recognise the site. */
  cloudBaseUrl: string | null;
  check: CloudActionsCheck;
};

export type CloudActionsStatus = {
  generatedAt: string | null;
  staleAfterSeconds: number;
  nextCheckAllowedAt: string | null;
  /** Null when this computer is not connected to Guard Cloud. */
  connection: CloudActionsConnection | null;
};

export type CloudActionsLink = {
  label: string;
  description: string;
  href: string;
};

export type CloudActionsStateCopy = {
  label: string;
  tone: CloudActionsTone;
  /** What the member can do next, or null when nothing is needed. */
  remedy: string | null;
  /** Whether connecting this computer again is the way forward. */
  reconnect: boolean;
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

const NOT_CHECKED: CloudActionsCheck = { state: "not_checked", checkedAt: null, stale: false, message: null };

function normalizeCheck(value: unknown): CloudActionsCheck {
  if (!isRecord(value) || value["state"] === "not_checked" || !isRecord(value["service"])) return NOT_CHECKED;
  const service = value["service"];
  const state = text(service["state"], /^[a-z_]{1,40}$/);
  if (state === null) return NOT_CHECKED;
  const checkedAt = moment(value["checked_at"]);
  const message = text(service["message"]);
  return {
    state,
    checkedAt,
    stale: checkedAt === null || value["stale"] === true,
    message: message === null ? null : message.slice(0, MAX_MESSAGE_CHARS),
  };
}

function cloudBase(value: unknown, cloudUrl: string | null): string | null {
  const base = text(value);
  if (base === null || cloudUrl === null || !base.startsWith(cloudUrl)) return null;
  return CLOUD_BASE_PATH_PATTERN.test(base.slice(cloudUrl.length)) ? base : null;
}

function normalizeConnection(value: Record<string, unknown>): CloudActionsConnection {
  const site = text(value["site"], SITE_PATTERN);
  const reported = text(value["cloud_url"], CLOUD_URL_PATTERN);
  // The address must name the same site the page shows.
  const cloudUrl = reported !== null && site !== null && reported.replace(/^https?:\/\//, "") === site ? reported : null;
  const setting = value["state"];
  return {
    setting: setting === "on" || setting === "off" ? setting : "unknown",
    workspace: text(value["workspace"], WORKSPACE_PATTERN),
    site,
    cloudBaseUrl: cloudBase(value["cloud_base_url"], cloudUrl),
    check: normalizeCheck(value["check"]),
  };
}

export function normalizeCloudActionsStatus(payload: unknown): CloudActionsStatus | null {
  if (!isRecord(payload) || payload["schema"] !== CLOUD_ACTIONS_STATUS_SCHEMA) return null;
  const connection = payload["connection"];
  if (!isRecord(connection) || typeof connection["state"] !== "string") return null;
  const staleAfter = payload["stale_after_seconds"];
  return {
    generatedAt: moment(payload["generated_at"]),
    staleAfterSeconds: typeof staleAfter === "number" && Number.isFinite(staleAfter) && staleAfter > 0 ? staleAfter : 300,
    nextCheckAllowedAt: moment(payload["next_check_allowed_at"]),
    connection: connection["state"] === "not_paired" ? null : normalizeConnection(connection),
  };
}

const STATE_COPY: Record<string, CloudActionsStateCopy> = {
  current: { label: "Available", tone: "good", remedy: null, reconnect: false },
  not_checked: {
    label: "Not checked yet",
    tone: "neutral",
    remedy: "Select Check now to ask Guard Cloud about Cloud actions.",
    reconnect: false,
  },
  offline: {
    label: "Guard Cloud not reachable",
    tone: "neutral",
    remedy: "Check this computer's internet connection, then check again.",
    reconnect: false,
  },
  not_turned_on: {
    label: "Not turned on",
    tone: "neutral",
    remedy: "Cloud actions are not turned on for this Guard Cloud. Nothing on this computer needs changing.",
    reconnect: false,
  },
  changed: {
    label: "Reconnect",
    tone: "attention",
    remedy: "Guard Cloud changed what Cloud actions offer. Reconnect this computer to pick up the change.",
    reconnect: true,
  },
  unexpected_answer: {
    label: "Unexpected answer",
    tone: "neutral",
    remedy: "Guard Cloud gave an answer Guard did not expect. Check again in a few minutes.",
    reconnect: false,
  },
  off: {
    label: "Off on this computer",
    tone: "neutral",
    remedy: "Cloud actions were left off when this computer connected. To turn them on, reconnect and leave them on in the browser.",
    reconnect: true,
  },
};

const UNKNOWN_STATE: CloudActionsStateCopy = {
  label: "Unknown",
  tone: "neutral",
  remedy: "Check again, or update Guard if this keeps happening.",
  reconnect: false,
};

export function cloudActionsStateCopy(state: string): CloudActionsStateCopy {
  return STATE_COPY[state] ?? UNKNOWN_STATE;
}

/** The state to show: Cloud actions left off on this computer outrank what Guard Cloud offers. */
export function cloudActionsCurrentState(connection: Pick<CloudActionsConnection, "setting" | "check">): string {
  return connection.setting === "off" ? "off" : connection.check.state;
}

/** The command that connects this computer again to the same workspace. */
export function cloudActionsReconnectCommand(connection: Pick<CloudActionsConnection, "workspace"> | null): string {
  if (connection === null || connection.workspace === null) return CLOUD_ACTIONS_CONNECT_COMMAND;
  return `${CLOUD_ACTIONS_CONNECT_COMMAND} --cloud-workspace ${connection.workspace}`;
}

export function cloudActionsSettingCopy(setting: CloudActionsSetting): string {
  if (setting === "on") return "On";
  if (setting === "off") return "Off";
  return "Not reported by Guard Cloud";
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

/**
 * When Guard Cloud last answered, labelled as out of date once the answer is
 * old. The page stays open, so age is measured against the current clock as
 * well as the flag the daemon set when it built the report.
 */
export function cloudActionsCheckedCopy(check: CloudActionsCheck, now: Date, staleAfterSeconds: number): string {
  if (check.checkedAt === null) return "Not checked yet";
  const seconds = Math.max(0, (now.getTime() - Date.parse(check.checkedAt)) / 1000);
  const when = `Checked ${elapsedCopy(seconds)}`;
  return check.stale || seconds > staleAfterSeconds ? `${when}. This answer may be out of date.` : when;
}

export function cloudActionsRetryAfterSeconds(nextCheckAllowedAt: string | null, now: Date): number {
  if (nextCheckAllowedAt === null) return 0;
  const seconds = Math.ceil((Date.parse(nextCheckAllowedAt) - now.getTime()) / 1000);
  return Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds, 60) : 0;
}

export function cloudActionsSummary(status: CloudActionsStatus): string {
  const connection = status.connection;
  if (connection === null) return "This computer is not connected to Guard Cloud.";
  const where = connection.workspace === null ? "Connected to Guard Cloud." : `Connected to workspace ${connection.workspace}.`;
  const copy = cloudActionsStateCopy(cloudActionsCurrentState(connection));
  return copy.tone === "attention" ? `${where} Cloud actions need attention.` : where;
}

/**
 * Guard Cloud pages for this connection's workspace, or none when the site or
 * workspace is not known. Links carry only the workspace; Guard Cloud checks
 * the member's own browser sign-in before showing anything.
 */
export function cloudActionsLinks(connection: Pick<CloudActionsConnection, "workspace" | "cloudBaseUrl">): CloudActionsLink[] {
  if (connection.workspace === null || connection.cloudBaseUrl === null) return [];
  const base = connection.cloudBaseUrl;
  const workspace = encodeURIComponent(connection.workspace);
  return [
    {
      label: "Review requests",
      description: "Actions waiting for a decision. Approving one there never approves anything paused on this computer.",
      href: `${base}/guard/review?workspaceId=${workspace}&tab=needs-review`,
    },
    {
      label: "Action history",
      description: "What Cloud actions did and who decided.",
      href: `${base}/guard/evidence?workspaceId=${workspace}&tab=decisions&source=cloud`,
    },
    {
      label: "Included actions",
      description: "How many actions your plan includes and how many are left.",
      href: `${base}/guard/settings?tab=billing&workspaceId=${workspace}#included-actions`,
    },
    {
      label: "Connected accounts",
      description: "The accounts Cloud actions can use for this workspace.",
      href: `${base}/guard/settings?tab=integrations&workspaceId=${workspace}#connected-accounts`,
    },
  ];
}
