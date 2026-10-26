import type { LocalCliCommand, LocalCliItem } from "../local-cli-api";

/** Commands the set-up flow may be prefilled with. Anything else in the URL is ignored. */
const PROFILE_SETUP_COMMANDS: Record<string, string> = { wrangler: "npx wrangler" };
export const PROFILE_COMMAND_PARAM = "command";

export function profileSetupCommand(item: LocalCliItem): string | null {
  return item.profile_id ? PROFILE_SETUP_COMMANDS[item.profile_id] ?? null : null;
}

export function customExtensionDisplayName(item: LocalCliItem): string {
  return item.display_name ?? item.name;
}

export function customExtensionBadge(item: LocalCliItem): "Detected" | "Set up" | null {
  if (item.seeded === true) return "Set up";
  if (item.surface === "cli" && item.state === "unset" && item.suggestable) return "Detected";
  return null;
}

export function hasSuggestedRules(item: LocalCliItem): boolean {
  return item.commands.some((command) => command.suggested_state !== undefined);
}

/**
 * Pre-select suggested rules while an extension has not been added yet. Once
 * added, its saved rules are shown as-is, including deliberate "inherit"
 * choices. Nothing is applied until the user confirms.
 */
export function prefillSuggestedStates(item: Pick<LocalCliItem, "state" | "commands">): LocalCliCommand[] {
  if (item.state !== "unset") return item.commands;
  return item.commands.map((command) => command.state === "inherit"
    && command.suggested_state !== undefined && command.suggested_state !== "inherit"
    ? { ...command, state: command.suggested_state }
    : command);
}

export function addCustomExtensionPrefillHref(base: string, command: string | undefined): string {
  if (!command || !Object.values(PROFILE_SETUP_COMMANDS).includes(command)) return base;
  return `${base}?${PROFILE_COMMAND_PARAM}=${encodeURIComponent(command)}`;
}

export function initialAddCommand(search: string): string {
  const value = new URLSearchParams(search).get(PROFILE_COMMAND_PARAM);
  return value !== null && Object.values(PROFILE_SETUP_COMMANDS).includes(value) ? value : "";
}

/** A Protect link opened from a request held on this connector (`?setup=<request>&identity=<hash>`). */
export type ConnectorSetupLink = { requestId: string; identityHash: string };
export type ConnectorSetupMatch = "ready" | "identity_changed" | "decided";
export type ConnectorGroupOutcome = { status: string; resolvedCount: number; retryHint: string | null };

const SETUP_REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const SETUP_IDENTITY = /^[0-9a-f]{64}$/;

export function connectorSetupLinkFromSearch(search: string): ConnectorSetupLink | null {
  const params = new URLSearchParams(search);
  const requestId = params.get("setup");
  const identityHash = params.get("identity");
  if (requestId === null || identityHash === null) return null;
  if (!SETUP_REQUEST_ID.test(requestId) || !SETUP_IDENTITY.test(identityHash)) return null;
  return { requestId, identityHash };
}

/** Only the exact identity that was held, still undecided, may be set up from the link. */
export function connectorSetupMatch(item: Pick<LocalCliItem, "identity_hash" | "state">, link: ConnectorSetupLink): ConnectorSetupMatch {
  if (item.identity_hash !== link.identityHash) return "identity_changed";
  return item.state === "unset" ? "ready" : "decided";
}

export function shortIdentity(identityHash: string): string {
  return identityHash.slice(0, 12);
}

/** The `connector_group` part of an apply response, or null when the apply did not resolve a group. */
export function connectorGroupOutcome(body: unknown): ConnectorGroupOutcome | null {
  if (typeof body !== "object" || body === null) return null;
  const group = (body as Record<string, unknown>).connector_group;
  if (typeof group !== "object" || group === null) return null;
  const record = group as Record<string, unknown>;
  const continuation = record.continuation;
  const retryHint = typeof continuation === "object" && continuation !== null
    ? (continuation as Record<string, unknown>).retry_hint : null;
  return {
    status: typeof record.status === "string" ? record.status : "failed",
    resolvedCount: typeof record.resolved_count === "number" ? record.resolved_count : 0,
    retryHint: typeof retryHint === "string" && retryHint.trim() ? retryHint.trim() : null,
  };
}
