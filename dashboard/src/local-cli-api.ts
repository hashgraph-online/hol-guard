import { fetchLocalCliApi } from "./guard-api";
import { SHA256_PATTERN, isLocalCliId, isRecord, requiredInt, requiredString } from "./local-cli-fields";
import { normalizeHelpStatus, normalizeLocalCliItem, normalizeLocalCliList, normalizeMcpClassification } from "./local-cli-normalize";
export { isLocalCliId } from "./local-cli-fields";
export { normalizeLocalCliItem, normalizeLocalCliCommand, normalizeLocalCliList } from "./local-cli-normalize";
import { startCancelableDiscoveryJob } from "./discovery-job-start";
import type { LocalCliContinuity } from "./custom-extension-continuity-api";

export type {
  LocalCliContinuity,
  LocalCliContinuityStatus,
} from "./custom-extension-continuity-api";

export type LocalCliKind = "executable" | "script";
export type LocalCliState = "unset" | "allowed" | "blocked";
export type LocalCliCommandState = "inherit" | "allow" | "review" | "block";
export type LocalCliSurface = "cli" | "mcp" | "package-scripts";
export type McpClassification = {
  effect: string; data: string; destination: string; reversibility: string;
  confidence: "reviewed-mapping" | "limited"; evidence: string[]; warnings: string[];
};
export type LocalCliCommand = {
  command_id: string;
  name: string;
  usage: string;
  description: string;
  parent_id: string | null;
  state: LocalCliCommandState;
  classification?: McpClassification;
};

export type LocalMcpCatalog = {
  complete: boolean;
  stale: boolean;
  reason: string | null;
  pages: number;
  listed_count: number;
  known_count: number;
  protocol_version: string | null;
  revision: number;
  updated_at: string;
  last_complete_at: string | null;
  changes?: Record<"added" | "changed" | "removed" | "stale", string[]>;
  fresh_until?: string;
  cache_scope?: "private" | "public";
  skills_catalog?: { declared: boolean; complete: boolean; stale: boolean; known_count: number; reason: string | null };
};

export type LocalCliItem = {
  cli_id: string;
  name: string;
  kind: LocalCliKind;
  identity_hash: string;
  example_label: string;
  interpreter_name: string | null;
  observed_count: number;
  last_seen_at: string | null;
  source_path: string | null;
  help_status: "ok" | "empty" | "failed" | null;
  surface: LocalCliSurface;
  server_identity_hash: string | null;
  source_label: string | null;
  state: LocalCliState;
  stale: boolean;
  grant_revision: number | null;
  authority_revision: number;
  suggestable: boolean;
  suggestion_score: number;
  commands: LocalCliCommand[];
  continuity?: LocalCliContinuity | null;
  mcp_catalog?: LocalMcpCatalog;
  provider_catalog?: {
    provider: "composio";
    known_count: number;
    full_schema_count: number;
    updated_at: string;
    coverage: "discovery-subset";
    account_binding: "unverified";
  };
  permission_scope?: "configured-connection" | "host-namespace" | "legacy-device";
};

export type LocalCliListResponse = {
  schema_version: string;
  revision: number;
  discovery_issue?: "catalog_limit_reached" | "observed_provider_scan_failed" | "configured_host_scan_failed" | "package_catalog_refresh_failed";
  native_publication?: {
    state: "acknowledged" | "pending" | "failed" | "unavailable";
    revision: number;
    generation?: number;
  };
  items: LocalCliItem[];
  cloud: {
    sync_local_only: boolean;
    continuity_enabled?: boolean;
    summary: string;
  };
};

export type LocalCliMutationPayload = {
  cli_id: string;
  identity_hash: string;
  name: string;
  kind: LocalCliKind;
  example_label: string;
  interpreter_name: string | null;
  state: LocalCliState;
  previous_revision: number;
  session_nonce: string;
  commands?: Array<{ command_id: string; state: LocalCliCommandState }>;
  provider_actions?: Array<{ tool_slug: string; state: "review" | "block"; revision: number }>;
  approval_password?: string;
  approval_totp_code?: string;
};

export class LocalCliApiError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export function addedCustomExtensions(items: readonly LocalCliItem[]): LocalCliItem[] {
  return items.filter((item) => item.state !== "unset");
}

export function connectorWorkspaceItems(items: readonly LocalCliItem[], query = ""): LocalCliItem[] {
  const needle = query.trim().toLowerCase();
  const attention = (item: LocalCliItem) => item.stale || item.state === "unset" || item.mcp_catalog?.stale
    || item.mcp_catalog?.complete === false || Boolean(item.mcp_catalog?.changes?.added.length)
    || Boolean(item.mcp_catalog?.changes?.changed.length);
  return items.filter((item) => item.state !== "unset" || (item.surface === "mcp" && item.suggestable))
    .filter((item) => !needle || [item.name, item.source_label, item.surface,
      ...item.commands.flatMap((command) => [command.name, command.usage, command.description])]
      .some((value) => value?.toLowerCase().includes(needle)))
    .sort((a, b) => Number(attention(b)) - Number(attention(a))
      || (Date.parse(b.last_seen_at ?? "") || 0) - (Date.parse(a.last_seen_at ?? "") || 0)
      || a.name.localeCompare(b.name) || a.cli_id.localeCompare(b.cli_id));
}

export function suggestedCustomExtensions(items: readonly LocalCliItem[]): LocalCliItem[] {
  return items.filter((item) => item.state === "unset" && item.suggestable);
}

export function suggestedHarnessExtensions(items: readonly LocalCliItem[]): LocalCliItem[] {
  return suggestedCustomExtensions(items).filter((item) => item.source_label !== null);
}

export function suggestedSeenExtensions(items: readonly LocalCliItem[]): LocalCliItem[] {
  return suggestedCustomExtensions(items)
    .filter((item) => item.source_label === null && item.surface !== "package-scripts")
    .slice()
    .sort(compareSeenSuggestions);
}

export function suggestedPackageScriptExtensions(items: readonly LocalCliItem[]): LocalCliItem[] {
  return suggestedCustomExtensions(items)
    .filter((item) => item.surface === "package-scripts")
    .slice()
    .sort(compareSeenSuggestions);
}

export function looksLikePackageScriptPaste(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;
  if (/(^|\/)package\.json$/i.test(trimmed)) return true;
  if (!trimmed.includes(" ") && (trimmed.includes("/") || trimmed.includes("\\") || trimmed === ".")) {
    return true;
  }
  const manager = /^(npm|pnpm|yarn|bun)(?:\.cmd)?\b/i.exec(trimmed);
  if (manager === null) return false;
  if (/\b(run|run-script|start|test|stop|restart)\b/i.test(trimmed)) return true;
  return /^yarn\s+\S+/i.test(trimmed);
}

export function filterExtensionSuggestions(
  items: readonly LocalCliItem[],
  query: string,
): LocalCliItem[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return [...items];
  return items.filter((item) => suggestionMatchesQuery(item, needle));
}

export function preferredPackageScriptExtension(items: readonly LocalCliItem[]): LocalCliItem | null {
  return suggestedPackageScriptExtensions(items).find((item) => item.commands.length > 0) ?? null;
}

export function looksLikeProjectRelocatePaste(value: string): boolean {
  const trimmed = unwrapPathPaste(value);
  if (!trimmed) return false;
  if (/(^|[\\/])package\.json$/i.test(trimmed)) return true;
  if (/\s(--prefix|-C|--dir|--cwd|--workspace-dir)(=|\s)/i.test(trimmed)) return true;
  if (/^[A-Za-z]:[\\/]/.test(trimmed) || trimmed.startsWith("/") || trimmed.startsWith("~/") || trimmed === ".") {
    return true;
  }
  return !trimmed.includes(" ") && (trimmed.includes("/") || trimmed.includes("\\"));
}

export function keepsPackageScriptCatalog(
  query: string,
  commands: readonly LocalCliCommand[],
): boolean {
  const trimmed = query.trim();
  if (!trimmed) return true;
  if (looksLikeProjectRelocatePaste(trimmed)) return false;
  if (looksLikePackageScriptPaste(trimmed)) return true;
  const needle = packageScriptFilterNeedle(trimmed) || trimmed.toLowerCase();
  return commands.some((command) => commandMatchesQuery(command, needle));
}

export function filterPackageScriptCommands(
  commands: readonly LocalCliCommand[],
  query: string,
): LocalCliCommand[] {
  const needle = packageScriptFilterNeedle(query);
  if (!needle) return [...commands];
  return commands.filter((command) => commandMatchesQuery(command, needle));
}

export function commandMatchesQuery(command: LocalCliCommand, needle: string): boolean {
  const haystacks = [command.name, command.usage, command.description];
  if (haystacks.some((value) => value.toLowerCase().includes(needle))) return true;
  return colonPartsMatch(command.name, needle);
}

export function enrollablePackageScriptCommands(
  commands: readonly LocalCliCommand[],
): LocalCliCommand[] {
  return commands.filter((command) => command.command_id !== "root" && command.command_id !== "other");
}

export function enrollmentCommandStates(
  commands: readonly LocalCliCommand[],
  pending: LocalCliState,
  surface: LocalCliSurface,
): Array<{ command_id: string; state: LocalCliCommandState }> {
  if (surface !== "package-scripts") return commandStatesFrom(commands);
  return commands.map((command) => ({
    command_id: command.command_id,
    state: packageScriptEnrollmentState(command, pending),
  }));
}

export function applyBulkCommandState(
  commands: readonly LocalCliCommand[],
  state: LocalCliCommandState,
  skipIds: ReadonlySet<string> = new Set(),
): LocalCliCommand[] {
  return commands.map((command) => (
    skipIds.has(command.command_id) ? command : { ...command, state }
  ));
}

export function bulkCommandState(commands: readonly LocalCliCommand[]): LocalCliCommandState | "mixed" {
  if (commands.length === 0) return "inherit";
  const first = commands[0]!.state;
  return commands.every((command) => command.state === first) ? first : "mixed";
}

function commandStatesFrom(
  commands: readonly LocalCliCommand[],
): Array<{ command_id: string; state: LocalCliCommandState }> {
  return commands.map((command) => ({ command_id: command.command_id, state: command.state }));
}

function packageScriptEnrollmentState(
  command: LocalCliCommand,
  pending: LocalCliState,
): LocalCliCommandState {
  if (command.command_id === "root" || command.command_id === "other") return command.state;
  if (pending === "blocked") return "block";
  if (command.state === "block") return "block";
  if (pending === "allowed") return "allow";
  return command.state;
}

function colonPartsMatch(name: string, needle: string): boolean {
  const queryParts = needle.split(":").map((part) => part.trim()).filter(Boolean);
  if (queryParts.length < 2) return false;
  const nameParts = name.toLowerCase().split(":");
  let index = 0;
  for (const part of nameParts) {
    if (index < queryParts.length && part.includes(queryParts[index]!)) index += 1;
  }
  return index === queryParts.length;
}

function packageScriptFilterNeedle(query: string): string {
  const trimmed = query.trim().toLowerCase();
  if (!trimmed) return "";
  return trimmed.replace(/^(npm|pnpm|yarn|bun)(?:\.cmd)?(?:\s+run(?:-script)?)?\s*/, "").trim();
}

function unwrapPathPaste(value: string): string {
  const trimmed = value.trim();
  if ((trimmed.startsWith("'") && trimmed.endsWith("'")) || (trimmed.startsWith('"') && trimmed.endsWith('"'))) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed;
}

export function seenSuggestionMeta(item: LocalCliItem): string {
  if (item.observed_count <= 0) {
    return item.kind === "script" ? "Script" : "Tool";
  }
  if (item.observed_count === 1) return "Seen once";
  return `Seen ${item.observed_count} times`;
}

function compareSeenSuggestions(left: LocalCliItem, right: LocalCliItem): number {
  if (right.suggestion_score !== left.suggestion_score) {
    return right.suggestion_score - left.suggestion_score;
  }
  if (right.observed_count !== left.observed_count) {
    return right.observed_count - left.observed_count;
  }
  const recency = (right.last_seen_at ?? "").localeCompare(left.last_seen_at ?? "");
  if (recency !== 0) return recency;
  return left.name.localeCompare(right.name);
}

function suggestionMatchesQuery(item: LocalCliItem, needle: string): boolean {
  const compact = packageScriptFilterNeedle(needle) || needle;
  const haystacks = [item.name, item.example_label, item.source_label ?? ""];
  if (haystacks.some((value) => value.toLowerCase().includes(needle) || value.toLowerCase().includes(compact))) {
    return true;
  }
  if (item.surface !== "package-scripts") return false;
  return item.commands.some((command) => commandMatchesQuery(command, compact));
}

async function readJson(response: Response): Promise<unknown> {
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const record = isRecord(payload) ? payload : {};
    const code = typeof record.error === "string" ? record.error : "local_cli_request_failed";
    const message = typeof record.message === "string"
      ? record.message
      : "Guard could not update this custom extension.";
    throw new LocalCliApiError(code, message);
  }
  if (payload === null) {
    throw new LocalCliApiError("local_cli_request_failed", "Guard could not update this custom extension.");
  }
  return payload;
}

export async function fetchLocalCliList(): Promise<LocalCliListResponse> {
  return normalizeLocalCliList(await readJson(await fetchLocalCliApi("/v1/local-clis")));
}

export async function previewLocalCliMutation(payload: LocalCliMutationPayload): Promise<{ summary: string }> {
  const body = await readJson(await fetchLocalCliApi("/v1/local-clis/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }));
  if (!isRecord(body)) throw new Error("Invalid local CLI preview");
  return { summary: requiredString(body.summary, "summary") };
}

export async function recognizeLocalCli(
  command: string,
  options?: { cliId?: string; refresh?: boolean },
): Promise<{
  item: LocalCliItem;
  summary: string;
  revision: number;
  help_status: LocalCliItem["help_status"];
}> {
  const body = await readJson(await fetchLocalCliApi("/v1/local-clis/recognize", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      command,
      ...(options?.cliId ? { cli_id: options.cliId } : {}),
      ...(options?.refresh ? { refresh: true } : {}),
    }),
  }));
  if (!isRecord(body)) throw new Error("Invalid local CLI recognition");
  const item = normalizeLocalCliItem(body.item);
  return {
    item,
    summary: requiredString(body.summary, "summary"),
    revision: requiredInt(body.revision, "revision"),
    help_status: normalizeHelpStatus(body.help_status) ?? item.help_status,
  };
}

export async function applyLocalCliMutation(payload: LocalCliMutationPayload): Promise<void> {
  await readJson(await fetchLocalCliApi("/v1/local-clis/apply", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }));
}

export async function refreshMcpInventory(
  cliId: string, signal: AbortSignal, configuredConnections = false, forceRefresh = false,
): Promise<void> {
  if (signal.aborted) return;
  const initialJob = await startCancelableDiscoveryJob(signal, async (clientJobId) => readJson(await fetchLocalCliApi(
    "/v1/local-clis/refresh-job", {
      method: "POST", headers: { "Content-Type": "application/json" }, signal,
      body: JSON.stringify(configuredConnections
        ? { operation: "configured-connections", client_job_id: clientJobId, ...(forceRefresh ? { force_refresh: true } : {}) }
        : { cli_id: cliId, confirm_process_start: true, client_job_id: clientJobId }),
    },
  )));
  if (initialJob === null) return;
  await waitForMcpDiscoveryJob(cliId, initialJob, signal);
}

export async function waitForMcpDiscoveryJob(cliId: string, initialJob: unknown, signal: AbortSignal): Promise<void> {
  const normalize = (body: unknown): Record<string, unknown> => {
    if (!isRecord(body) || typeof body.job_id !== "string" || !/^[a-f0-9]{32}$/.test(body.job_id)
      || body.cli_id !== cliId || !["running", "cancelling", "complete", "cancelled", "failed"].includes(String(body.state))) {
      throw new Error("Invalid discovery progress");
    }
    return body;
  };
  const request = async (payload: Record<string, unknown>) => {
    const body = await readJson(await fetchLocalCliApi("/v1/local-clis/refresh-job", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    }));
    const next = normalize(body);
    if (payload.job_id !== next.job_id) throw new Error("Discovery identity changed");
    return next;
  };
  let job = normalize(initialJob);
  let finished = false;
  try {
    for (let poll = 0; poll < 120; poll += 1) {
      if (signal.aborted) return;
      if (job.state === "complete" || job.state === "cancelled") { finished = true; return; }
      if (job.state === "failed") {
        finished = true;
        let message: string;
        switch (job.error) {
          case "mcp_refresh_unavailable":
            message = "Guard cannot list this connection directly. Refresh it in its host app."; break;
          case "catalog_revision_conflict":
            message = "A newer discovery finished first. Reload the inventory."; break;
          case "configured_host_scan_failed":
            message = "Guard could not read the host's configured connections. Check the host app and retry."; break;
          case "observed_provider_scan_failed":
            message = "Guard could not merge observed provider tools. Known tools and choices were kept; retry discovery."; break;
          case "catalog_limit_reached":
            message = "This connector has more tools than Guard can catalog safely. Existing choices were kept."; break;
          default:
            console.warn("Unknown discovery error code:", job.error);
            message = "Discovery did not finish. Known tools and choices were kept. Try again shortly.";
        }
        throw new Error(message);
      }
      await new Promise<void>((resolve) => {
        const done = () => { window.clearTimeout(timer); signal.removeEventListener("abort", done); resolve(); };
        const timer = window.setTimeout(done, 500);
        signal.addEventListener("abort", done, { once: true });
      });
      if (!signal.aborted) job = await request({ job_id: job.job_id });
    }
    throw new Error("Discovery took too long. Known tools and choices were kept.");
  } finally {
    if (!finished) await request({ job_id: job.job_id, cancel: true });
  }
}

export type McpProviderAction = {
  tool_slug: string;
  toolkit: string;
  description: string;
  full_schema: boolean;
  revision: number;
  updated_at: string;
  permission_state: "review" | "block";
  allow_supported: false;
  account_binding: "unverified";
  classification?: McpClassification;
};

export async function fetchMcpProviderActions(
  cliId: string, options: { search: string; offset: number; signal?: AbortSignal; catalogToken?: string },
): Promise<{ actions: McpProviderAction[]; nextOffset: number | null; catalogToken: string }> {
  const body = await readJson(await fetchLocalCliApi("/v1/local-clis/provider-actions", {
    method: "POST", headers: { "Content-Type": "application/json" }, signal: options.signal,
    body: JSON.stringify({ cli_id: cliId, search: options.search, offset: options.offset, limit: 50,
      ...(options.catalogToken ? { catalog_token: options.catalogToken } : {}) }),
  }));
  if (!isRecord(body) || body.cli_id !== cliId || body.coverage !== "discovery-subset"
    || !Array.isArray(body.actions) || body.actions.length > 50
    || typeof body.catalog_token !== "string" || !SHA256_PATTERN.test(body.catalog_token)) throw new Error("Invalid provider action inventory");
  const actions = body.actions.map((entry): McpProviderAction => {
    if (!isRecord(entry) || typeof entry.tool_slug !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(entry.tool_slug)
      || typeof entry.toolkit !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(entry.toolkit)
      || typeof entry.description !== "string" || entry.description.length > 2000
      || typeof entry.full_schema !== "boolean" || !["review", "block"].includes(String(entry.permission_state)) || entry.allow_supported !== false
      || entry.account_binding !== "unverified" || typeof entry.revision !== "number"
      || !Number.isSafeInteger(entry.revision) || entry.revision < 1
      || typeof entry.updated_at !== "string" || !Number.isFinite(Date.parse(entry.updated_at))) {
      throw new Error("Invalid provider action evidence");
    }
    return {
      tool_slug: entry.tool_slug, toolkit: entry.toolkit, description: entry.description, full_schema: entry.full_schema,
      revision: entry.revision, updated_at: entry.updated_at,
      permission_state: entry.permission_state as "review" | "block", allow_supported: false,
      account_binding: "unverified",
      classification: normalizeMcpClassification(entry.classification),
    };
  });
  const nextOffset = body.next_offset;
  if (nextOffset !== null && (typeof nextOffset !== "number" || !Number.isSafeInteger(nextOffset)
    || nextOffset !== options.offset + 50 || nextOffset > 10_000)) throw new Error("Invalid provider inventory page");
  return { actions, nextOffset, catalogToken: body.catalog_token };
}
