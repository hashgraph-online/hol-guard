import { fetchLocalCliApi } from "./guard-api";

export type LocalCliKind = "executable" | "script";
export type LocalCliState = "unset" | "allowed" | "blocked";
export type LocalCliCommandState = "inherit" | "allow" | "block";
export type LocalCliSurface = "cli" | "mcp" | "package-scripts";

export type LocalCliCommand = {
  command_id: string;
  name: string;
  usage: string;
  description: string;
  parent_id: string | null;
  state: LocalCliCommandState;
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
};

export type LocalCliListResponse = {
  schema_version: string;
  revision: number;
  items: LocalCliItem[];
  cloud: {
    sync_local_only: boolean;
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

const CLI_ID_PATTERN = /^local-cli\.[a-z0-9]+(?:-[a-z0-9]+){0,8}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`Invalid local CLI ${field}`);
  return value.trim();
}

function requiredInt(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value)) throw new Error(`Invalid local CLI ${field}`);
  return value;
}

function optionalString(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string") throw new Error("Invalid local CLI string");
  return value;
}

export function isLocalCliId(value: string): boolean {
  return CLI_ID_PATTERN.test(value);
}

export function addedCustomExtensions(items: readonly LocalCliItem[]): LocalCliItem[] {
  return items.filter((item) => item.state !== "unset");
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
  return [command.name, command.usage, command.description].some((value) => value.toLowerCase().includes(needle));
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

export function normalizeLocalCliItem(value: unknown): LocalCliItem {
  if (!isRecord(value)) throw new Error("Invalid local CLI item");
  const cliId = requiredString(value.cli_id, "id");
  if (!isLocalCliId(cliId)) throw new Error("Invalid local CLI id");
  const identityHash = requiredString(value.identity_hash, "identity");
  if (!SHA256_PATTERN.test(identityHash)) throw new Error("Invalid local CLI identity");
  const kind = value.kind;
  if (kind !== "executable" && kind !== "script") throw new Error("Invalid local CLI kind");
  const state = value.state;
  if (state !== "unset" && state !== "allowed" && state !== "blocked") throw new Error("Invalid local CLI state");
  return {
    cli_id: cliId,
    name: requiredString(value.name, "name").slice(0, 120),
    kind,
    identity_hash: identityHash,
    example_label: requiredString(value.example_label, "example").slice(0, 160),
    interpreter_name: optionalString(value.interpreter_name),
    observed_count: requiredInt(value.observed_count, "count"),
    last_seen_at: optionalString(value.last_seen_at),
    source_path: optionalString(value.source_path),
    help_status: normalizeHelpStatus(value.help_status),
    surface: normalizeSurface(value.surface),
    server_identity_hash: normalizeIdentityHash(value.server_identity_hash),
    source_label: optionalSourceLabel(value.source_label),
    state,
    stale: value.stale === true,
    grant_revision: value.grant_revision === null || value.grant_revision === undefined
      ? null
      : requiredInt(value.grant_revision, "grant revision"),
    authority_revision: requiredInt(value.authority_revision, "revision"),
    suggestable: value.suggestable === true,
    suggestion_score: optionalScore(value.suggestion_score),
    commands: Array.isArray(value.commands) ? value.commands.map(normalizeLocalCliCommand) : [],
  };
}

function normalizeSurface(value: unknown): LocalCliSurface {
  if (value === "mcp") return "mcp";
  if (value === "package-scripts") return "package-scripts";
  return "cli";
}

function normalizeHelpStatus(value: unknown): LocalCliItem["help_status"] {
  if (value === "ok" || value === "empty" || value === "failed") return value;
  return null;
}

function normalizeIdentityHash(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) return null;
  return value;
}

function optionalScore(value: unknown): number {
  if (value === null || value === undefined) return 0;
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new Error("Invalid local CLI suggestion score");
  }
  return value;
}

function optionalSourceLabel(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string") return null;
  return value.trim().slice(0, 120) || null;
}

export function normalizeLocalCliCommand(value: unknown): LocalCliCommand {
  if (!isRecord(value)) throw new Error("Invalid local CLI command");
  const state = value.state;
  if (state !== "inherit" && state !== "allow" && state !== "block") {
    throw new Error("Invalid local CLI command state");
  }
  const parent = value.parent_id;
  if (parent !== null && parent !== undefined && typeof parent !== "string") {
    throw new Error("Invalid local CLI command parent");
  }
  return {
    command_id: requiredString(value.command_id, "command").slice(0, 80),
    name: requiredString(value.name, "command name").slice(0, 120),
    usage: requiredString(value.usage, "command usage").slice(0, 160),
    description: typeof value.description === "string" ? value.description.slice(0, 240) : "",
    parent_id: typeof parent === "string" && parent.trim() ? parent : null,
    state,
  };
}

export function normalizeLocalCliList(value: unknown): LocalCliListResponse {
  if (!isRecord(value)) throw new Error("Invalid local CLI list");
  const cloud = isRecord(value.cloud) ? value.cloud : {};
  const items = Array.isArray(value.items) ? value.items.map(normalizeLocalCliItem) : [];
  return {
    schema_version: requiredString(value.schema_version, "schema"),
    revision: requiredInt(value.revision, "revision"),
    items,
    cloud: {
      sync_local_only: cloud.sync_local_only !== false,
      summary: typeof cloud.summary === "string"
        ? cloud.summary
        : "Custom extensions stay on this device. Guard Cloud can keep the same extension on your other machines.",
    },
  };
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
  options?: { cliId?: string },
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
