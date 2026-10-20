import { harnessDisplayName, resolveRequestWorkingDirectory } from "./approval-center-utils";
import type { GuardApprovalRequest } from "./guard-types";
import { enrollablePackageScriptCommands, type LocalCliItem, type LocalCliSurface } from "./local-cli-api";
import { localCliHref } from "./local-cli-links";
import { BULK_BLOCKED_CATEGORY_IDS, BULK_HIGH_CATEGORY_IDS, resolveQueueCategory } from "./queue-state";

/**
 * Inbox rows held only because Guard does not recognise a local tool this
 * device was never set up for share a `connector:<identity_hash>:<action>`
 * queue group. The Inbox shows one setup card per connector; every row stays
 * listed inside it as evidence.
 */
export const CONNECTOR_GROUP_PREFIX = "connector:";
const PROTECT_LIST_HREF = "/extensions";
const IDENTITY_HASH_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

export type ConnectorSetupGroup = {
  /** `connector:<identity_hash>`, shared by every action row of the connector. */
  key: string;
  identityHash: string;
  /** Rows newest first; each one is still a decidable Inbox row. */
  items: GuardApprovalRequest[];
  /** Calls waiting on this connector, counting merged retries of the same action. */
  callCount: number;
  harnesses: string[];
  latest: GuardApprovalRequest;
  workspaceLabel: string | null;
  caution: boolean;
  cautionCount: number;
  /** Protect entry for this connector, when the local tool list resolves it. */
  cli: LocalCliItem | null;
  setupHref: string;
  /** Top-level command names from the tool's own catalog; never operands. */
  triedCommands: string[];
};

/** The `connector:<identity_hash>` key of a row, or `null` for an ordinary review. */
export function connectorGroupKey(queueGroupId: string | null | undefined): string | null {
  if (typeof queueGroupId !== "string" || !queueGroupId.startsWith(CONNECTOR_GROUP_PREFIX)) return null;
  const identityHash = queueGroupId.slice(CONNECTOR_GROUP_PREFIX.length).split(":")[0] ?? "";
  return IDENTITY_HASH_PATTERN.test(identityHash) ? `${CONNECTOR_GROUP_PREFIX}${identityHash}` : null;
}

export function isConnectorSetupItem(item: GuardApprovalRequest): boolean {
  return item.status === "pending" && connectorGroupKey(item.queue_group_id) !== null;
}

/** Calls one row stands for, counting retries of the same action that were merged into it. */
export function connectorItemCallCount(item: GuardApprovalRequest): number {
  return Math.max(1, item.dedupe_count ?? 1);
}

/** Same caution rule as bulk approval and the built-in extension card. */
export function connectorItemNeedsCaution(item: GuardApprovalRequest): boolean {
  if (item.extension_recommendation?.caution === true) return true;
  const categoryId = resolveQueueCategory(item).id;
  return BULK_HIGH_CATEGORY_IDS.has(categoryId) || BULK_BLOCKED_CATEGORY_IDS.has(categoryId);
}

export function connectorSurfaceLabel(surface: LocalCliSurface | null): string {
  if (surface === "mcp") return "MCP server";
  if (surface === "package-scripts") return "Package scripts";
  return "Local CLI";
}

function itemTimestamp(item: GuardApprovalRequest): number {
  const value = new Date(item.last_seen_at ?? item.created_at).getTime();
  return Number.isFinite(value) ? value : 0;
}

function itemCommand(item: GuardApprovalRequest): string | null {
  return item.action_envelope_json?.command ?? item.raw_command_text ?? null;
}

function workspaceLabel(item: GuardApprovalRequest): string | null {
  const directory = resolveRequestWorkingDirectory(item);
  if (directory === null) return null;
  const segments = directory.split(/[\\/]/).filter(Boolean);
  return segments[segments.length - 1] ?? null;
}

const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
/** Package-manager flags that take the next token as their value (`pnpm --filter web run build`). */
const PACKAGE_MANAGER_VALUE_FLAGS = new Set(["--filter", "-F", "--prefix", "-C", "--dir", "--cwd", "--workspace", "-w", "--workspace-dir"]);
/** Runner verbs that put the script name in the next operand (`npm run build`). */
const SCRIPT_RUN_VERBS = new Set(["run", "run-script"]);

/** The first operands after the executable. Options are skipped and never returned. */
function leadingOperands(command: string, limit: number, valueFlags: ReadonlySet<string>): string[] {
  const tokens = command.trim().split(/\s+/);
  while (tokens.length > 0 && ENV_ASSIGNMENT.test(tokens[0])) tokens.shift();
  const operands: string[] = [];
  for (let index = 1; index < tokens.length && operands.length < limit; index += 1) {
    const token = tokens[index];
    if (token.startsWith("-")) {
      if (valueFlags.has(token)) index += 1;
      continue;
    }
    operands.push(token);
  }
  return operands;
}

/** Script name a package-manager command runs: `npm run build`, `pnpm build` and `yarn build` all give `build`. */
function packageScriptName(command: string): string | null {
  const [first, second] = leadingOperands(command, 2, PACKAGE_MANAGER_VALUE_FLAGS);
  if (first === undefined) return null;
  return SCRIPT_RUN_VERBS.has(first) ? (second ?? null) : first;
}

/** Catalog command names the rows invoked. Arguments are matched, never shown. */
export function triedCatalogCommands(items: GuardApprovalRequest[], cli: LocalCliItem | null): string[] {
  if (cli === null) return [];
  const packageScripts = cli.surface === "package-scripts";
  const known = new Set(
    packageScripts
      ? enrollablePackageScriptCommands(cli.commands).map((command) => command.name)
      : cli.commands.filter((command) => command.parent_id === null).map((command) => command.name),
  );
  const tried = new Set<string>();
  for (const item of items) {
    const command = itemCommand(item);
    if (command === null) continue;
    const name = packageScripts ? packageScriptName(command) : (leadingOperands(command, 1, new Set())[0] ?? null);
    if (name !== null && known.has(name)) tried.add(name);
  }
  return [...tried].sort();
}

export function connectorSetupHref(cli: LocalCliItem | null): string {
  return cli === null ? PROTECT_LIST_HREF : localCliHref(cli.cli_id);
}

export function buildConnectorSetupGroups(
  items: GuardApprovalRequest[],
  localClis: readonly LocalCliItem[] = [],
): ConnectorSetupGroup[] {
  const byKey = new Map<string, GuardApprovalRequest[]>();
  for (const item of items) {
    if (!isConnectorSetupItem(item)) continue;
    const key = connectorGroupKey(item.queue_group_id);
    if (key === null) continue;
    const rows = byKey.get(key) ?? [];
    rows.push(item);
    byKey.set(key, rows);
  }
  const groups: ConnectorSetupGroup[] = [];
  for (const [key, rows] of byKey) {
    const sorted = [...rows].sort((a, b) => itemTimestamp(b) - itemTimestamp(a));
    const identityHash = key.slice(CONNECTOR_GROUP_PREFIX.length);
    const cli = localClis.find((entry) => entry.identity_hash === identityHash) ?? null;
    const cautionCount = sorted
      .filter(connectorItemNeedsCaution)
      .reduce((sum, item) => sum + connectorItemCallCount(item), 0);
    groups.push({
      key,
      identityHash,
      items: sorted,
      callCount: sorted.reduce((sum, item) => sum + connectorItemCallCount(item), 0),
      harnesses: [...new Set(sorted.map((item) => harnessDisplayName(item.harness)))],
      latest: sorted[0],
      workspaceLabel: workspaceLabel(sorted[0]),
      caution: cautionCount > 0,
      cautionCount,
      cli,
      setupHref: connectorSetupHref(cli),
      triedCommands: triedCatalogCommands(sorted, cli),
    });
  }
  return groups.sort((a, b) => itemTimestamp(b.latest) - itemTimestamp(a.latest));
}

/**
 * Stable key of the connector identities in the Inbox, independent of row order
 * and repeats. It changes exactly when a connector appears or leaves.
 */
export function connectorSetupIdentityKey(items: GuardApprovalRequest[]): string {
  const hashes = new Set<string>();
  for (const item of items) {
    if (!isConnectorSetupItem(item)) continue;
    const key = connectorGroupKey(item.queue_group_id);
    if (key !== null) hashes.add(key.slice(CONNECTOR_GROUP_PREFIX.length));
  }
  return [...hashes].sort().join(",");
}
