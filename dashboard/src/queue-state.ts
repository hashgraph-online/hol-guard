import { useRef, useCallback } from "react";
import type { GuardApprovalRequest, GuardProtectionState, GuardQueueResolutionResult } from "./guard-types";
import { requestSupportsScope } from "./approval-scopes";

export type QueueSortDirection = "newest" | "oldest" | "category" | "highest_risk";

export type SemanticGroupId = "all" | "files" | "shell" | "network" | "tools" | "other";

export type QueueDateRange = {
  from: string;
  to: string;
};

export const REVIEW_SEMANTIC_GROUPS: { id: SemanticGroupId; label: string; matches: QueueCategoryId[] }[] = [
  { id: "all", label: "All", matches: [] },
  {
    id: "files",
    label: "File read / write",
    matches: ["file_read", "source_edit", "docs_edit", "generated_inventory_edit"],
  },
  {
    id: "shell",
    label: "Shell execution",
    matches: ["shell_command", "destructive_shell", "encoded_shell", "git_operation", "process_control"],
  },
  {
    id: "network",
    label: "Network / data egress",
    matches: ["network", "secret_exfiltration", "secret_file_read", "credential_output", "file_upload"],
  },
  {
    id: "tools",
    label: "MCP, skill & packages",
    matches: ["mcp_tool", "package_script", "browser_action", "package_install"],
  },
  {
    id: "other",
    label: "Agent autonomy & other",
    matches: [
      "harness_start",
      "prompt_injection",
      "system_prompt_access",
      "guard_bypass",
      "config_change",
      "container_or_deploy",
      "persistence_change",
      "other",
    ],
  },
];

export type QueueCategoryId =
  | "credential_output"
  | "secret_file_read"
  | "file_read"
  | "secret_exfiltration"
  | "system_prompt_access"
  | "prompt_injection"
  | "guard_bypass"
  | "generated_inventory_edit"
  | "docs_edit"
  | "source_edit"
  | "config_change"
  | "file_upload"
  | "file_delete_cleanup"
  | "git_operation"
  | "process_control"
  | "container_or_deploy"
  | "persistence_change"
  | "package_install"
  | "package_script"
  | "destructive_shell"
  | "encoded_shell"
  | "network"
  | "mcp_tool"
  | "browser_action"
  | "harness_start"
  | "shell_command"
  | "other";

export type QueueCategory = {
  id: QueueCategoryId;
  label: string;
  shortLabel: string;
  description: string;
};

export const QUEUE_CATEGORIES: QueueCategory[] = [
  {
    id: "credential_output",
    label: "Secret-looking output",
    shortLabel: "Secret output",
    description: "Command output contains patterns that resemble tokens, keys, passwords, or other secret-looking values. Review before allowing if this output will leave the local machine.",
  },
  {
    id: "secret_file_read",
    label: "Secret file access",
    shortLabel: "Secret read",
    description: "Reads paths known to store secrets: env files, credential stores, token files, SSH keys, or cloud config. Normal source reads are classified as file read instead.",
  },
  {
    id: "file_read",
    label: "File read",
    shortLabel: "File read",
    description: "Requests local file contents, paths, or read-only filesystem access.",
  },
  {
    id: "secret_exfiltration",
    label: "Secret exfiltration path",
    shortLabel: "Secret exfil",
    description: "Moves local secret material toward a network host, upload, clipboard, or external sink.",
  },
  {
    id: "system_prompt_access",
    label: "System prompt access",
    shortLabel: "System prompt",
    description: "Attempts to reveal hidden system, developer, policy, or harness instructions.",
  },
  {
    id: "prompt_injection",
    label: "Prompt injection attempt",
    shortLabel: "Prompt injection",
    description: "Prompt content tries to override instructions, ignore policy, or redirect tool behavior.",
  },
  {
    id: "guard_bypass",
    label: "Guard bypass attempt",
    shortLabel: "Bypass",
    description: "Attempts to disable, evade, suppress, or work around Guard policy checks.",
  },
  {
    id: "generated_inventory_edit",
    label: "Generated inventory edit",
    shortLabel: "Inventory edit",
    description: "Updates generated API, route, or cloud inventory documentation.",
  },
  {
    id: "docs_edit",
    label: "Documentation edit",
    shortLabel: "Docs edit",
    description: "Changes markdown, docs, runbooks, guides, or generated prose files.",
  },
  {
    id: "source_edit",
    label: "Source code edit",
    shortLabel: "Source edit",
    description: "Changes application, script, test, or source-controlled code files.",
  },
  {
    id: "config_change",
    label: "Configuration change",
    shortLabel: "Config",
    description: "Modifies Guard, harness, project, CI, package, or tool configuration.",
  },
  {
    id: "file_upload",
    label: "File upload or copy-out",
    shortLabel: "Upload",
    description: "Copies local files to a remote host, bucket, paste service, or external destination.",
  },
  {
    id: "file_delete_cleanup",
    label: "File delete or cleanup",
    shortLabel: "Delete",
    description: "Deletes, wipes, truncates, force-cleans, or otherwise risks local data loss.",
  },
  {
    id: "git_operation",
    label: "Git workspace operation",
    shortLabel: "Git",
    description: "Mutates repository state through git add, commit, merge, rebase, push, pull, reset, or checkout.",
  },
  {
    id: "process_control",
    label: "Process control",
    shortLabel: "Process",
    description: "Starts, stops, kills, reloads, or restarts local services and processes.",
  },
  {
    id: "container_or_deploy",
    label: "Container or deploy command",
    shortLabel: "Deploy",
    description: "Runs Docker, Kubernetes, Helm, cloud, deployment, or infrastructure commands.",
  },
  {
    id: "persistence_change",
    label: "Persistence change",
    shortLabel: "Persistence",
    description: "Changes cron, launch agents, services, shell profiles, startup items, or scheduled jobs.",
  },
  {
    id: "package_install",
    label: "Package install",
    shortLabel: "Install",
    description: "Installs, removes, upgrades, or publishes dependencies and packages.",
  },
  {
    id: "package_script",
    label: "Package script",
    shortLabel: "Package script",
    description: "Runs install, postinstall, build, test, or package-manager scripts.",
  },
  {
    id: "destructive_shell",
    label: "Destructive shell command",
    shortLabel: "Destructive",
    description: "Deletes, overwrites, wipes, force-cleans, or otherwise risks data loss.",
  },
  {
    id: "encoded_shell",
    label: "Encoded shell execution",
    shortLabel: "Encoded shell",
    description: "Runs encoded, encrypted, decoded, or obfuscated shell payloads.",
  },
  {
    id: "network",
    label: "Network request",
    shortLabel: "Network",
    description: "Contacts hosts, downloads, calls APIs, or opens network destinations.",
  },
  {
    id: "mcp_tool",
    label: "MCP tool call",
    shortLabel: "MCP",
    description: "Invokes an MCP server or tool with sensitive arguments.",
  },
  {
    id: "browser_action",
    label: "Browser action",
    shortLabel: "Browser",
    description: "Uses browser automation, navigation, or form interaction.",
  },
  {
    id: "harness_start",
    label: "Agent launch",
    shortLabel: "Agent launch",
    description: "Starts or reconnects an AI agent or harness under Guard control. Review when unexpected autonomy or a new session begins.",
  },
  {
    id: "shell_command",
    label: "Shell command",
    shortLabel: "Shell",
    description: "Runs a shell command that does not fit a more specific category.",
  },
  {
    id: "other",
    label: "Other review",
    shortLabel: "Other",
    description: "Needs review but has no more specific category signal.",
  },
];

const QUEUE_CATEGORY_BY_ID = new Map(QUEUE_CATEGORIES.map((category) => [category.id, category]));

const SIGNAL_SEVERITY_SCORE: Record<string, number> = {
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
  info: 5,
};

const CATEGORY_RISK_SCORE = new Map<QueueCategoryId, number>([
  ["secret_exfiltration", 1],
  ["credential_output", 1],
  ["guard_bypass", 1],
  ["prompt_injection", 2],
  ["system_prompt_access", 2],
  ["secret_file_read", 2],
  ["encoded_shell", 2],
  ["persistence_change", 3],
  ["destructive_shell", 3],
  ["file_delete_cleanup", 3],
  ["network", 3],
  ["container_or_deploy", 4],
  ["git_operation", 4],
  ["process_control", 4],
  ["file_upload", 4],
  ["package_install", 4],
  ["package_script", 4],
  ["source_edit", 5],
  ["config_change", 5],
  ["shell_command", 5],
  ["mcp_tool", 5],
  ["browser_action", 5],
  ["harness_start", 5],
  ["file_read", 6],
  ["docs_edit", 6],
  ["generated_inventory_edit", 6],
  ["other", 6],
]);

export function riskScore(item: GuardApprovalRequest): number {
  if (item.policy_action === "block") {
    return 0;
  }
  const signals = item.decision_v2_json?.signals ?? [];
  if (signals.length > 0) {
    const minSeverityScore = Math.min(...signals.map((s) => SIGNAL_SEVERITY_SCORE[s.severity] ?? 6));
    const dedupeBonus = (item.dedupe_count ?? 0) > 0 ? -0.25 : 0;
    return minSeverityScore + dedupeBonus;
  }
  const categoryScore = CATEGORY_RISK_SCORE.get(resolveQueueCategory(item).id) ?? 6;
  const dedupeBonus = (item.dedupe_count ?? 0) > 0 ? -0.25 : 0;
  return categoryScore + dedupeBonus;
}

export function buildStaleRequestCopy(item: GuardApprovalRequest): string | null {
  if (item.status === "resolved") {
    return "This request was already decided. Return to your AI app to resume, or reload the queue.";
  }
  if (item.status === "expired") {
    return "This request timed out. Return to your AI app to try the action again, then review the new request here.";
  }
  const seenAt = item.last_seen_at ?? item.created_at;
  const ageMinutes = (Date.now() - new Date(seenAt).getTime()) / 60000;
  if (ageMinutes > 30 && item.status === "pending") {
    return "This request has been waiting a while. If you already decided this elsewhere, reload the queue to see the latest state.";
  }
  return null;
}

export type QueueGroup = {
  primary: GuardApprovalRequest;
  duplicateCount: number;
  duplicateIds: string[];
};

export type HomeProtectionStatus = "protected" | "needs_decision" | "setup_needed";

export type HomePrimaryState = {
  status: HomeProtectionStatus;
  copy: string;
  ctaLabel: string;
};

export function isSensitiveFileReadItem(item: GuardApprovalRequest): boolean {
  return resolveQueueCategory(item).id === "secret_file_read";
}

export function isReadOnlyQueueGroup(group: QueueGroup): boolean {
  if (group.primary.policy_action === "block") return false;
  const isFileRead =
    group.primary.action_envelope_json?.action_type === "file_read" ||
    group.primary.artifact_type === "file_read_request";
  if (!isFileRead) return false;
  return !isSensitiveFileReadItem(group.primary);
}

/**
 * Categories that must never be bulk-approved: these are trust-breaking or
 * secret-compromising — secrets, exfiltration, credential output, prompt
 * injection, system prompt access, guard bypass, and encoded payloads. They
 * stay in the queue for individual review. Mirrors the server-side
 * `_bulk_request_is_bulk_blocked` set.
 *
 * Destructive deletes (destructive_shell, file_delete_cleanup) are intentionally
 * NOT in this set: they are dangerous but not trust-breaking, so they are
 * bulk-approvable at the highest risk tier with a typed confirmation.
 */
const BULK_BLOCKED_CATEGORY_IDS: ReadonlySet<QueueCategoryId> = new Set([
  "secret_exfiltration",
  "credential_output",
  "secret_file_read",
  "prompt_injection",
  "system_prompt_access",
  "guard_bypass",
  "encoded_shell",
]);

/**
 * Low-risk categories: file reads, docs edits, generated inventory. Everything
 * else that is not blocked is "elevated" (shell, source edits, git, network,
 * packages, deploys, destructive deletes, etc.).
 */
const BULK_LOW_CATEGORY_IDS: ReadonlySet<QueueCategoryId> = new Set([
  "file_read",
  "docs_edit",
  "generated_inventory_edit",
  "other",
]);

/**
 * High-risk categories: destructive deletes and wipes. These are bulk-eligible
 * (not trust-breaking) but always escalate the disclosure to the highest tier
 * and require a typed confirmation, since approving many at once can cause
 * irreversible data loss.
 */
const BULK_HIGH_CATEGORY_IDS: ReadonlySet<QueueCategoryId> = new Set([
  "destructive_shell",
  "file_delete_cleanup",
]);

export type BulkApprovalTier = "blocked" | "high" | "elevated" | "low";

/**
 * Classify a queue group into a bulk-approval risk tier. "blocked" groups are
 * never bulk-eligible; "low" and "elevated" are both approvable, with the
 * dashboard's risk disclosure escalating its copy and friction accordingly.
 */
export function bulkApprovalRiskTier(group: QueueGroup): BulkApprovalTier {
  if (
    group.primary.decision_contract_error !== undefined ||
    group.primary.policy_action === "block" ||
    group.primary.policy_action === "sandbox-required"
  ) {
    return "blocked";
  }
  const categoryId = resolveQueueCategory(group.primary).id;
  if (BULK_BLOCKED_CATEGORY_IDS.has(categoryId)) return "blocked";
  if (BULK_HIGH_CATEGORY_IDS.has(categoryId)) return "high";
  if (BULK_LOW_CATEGORY_IDS.has(categoryId)) return "low";
  return "elevated";
}

export function isBulkApprovableGroup(group: QueueGroup): boolean {
  return (
    bulkApprovalRiskTier(group) !== "blocked" &&
    requestSupportsScope(group.primary, "allow", "artifact")
  );
}

export function countSensitiveFileReadGroups(groups: QueueGroup[]): number {
  return groups.filter((g) => {
    if (g.primary.policy_action === "block") return false;
    const isFileRead =
      g.primary.action_envelope_json?.action_type === "file_read" ||
      g.primary.artifact_type === "file_read_request";
    return isFileRead && isSensitiveFileReadItem(g.primary);
  }).length;
}

/**
 * Sum of duplicate retry actions across the given groups. Used by the bulk
 * approval risk disclosure to surface "X duplicate retries are included".
 */
export function countDuplicateActionsInGroups(groups: QueueGroup[]): number {
  return groups.reduce((sum, group) => sum + Math.max(0, group.duplicateCount), 0);
}

export type SensitiveFileReadSummary = {
  count: number;
  samplePaths: string[];
};

/**
 * Collect the sensitive file-read groups in the queue along with up to three
 * sample paths. These groups are never approved by bulk approval — they stay
 * in the queue for individual review — but the disclosure surfaces them so the
 * user knows what was deliberately excluded.
 */
export function summarizeSensitiveFileReadGroups(groups: QueueGroup[]): SensitiveFileReadSummary {
  const paths: string[] = [];
  let count = 0;
  for (const group of groups) {
    if (group.primary.policy_action === "block") continue;
    const isFileRead =
      group.primary.action_envelope_json?.action_type === "file_read" ||
      group.primary.artifact_type === "file_read_request";
    if (!isFileRead || !isSensitiveFileReadItem(group.primary)) continue;
    count += 1;
    if (paths.length < 3) {
      const path =
        group.primary.action_envelope_json?.target_paths?.[0] ??
        group.primary.launch_target ??
        group.primary.artifact_name;
      if (path) paths.push(path);
    }
  }
  return { count, samplePaths: paths };
}

export function bulkApproveActionCount(groups: QueueGroup[]): number {
  return groups.reduce((sum, g) => sum + 1 + g.duplicateCount, 0);
}

export function bulkApprovePrimaryIds(groups: QueueGroup[]): string[] {
  return groups.map((g) => g.primary.request_id);
}

export function isDuplicateGroup(group: QueueGroup): boolean {
  return group.duplicateCount > 0;
}

export function buildProgressCopy(activeIndex: number, total: number): string {
  if (total === 0) {
    return "";
  }
  return `${activeIndex + 1} of ${total} decisions`;
}

export function selectNextAfterResolution(
  result: GuardQueueResolutionResult,
  currentItems: GuardApprovalRequest[]
): string | null {
  if (result.next_selectable_request_id !== null) {
    return result.next_selectable_request_id;
  }
  const remaining = result.remaining_pending_summaries;
  if (remaining.length > 0) {
    return remaining[0].request_id;
  }
  const resolvedIds = new Set<string>(result.resolved_duplicate_ids);
  if (result.resolved_scope_ids !== undefined) {
    for (const id of result.resolved_scope_ids) {
      resolvedIds.add(id);
    }
  }
  if (result.resolved_request !== null) {
    resolvedIds.add(result.resolved_request.request_id);
  }
  if (result.item !== null) {
    resolvedIds.add(result.item.request_id);
  }
  const next = currentItems.find((item) => !resolvedIds.has(item.request_id));
  return next?.request_id ?? null;
}

export function groupDuplicates(items: GuardApprovalRequest[]): QueueGroup[] {
  const seen = new Set<string>();
  const groups: QueueGroup[] = [];
  const groupedItems = new Map<string, GuardApprovalRequest[]>();
  for (const item of items) {
    const groupId = item.queue_group_id ?? null;
    if (groupId === null) {
      continue;
    }
    const peers = groupedItems.get(groupId) ?? [];
    peers.push(item);
    groupedItems.set(groupId, peers);
  }
  for (const item of items) {
    if (seen.has(item.request_id)) {
      continue;
    }
    seen.add(item.request_id);
    const groupId = item.queue_group_id ?? null;
    if (groupId !== null) {
      const peers = (groupedItems.get(groupId) ?? []).filter(
        (peer) => peer.request_id !== item.request_id && !seen.has(peer.request_id)
      );
      for (const peer of peers) {
        seen.add(peer.request_id);
      }
      groups.push({
        primary: item,
        duplicateCount: peers.length,
        duplicateIds: peers.map((p) => p.request_id),
      });
    } else {
      groups.push({ primary: item, duplicateCount: 0, duplicateIds: [] });
    }
  }
  return groups;
}

function queueTimestamp(item: GuardApprovalRequest): number {
  const timestamp = new Date(item.last_seen_at ?? item.created_at).getTime();
  return Number.isFinite(timestamp) ? timestamp : 0;
}

function dateInputToBoundary(value: string, boundary: "start" | "end"): number | null {
  if (value.trim().length === 0) {
    return null;
  }
  const [year, month, day] = value.split("-").map((part) => Number.parseInt(part, 10));
  if (!year || !month || !day) {
    return null;
  }
  const date = new Date(year, month - 1, day);
  if (boundary === "start") {
    date.setHours(0, 0, 0, 0);
  } else {
    date.setHours(23, 59, 59, 999);
  }
  const timestamp = date.getTime();
  return Number.isFinite(timestamp) ? timestamp : null;
}

export function filterQueueByDateRange(
  items: GuardApprovalRequest[],
  range: QueueDateRange
): GuardApprovalRequest[] {
  const from = dateInputToBoundary(range.from, "start");
  const to = dateInputToBoundary(range.to, "end");
  if (from === null && to === null) {
    return items;
  }
  return items.filter((item) => {
    const timestamp = queueTimestamp(item);
    if (from !== null && timestamp < from) {
      return false;
    }
    if (to !== null && timestamp > to) {
      return false;
    }
    return true;
  });
}

const queueDateFormatter = new Intl.DateTimeFormat("en-US", {
  month: "2-digit",
  day: "2-digit",
  year: "2-digit",
  hour: "numeric",
  minute: "2-digit",
});

export function formatQueueRequestDate(item: GuardApprovalRequest): string {
  const timestamp = queueTimestamp(item);
  if (timestamp === 0) {
    return "Date unknown";
  }
  return queueDateFormatter.format(new Date(timestamp));
}

export function queueCategoryById(id: QueueCategoryId): QueueCategory {
  return QUEUE_CATEGORY_BY_ID.get(id) ?? QUEUE_CATEGORIES[QUEUE_CATEGORIES.length - 1];
}

export function resolveQueueCategory(item: GuardApprovalRequest): QueueCategory {
  return queueCategoryById(resolveQueueCategoryId(item));
}

export function queueCategoriesForItems(items: GuardApprovalRequest[]): QueueCategory[] {
  const seen = new Set<QueueCategoryId>();
  for (const item of items) {
    seen.add(resolveQueueCategory(item).id);
  }
  return QUEUE_CATEGORIES.filter((category) => seen.has(category.id));
}

function resolveQueueCategoryId(item: GuardApprovalRequest): QueueCategoryId {
  const envelope = item.action_envelope_json;
  const decisionCategories = item.decision_v2_json?.signals.map((signal) => signal.category) ?? [];
  const command = envelope?.command ?? item.launch_target ?? "";
  const text = queueCategoryText(item);
  const isPromptReview = envelope?.action_type === "prompt" || decisionCategories.includes("prompt");
  const isWriteReview = envelope?.action_type === "file_write" || commandLooksLikeFileEdit(command);

  if (hasSecretSignal(decisionCategories, text) && hasExternalSink(text, command, !isWriteReview)) {
    return "secret_exfiltration";
  }

  if (textIncludesAny(text, ["credential-looking output", "contains credential-looking", "exposes token", "exposes key"])) {
    return "credential_output";
  }

  if (isPromptReview && systemPromptAccessText(text)) {
    return "system_prompt_access";
  }

  if (isPromptReview && promptInjectionText(text)) {
    return "prompt_injection";
  }

  if (decisionCategories.includes("bypass") || (!isWriteReview && guardBypassText(text))) {
    return "guard_bypass";
  }

  if (decisionCategories.includes("persistence") || persistenceCommand(command, text)) {
    return "persistence_change";
  }

  if (decisionCategories.includes("encoded") || encodedCommand(text)) {
    return "encoded_shell";
  }

  if (generatedInventoryEdit(command, text)) {
    return "generated_inventory_edit";
  }

  if (fileDeleteOrCleanupCommand(command, text)) {
    return "file_delete_cleanup";
  }

  if (gitOperationCommand(command)) {
    return "git_operation";
  }

  if (fileUploadCommand(command, text)) {
    return "file_upload";
  }

  if (inboundCopyCommand(command)) {
    return "network";
  }

  if (processControlCommand(command)) {
    return "process_control";
  }

  if (containerOrDeployCommand(command)) {
    return "container_or_deploy";
  }

  if (envelope?.action_type === "package_script") {
    return "package_script";
  }

  if (packageInstallCommand(command)) {
    return "package_install";
  }

  if (secretReadAction(item, command, text) && hasSecretSignal(decisionCategories, text)) {
    return "secret_file_read";
  }

  if (envelope?.action_type === "mcp_tool") {
    return "mcp_tool";
  }
  if (envelope?.action_type === "config_change") {
    return "config_change";
  }
  if (envelope?.action_type === "browser_action") {
    return "browser_action";
  }
  if (envelope?.action_type === "harness_start") {
    return "harness_start";
  }
  if (envelope?.action_type === "file_read" || item.artifact_type === "file_read_request") {
    return "file_read";
  }

  if (docsEditCommand(command, text)) {
    return "docs_edit";
  }

  if (sourceEditCommand(command, text) || envelope?.action_type === "file_write" || commandLooksLikeFileEdit(command)) {
    return "source_edit";
  }

  if (textIncludesAny(text, ["destructive shell command", " rm -", "rm -rf", "delete files", "wipe", "force-clean", "git clean -fd", "truncate"])) {
    return "destructive_shell";
  }

  if (networkCommand(command, text) || decisionCategories.includes("network")) {
    return "network";
  }

  if (envelope?.action_type === "shell_command" || item.artifact_type === "command" || text.includes("shell command")) {
    return "shell_command";
  }
  return "other";
}

function queueCategoryText(item: GuardApprovalRequest): string {
  const envelope = item.action_envelope_json;
  return [
    item.artifact_name,
    item.artifact_type,
    item.risk_headline ?? "",
    item.risk_summary ?? "",
    item.trigger_summary ?? "",
    item.launch_summary ?? "",
    item.why_now ?? "",
    item.launch_target ?? "",
    envelope?.action_type ?? "",
    envelope?.command ?? "",
    envelope?.tool_name ?? "",
    (envelope?.prompt_text ?? envelope?.prompt_excerpt) ?? "",
    envelope?.mcp_server ?? "",
    envelope?.mcp_tool ?? "",
    envelope?.package_manager ?? "",
    envelope?.package_name ?? "",
    envelope?.script_name ?? "",
    ...(item.risk_signals ?? []),
    ...(envelope?.target_paths ?? []),
    ...(envelope?.network_hosts ?? []),
    ...(item.decision_v2_json?.signals.map((signal) => `${signal.category} ${signal.title} ${signal.plain_reason}`) ?? []),
  ].join(" ").toLowerCase();
}

function textIncludesAny(text: string, needles: string[]): boolean {
  return needles.some((needle) => text.includes(needle));
}

function commandLooksLikeFileEdit(command: string): boolean {
  const normalized = command.trim().toLowerCase();
  if (!normalized) {
    return false;
  }
  return (
    /\bperl\b[\s\S]*\s-[\w-]*i\b/.test(normalized) ||
    /\bsed\b[\s\S]*\s-[\w-]*i\b/.test(normalized) ||
    /\bpython(?:3)?\b[\s\S]*(?:write_text|open\([^)]*,\s*['"]w|path\.write)/.test(normalized) ||
    /\btee\s+-a?\b/.test(normalized) ||
    /\bapply_patch\b/.test(normalized)
  );
}

function hasSecretSignal(decisionCategories: string[], text: string): boolean {
  return (
    decisionCategories.includes("secret") ||
    textIncludesAny(text, [
      "credential",
      "secret",
      ".env",
      "token",
      "api key",
      "apikey",
      "password",
      "private key",
      "ssh key",
      "aws_access_key",
      "github_token",
    ])
  );
}

function secretReadAction(item: GuardApprovalRequest, command: string, text: string): boolean {
  const envelope = item.action_envelope_json;
  return (
    envelope?.action_type === "file_read" ||
    item.artifact_type === "file_read_request" ||
    (readCommand(command) && hasSecretPathText(text))
  );
}

function readCommand(command: string): boolean {
  return /\b(?:cat|grep|rg|sed\s+-n|awk|less|more|head|tail)\b/.test(command.toLowerCase());
}

function hasSecretPathText(text: string): boolean {
  return textIncludesAny(text, [".env", "token", "secret", "credential", "password", "private key", "api key"]);
}

function hasExternalSink(text: string, command: string, allowTextHints: boolean): boolean {
  return (
    fileUploadCommand(command, text) ||
    outboundNetworkCommand(command, text) ||
    (allowTextHints && textIncludesAny(text, ["exfiltrat", "clipboard", "pastebin"]))
  );
}

function outboundNetworkCommand(command: string, text: string): boolean {
  return networkCommand(command, text) && !inboundCopyCommand(command);
}

function networkCommand(command: string, text: string): boolean {
  const normalized = command.toLowerCase();
  return (
    /(?:^|\s)(?:curl|wget|httpie|nc|netcat|scp|rsync|ftp|sftp)(?:\s|$)/.test(normalized) ||
    /(?:^|\s)ssh\s+/.test(normalized) ||
    /https?:\/\//.test(normalized) ||
    textIncludesAny(text, ["network host", "outbound", "webhook", "https://", "http://"])
  );
}

function fileUploadCommand(command: string, text: string): boolean {
  return (
    outboundCopyCommand(command) ||
    /\bcurl\b[\s\S]*(?:--upload-file(?:=|\s+)\S+|(?:^|\s)-T(?:\S+|\s+\S+)|--form(?:=|\s+)\S*@|-F(?:\S*@|\s+\S*@)|--data(?:-binary|-raw|-urlencode)?(?:=|\s+)@\S+)/.test(command)
  );
}

function systemPromptAccessText(text: string): boolean {
  return textIncludesAny(text, [
    "system prompt",
    "developer instructions",
    "hidden instruction",
    "hidden prompt",
    "reveal the prompt",
    "show the prompt",
  ]);
}

function promptInjectionText(text: string): boolean {
  return textIncludesAny(text, [
    "prompt injection",
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "override instruction",
    "jailbreak",
    "act as",
  ]);
}

function guardBypassText(text: string): boolean {
  return textIncludesAny(text, [
    "bypass guard",
    "disable guard",
    "skip approval",
    "ignore approval",
    "without approval",
    "guard_bypass",
    "no guard",
  ]);
}

function persistenceCommand(command: string, text: string): boolean {
  const normalized = command.toLowerCase();
  const mutatesPersistenceFile = commandLooksLikeFileEdit(command) || text.includes("file_write");
  return (
    /\|\s*crontab\b/.test(normalized) ||
    /\bcrontab\s+-(?!l\b)/.test(normalized) ||
    /\b(?:schtasks|at)\b/.test(normalized) ||
    /\bsystemctl\s+(?:enable|disable|preset|link)\b/.test(normalized) ||
    /\blaunchctl\s+(?:load|unload|bootstrap|bootout)\b/.test(normalized) ||
    (mutatesPersistenceFile && /(?:\.zshrc|\.bashrc|\.bash_profile|\.profile|launchagents|launchdaemons|systemd|login item)/.test(normalized)) ||
    textIncludesAny(text, ["persistence", "startup item", "scheduled task", "launch agent"])
  );
}

function encodedCommand(text: string): boolean {
  return textIncludesAny(text, [
    "encoded or encrypted shell command",
    "base64",
    "openssl enc",
    "xxd -r",
    "decode-and-exec",
  ]);
}

function outboundCopyCommand(command: string): boolean {
  const operands = copyOperands(command);
  return isOutboundCopy(operands?.source, operands?.destination);
}

function inboundCopyCommand(command: string): boolean {
  const operands = copyOperands(command);
  return isInboundCopy(operands?.source, operands?.destination);
}

function copyOperands(command: string): { source: string; destination: string } | null {
  const tokens = stripOptionTokens(shellTokens(command));
  const awsIndex = findSequence(tokens, ["aws", "s3", "cp"]);
  if (awsIndex >= 0) {
    return positionalPair(tokens.slice(awsIndex + 3));
  }
  const gsutilIndex = findSequence(tokens, ["gsutil", "cp"]);
  if (gsutilIndex >= 0) {
    return positionalPair(tokens.slice(gsutilIndex + 2));
  }
  const copyIndex = tokens.findIndex((token) => token === "scp" || token === "rsync");
  if (copyIndex >= 0) {
    return positionalPair(tokens.slice(copyIndex + 1));
  }
  return null;
}

function positionalPair(tokens: string[]): { source: string; destination: string } | null {
  const positional = tokens.filter((token) => token === "-" || !token.startsWith("-"));
  if (positional.length < 2) {
    return null;
  }
  return { source: positional[0], destination: positional[1] };
}

function stripOptionTokens(tokens: string[]): string[] {
  const optionsWithValues = new Set([
    "--profile",
    "--region",
    "--endpoint-url",
    "--source-region",
    "--exclude",
    "--include",
    "--acl",
    "--storage-class",
    "--sse",
    "--rsh",
    "-P",
    "-i",
    "-o",
    "-F",
    "-f",
    "-S",
    "-s",
    "-e",
  ]);
  const stripped: string[] = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token === "-") {
      stripped.push(token);
      continue;
    }
    if (!token.startsWith("-")) {
      stripped.push(token);
      continue;
    }
    const optionName = token.includes("=") ? token.slice(0, token.indexOf("=")) : token;
    if (optionsWithValues.has(optionName) && !token.includes("=")) {
      index += 1;
    }
  }
  return stripped;
}

function shellTokens(command: string): string[] {
  return (command.match(/"[^"]*"|'[^']*'|\S+/g) ?? []).map((token) => token.replace(/^['"]|['"]$/g, ""));
}

function findSequence(tokens: string[], sequence: string[]): number {
  return tokens.findIndex((_, index) => sequence.every((part, offset) => tokens[index + offset] === part));
}

function isOutboundCopy(source: string | undefined, destination: string | undefined): boolean {
  return source !== undefined && destination !== undefined && !remotePath(source) && remotePath(destination);
}

function isInboundCopy(source: string | undefined, destination: string | undefined): boolean {
  return source !== undefined && destination !== undefined && remotePath(source) && !remotePath(destination);
}

function remotePath(value: string): boolean {
  return /^(?:s3|gs):\/\//.test(value) || /^[\w.-]+@?[\w.-]+:/.test(value);
}

function generatedInventoryEdit(command: string, text: string): boolean {
  const haystack = `${command} ${text}`.toLowerCase();
  return (
    (commandLooksLikeFileEdit(command) || text.includes("file_write")) &&
    /docs\/.*(?:api|route|cloud).*inventory\.generated\.(?:md|json|txt)/.test(haystack)
  );
}

function fileDeleteOrCleanupCommand(command: string, text: string): boolean {
  const normalized = command.toLowerCase();
  return (
    /\b(?:rm|unlink|rmdir|shred)\b/.test(normalized) ||
    /\btruncate\s+-s\s+0\b/.test(normalized) ||
    /\bgit\s+(?:clean|reset\s+--hard|checkout\s+--)\b/.test(normalized) ||
    textIncludesAny(text, ["force-clean", "delete files", "wipe files"])
  );
}

function gitOperationCommand(command: string): boolean {
  const normalized = command.toLowerCase();
  return /\bgit\s+(?:add|commit|push|pull|merge|rebase|reset|checkout|restore|clean|stash|tag)\b/.test(normalized);
}

function processControlCommand(command: string): boolean {
  const normalized = command.toLowerCase();
  return (
    /\b(?:kill|pkill|killall|launchctl|systemctl|pm2|supervisorctl)\b/.test(normalized) ||
    /\bservice\s+\S+\s+(?:start|stop|restart|reload|status)\b/.test(normalized)
  );
}

function containerOrDeployCommand(command: string): boolean {
  const normalized = command.toLowerCase();
  return /\b(?:docker|docker-compose|kubectl|helm|terraform|pulumi|flyctl|vercel|netlify|gcloud|aws|az)\b/.test(normalized);
}

function packageInstallCommand(command: string): boolean {
  const normalized = command.toLowerCase();
  return /\b(?:npm|pnpm|yarn|bun|pip|pipx|uv|poetry|brew|cargo|gem|go)\s+(?:add|i|install|remove|uninstall|update|upgrade|publish)\b/.test(normalized);
}

function docsEditCommand(command: string, text: string): boolean {
  const haystack = `${command} ${text}`.toLowerCase();
  return (
    (commandLooksLikeFileEdit(command) || text.includes("file_write")) &&
    /(?:^|\s)(?:docs\/|readme|changelog|\.md\b|\.mdx\b)/.test(haystack)
  );
}

function sourceEditCommand(command: string, text: string): boolean {
  const haystack = `${command} ${text}`.toLowerCase();
  return (
    (commandLooksLikeFileEdit(command) || text.includes("file_write")) &&
    /\.(?:ts|tsx|js|jsx|mjs|cjs|py|rs|go|java|kt|swift|rb|php|css|scss|html|json|yaml|yml|toml)\b/.test(haystack)
  );
}

export function sortQueue(
  items: GuardApprovalRequest[],
  direction: QueueSortDirection
): GuardApprovalRequest[] {
  if (direction === "highest_risk") {
    const scores = new Map(items.map((item) => [item.request_id, riskScore(item)]));
    return [...items].sort((a, b) => {
      const scoreDelta = (scores.get(a.request_id) ?? 6) - (scores.get(b.request_id) ?? 6);
      if (scoreDelta !== 0) return scoreDelta;
      return (
        new Date(b.last_seen_at ?? b.created_at).getTime() -
        new Date(a.last_seen_at ?? a.created_at).getTime()
      );
    });
  }
  const categoryLabels =
    direction === "category"
      ? new Map(items.map((item) => [item.request_id, resolveQueueCategory(item).label]))
      : null;
  return [...items].sort((a, b) => {
    if (categoryLabels !== null) {
      const categoryDelta = (categoryLabels.get(a.request_id) ?? "").localeCompare(
        categoryLabels.get(b.request_id) ?? ""
      );
      if (categoryDelta !== 0) {
        return categoryDelta;
      }
    }
    const dateA = queueTimestamp(a);
    const dateB = queueTimestamp(b);
    const dateDelta = direction === "oldest" ? dateA - dateB : dateB - dateA;
    if (dateDelta !== 0) {
      return dateDelta;
    }
    return direction === "oldest"
      ? a.request_id.localeCompare(b.request_id)
      : b.request_id.localeCompare(a.request_id);
  });
}

export function filterQueueByCategory(
  items: GuardApprovalRequest[],
  categoryId: QueueCategoryId | "all"
): GuardApprovalRequest[] {
  if (categoryId === "all") {
    return items;
  }
  return items.filter((item) => resolveQueueCategory(item).id === categoryId);
}

export function searchQueue(items: GuardApprovalRequest[], term: string): GuardApprovalRequest[] {
  const normalized = term.trim().toLowerCase();
  if (normalized.length === 0) {
    return items;
  }
  return items.filter((item) => {
    const envelope = item.action_envelope_json;
    const category = resolveQueueCategory(item);
    const parts: string[] = [
      item.artifact_name,
      item.artifact_id,
      item.artifact_type,
      item.harness,
      item.policy_action,
      item.risk_headline ?? "",
      item.risk_summary ?? "",
      item.trigger_summary ?? "",
      item.launch_summary ?? "",
      item.why_now ?? "",
      envelope?.command ?? "",
      item.raw_command_text ?? "",
      item.fallback_cli_command ?? "",
      item.review_command ?? "",
      (envelope?.prompt_text ?? envelope?.prompt_excerpt) ?? "",
      envelope?.mcp_server ?? "",
      envelope?.mcp_tool ?? "",
      envelope?.package_name ?? "",
      envelope?.script_name ?? "",
      JSON.stringify(envelope?.raw_payload_redacted ?? {}),
      category.label,
      category.shortLabel,
      ...(envelope?.network_hosts ?? []),
      ...(envelope?.target_paths ?? []),
    ];
    return parts.join(" ").toLowerCase().includes(normalized);
  });
}

export function resolveStaleRequestRecovery(
  activeRequestId: string | null,
  items: GuardApprovalRequest[]
): string | null {
  if (activeRequestId === null) {
    return null;
  }
  const found = items.find((item) => item.request_id === activeRequestId);
  if (found !== undefined) {
    return activeRequestId;
  }
  return items[0]?.request_id ?? null;
}

export type IsResolvingGuard = {
  isResolvingRef: React.RefObject<boolean>;
  setResolving: (value: boolean) => void;
};

export function useIsResolving(): IsResolvingGuard {
  const isResolvingRef = useRef(false);
  const setResolving = useCallback((value: boolean) => {
    isResolvingRef.current = value;
  }, []);
  return { isResolvingRef, setResolving };
}

export function buildNextUpChipText(item: GuardApprovalRequest): string {
  const envelope = item.action_envelope_json;
  const preview =
    envelope?.command?.slice(0, 40) ??
    envelope?.mcp_tool ??
    (envelope?.prompt_text ?? envelope?.prompt_excerpt)?.slice(0, 40) ??
    item.artifact_type;
  return `${item.harness} — ${preview}`;
}

export function buildHomePrimaryState(
  pendingCount: number,
  watchedAppsCount: number,
  protectionState: GuardProtectionState = "degraded",
): HomePrimaryState {
  if (pendingCount > 0) {
    return {
      status: "needs_decision",
      copy: `${pendingCount} action${pendingCount !== 1 ? "s" : ""} paused and waiting for your decision.`,
      ctaLabel: "Review waiting action",
    };
  }
  if (watchedAppsCount === 0) {
    return {
      status: "setup_needed",
      copy: "Guard is running but no apps are connected yet.",
      ctaLabel: "Set up protection",
    };
  }
  if (protectionState !== "protected") {
    return {
      status: "setup_needed",
      copy: protectionState === "partial"
        ? "App protection is partial. Review the missing evidence before relying on it."
        : "App protection is degraded. Review required checks before relying on it.",
      ctaLabel: "Review protection",
    };
  }
  return {
    status: "protected",
    copy: "Guard is protecting your apps. No actions are waiting for a decision.",
    ctaLabel: "Open review queue",
  };
}
