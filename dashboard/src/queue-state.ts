import { useRef, useCallback } from "react";
import type { GuardApprovalRequest, GuardQueueResolutionResult } from "./guard-types";

export type QueueSortDirection = "newest" | "oldest" | "category";

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
    label: "Credential-looking output",
    shortLabel: "Credential output",
    description: "Command output appears to expose tokens, keys, passwords, or secret-looking values.",
  },
  {
    id: "secret_file_read",
    label: "Secret file read",
    shortLabel: "Secret read",
    description: "Reads local credential stores, environment files, tokens, keys, or other secret paths.",
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
    label: "Harness launch",
    shortLabel: "Launch",
    description: "Starts or reconnects an AI app under Guard control.",
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

export function isReadOnlyQueueGroup(group: QueueGroup): boolean {
  return (
    group.primary.policy_action !== "block" &&
    (group.primary.action_envelope_json?.action_type === "file_read" ||
      group.primary.artifact_type === "file_read_request")
  );
}

export function bulkApproveActionCount(groups: QueueGroup[]): number {
  return groups.reduce((sum, g) => sum + 1 + g.duplicateCount, 0);
}

export function bulkApprovePrimaryIds(groups: QueueGroup[]): string[] {
  return groups.map((g) => g.primary.request_id);
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
  return new Date(item.last_seen_at ?? item.created_at).getTime();
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

  if (hasSecretSignal(decisionCategories, text) && hasExternalSink(text, command)) {
    return "secret_exfiltration";
  }

  if (textIncludesAny(text, ["credential-looking output", "contains credential-looking", "exposes token", "exposes key"])) {
    return "credential_output";
  }

  if (systemPromptAccessText(text)) {
    return "system_prompt_access";
  }

  if (decisionCategories.includes("prompt") || promptInjectionText(text)) {
    return "prompt_injection";
  }

  if (decisionCategories.includes("bypass") || guardBypassText(text)) {
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

  if (hasSecretSignal(decisionCategories, text)) {
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
    envelope?.prompt_excerpt ?? "",
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

function hasExternalSink(text: string, command: string): boolean {
  return networkCommand(command, text) || fileUploadCommand(command, text) || textIncludesAny(text, ["clipboard", "pastebin"]);
}

function networkCommand(command: string, text: string): boolean {
  const normalized = command.toLowerCase();
  return (
    /\b(?:curl|wget|httpie|nc|netcat|ssh|scp|rsync|ftp|sftp)\b/.test(normalized) ||
    /https?:\/\//.test(normalized) ||
    textIncludesAny(text, ["network host", "outbound", "webhook", "https://", "http://"])
  );
}

function fileUploadCommand(command: string, text: string): boolean {
  const normalized = command.toLowerCase();
  return (
    /\b(?:scp|rsync|sftp|ftp)\b/.test(normalized) ||
    /\bcurl\b[\s\S]*(?:--upload-file|-t|--form\s+\S*@|-f\s+\S*@|--data(?:-binary|-raw|-urlencode)?\s+@)/.test(normalized) ||
    /\baws\s+s3\s+cp\b/.test(normalized) ||
    /\bgsutil\s+cp\b/.test(normalized) ||
    textIncludesAny(text, ["upload", "copy-out", "external sink"])
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
  return (
    /\b(?:crontab|schtasks|at)\b/.test(normalized) ||
    /\bsystemctl\s+(?:enable|disable|preset|link)\b/.test(normalized) ||
    /\blaunchctl\s+(?:load|unload|bootstrap|bootout)\b/.test(normalized) ||
    /(?:\.zshrc|\.bashrc|\.bash_profile|\.profile|launchagents|launchdaemons|systemd|login item)/.test(normalized) ||
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
    "eval",
  ]);
}

function generatedInventoryEdit(command: string, text: string): boolean {
  const haystack = `${command} ${text}`.toLowerCase();
  return /docs\/.*(?:api|route|cloud).*inventory\.generated\.(?:md|json|txt)/.test(haystack);
}

function fileDeleteOrCleanupCommand(command: string, text: string): boolean {
  const normalized = command.toLowerCase();
  return (
    /\b(?:rm|unlink|rmdir|shred)\b/.test(normalized) ||
    /\btruncate\s+-s\s+0\b/.test(normalized) ||
    /\bgit\s+(?:clean|reset\s+--hard|checkout\s+--|restore\s+--staged)\b/.test(normalized) ||
    textIncludesAny(text, ["force-clean", "delete files", "wipe files"])
  );
}

function gitOperationCommand(command: string): boolean {
  const normalized = command.toLowerCase();
  return /\bgit\s+(?:add|commit|push|pull|merge|rebase|reset|checkout|restore|clean|stash|tag)\b/.test(normalized);
}

function processControlCommand(command: string): boolean {
  const normalized = command.toLowerCase();
  return /\b(?:kill|pkill|killall|launchctl|systemctl|service|pm2|supervisorctl)\b/.test(normalized);
}

function containerOrDeployCommand(command: string): boolean {
  const normalized = command.toLowerCase();
  return /\b(?:docker|docker-compose|kubectl|helm|terraform|pulumi|flyctl|vercel|netlify|gcloud|aws|az)\b/.test(normalized);
}

function packageInstallCommand(command: string): boolean {
  const normalized = command.toLowerCase();
  return /\b(?:npm|pnpm|yarn|bun|pip|pipx|uv|poetry|brew|cargo|gem|go)\s+(?:add|install|remove|uninstall|update|upgrade|publish)\b/.test(normalized);
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
      envelope?.prompt_excerpt ?? "",
      envelope?.mcp_server ?? "",
      envelope?.mcp_tool ?? "",
      envelope?.package_name ?? "",
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
    envelope?.prompt_excerpt?.slice(0, 40) ??
    item.artifact_type;
  return `${item.harness} — ${preview}`;
}

export function buildHomePrimaryState(
  pendingCount: number,
  watchedAppsCount: number
): HomePrimaryState {
  if (pendingCount > 0) {
    return {
      status: "needs_decision",
      copy: `${pendingCount} action${pendingCount !== 1 ? "s" : ""} paused and waiting for your decision.`,
      ctaLabel: "Review blocked action",
    };
  }
  if (watchedAppsCount === 0) {
    return {
      status: "setup_needed",
      copy: "Guard is running but no apps are connected yet.",
      ctaLabel: "Set up protection",
    };
  }
  return {
    status: "protected",
    copy: "Guard is protecting your apps. No blocked actions right now.",
    ctaLabel: "Open review queue",
  };
}
