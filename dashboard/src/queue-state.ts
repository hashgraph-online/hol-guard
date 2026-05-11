import { useRef, useCallback } from "react";
import type { GuardApprovalRequest, GuardQueueResolutionResult } from "./guard-types";

export type QueueSortDirection = "newest" | "oldest" | "category";

export type QueueCategoryId =
  | "secret_access"
  | "data_exfiltration"
  | "file_edit"
  | "file_read"
  | "destructive_shell"
  | "encoded_shell"
  | "network"
  | "mcp_tool"
  | "package_script"
  | "prompt_instruction"
  | "config_change"
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
    id: "secret_access",
    label: "Secret or credential access",
    shortLabel: "Secrets",
    description: "Reads or exposes local credentials, tokens, keys, or secret files.",
  },
  {
    id: "data_exfiltration",
    label: "Data exfiltration path",
    shortLabel: "Exfiltration",
    description: "Moves local sensitive data toward a network host, upload, clipboard, or external sink.",
  },
  {
    id: "file_edit",
    label: "File edit command",
    shortLabel: "File edit",
    description: "Changes local files in place without matching a delete or wipe pattern.",
  },
  {
    id: "file_read",
    label: "Sensitive file read",
    shortLabel: "File read",
    description: "Requests local file contents, paths, or read-only filesystem access.",
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
    label: "Network access",
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
    id: "package_script",
    label: "Package script",
    shortLabel: "Package",
    description: "Runs install, postinstall, build, or package-manager scripts.",
  },
  {
    id: "prompt_instruction",
    label: "Prompt instruction",
    shortLabel: "Prompt",
    description: "User or model prompt asks the harness to perform a sensitive action.",
  },
  {
    id: "config_change",
    label: "Configuration change",
    shortLabel: "Config",
    description: "Modifies Guard, harness, project, or tool configuration.",
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
  const text = queueCategoryText(item);

  if (decisionCategories.includes("network") || textIncludesAny(text, ["network host", "outbound", "webhook", "curl ", "https://", "http://"])) {
    if (textIncludesAny(text, ["secret", "credential", "token", "api key", "upload", "exfiltrat"])) {
      return "data_exfiltration";
    }
    return "network";
  }
  if (decisionCategories.includes("secret") || textIncludesAny(text, ["credential-looking", "secret", ".env", "token", "api key", "password", "private key"])) {
    return "secret_access";
  }
  if (textIncludesAny(text, ["encoded or encrypted shell command", "base64", "openssl enc", "xxd -r", "decode-and-exec"])) {
    return "encoded_shell";
  }
  if (envelope?.action_type === "file_read" || item.artifact_type === "file_read_request") {
    return "file_read";
  }
  if (envelope?.action_type === "mcp_tool") {
    return "mcp_tool";
  }
  if (envelope?.action_type === "package_script") {
    return "package_script";
  }
  if (envelope?.action_type === "prompt") {
    return "prompt_instruction";
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
  if (envelope?.action_type === "file_write" || commandLooksLikeFileEdit(envelope?.command ?? item.launch_target ?? "")) {
    return "file_edit";
  }
  if (textIncludesAny(text, ["destructive shell command", " rm -", "rm -rf", "delete", "wipe", "force-clean", "git clean -fd", "truncate"])) {
    return "destructive_shell";
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

export function sortQueue(
  items: GuardApprovalRequest[],
  direction: QueueSortDirection
): GuardApprovalRequest[] {
  return [...items].sort((a, b) => {
    if (direction === "category") {
      const categoryDelta = resolveQueueCategory(a).label.localeCompare(resolveQueueCategory(b).label);
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
    const parts: string[] = [
      item.artifact_name,
      item.artifact_type,
      item.harness,
      item.policy_action,
      envelope?.command ?? "",
      envelope?.prompt_excerpt ?? "",
      envelope?.mcp_server ?? "",
      envelope?.mcp_tool ?? "",
      envelope?.package_name ?? "",
      resolveQueueCategory(item).label,
      resolveQueueCategory(item).shortLabel,
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
