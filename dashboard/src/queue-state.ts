import type { GuardApprovalRequest, GuardQueueResolutionResult } from "./guard-types";

export type QueueSortDirection = "newest" | "oldest";

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

export function sortQueue(
  items: GuardApprovalRequest[],
  direction: QueueSortDirection
): GuardApprovalRequest[] {
  return [...items].sort((a, b) => {
    const dateA = queueTimestamp(a);
    const dateB = queueTimestamp(b);
    const dateDelta = direction === "newest" ? dateB - dateA : dateA - dateB;
    if (dateDelta !== 0) {
      return dateDelta;
    }
    return direction === "newest"
      ? b.request_id.localeCompare(a.request_id)
      : a.request_id.localeCompare(b.request_id);
  });
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
      copy: "HOL Guard is running but no apps are connected yet.",
      ctaLabel: "Connect an app",
    };
  }
  return {
    status: "protected",
    copy: "HOL Guard is watching this machine. No blocked actions right now.",
    ctaLabel: "Open review queue",
  };
}
