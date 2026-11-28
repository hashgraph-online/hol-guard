import { createContext, useContext } from "react";
import type { GuardApprovalRequest } from "../guard-types";

/**
 * Burst coalescing (BP-T066, PRD 5.5 and R-QUIET-2). Pending browser rows that Core gave the same
 * `browser_burst_key` (one session, one driver, one origin) and that arrived within the review
 * window of each other show as one card: the first step, a count and the step list. The rows stay
 * separate in the store. Resolving the card answers its first row; a grant also clears the rows it
 * covers, and the rest stay pending and form the next card.
 */
export const BROWSER_BURST_WINDOW_MS = 2 * 60 * 1000;

export type BrowserBurstStep = { requestId: string; text: string };
export type BrowserBurst = { count: number; steps: BrowserBurstStep[] };
export type CoalescedQueue = {
  items: GuardApprovalRequest[];
  bursts: ReadonlyMap<string, BrowserBurst>;
};

/** Core adds the key to carded rows whose session and site it knows. */
type BurstRow = GuardApprovalRequest & { browser_burst_key?: string | null };

function burstKey(item: BurstRow): string | null {
  if (item.status !== "pending" || item.browser_card == null) return null;
  const key = item.browser_burst_key;
  return typeof key === "string" && key.length > 0 ? key : null;
}

function arrivedAt(item: GuardApprovalRequest): number {
  const at = new Date(item.created_at).getTime();
  return Number.isFinite(at) ? at : Number.NaN;
}

function stepText(item: GuardApprovalRequest): string {
  return item.browser_card?.headline || item.queue_preview || item.artifact_name;
}

/** Splits one key's rows, oldest first, wherever the gap to the previous row passes the window. */
function runsOf(rows: GuardApprovalRequest[]): GuardApprovalRequest[][] {
  const ordered = rows
    .filter((row) => Number.isFinite(arrivedAt(row)))
    .sort((a, b) => arrivedAt(a) - arrivedAt(b) || a.request_id.localeCompare(b.request_id));
  const runs: GuardApprovalRequest[][] = [];
  for (const row of ordered) {
    const run = runs[runs.length - 1];
    const previous = run?.[run.length - 1];
    if (run && previous && arrivedAt(row) - arrivedAt(previous) <= BROWSER_BURST_WINDOW_MS) {
      run.push(row);
    } else {
      runs.push([row]);
    }
  }
  return runs.filter((run) => run.length > 1);
}

/** The queue with each burst folded into its first step, kept where the burst first appears. */
export function coalesceBrowserBursts(items: GuardApprovalRequest[]): CoalescedQueue {
  const byKey = new Map<string, GuardApprovalRequest[]>();
  for (const item of items) {
    const key = burstKey(item);
    if (key !== null) byKey.set(key, [...(byKey.get(key) ?? []), item]);
  }
  const lead = new Map<string, GuardApprovalRequest>();
  const bursts = new Map<string, BrowserBurst>();
  for (const rows of byKey.values()) {
    for (const run of runsOf(rows)) {
      const first = run[0];
      bursts.set(first.request_id, {
        count: run.length,
        steps: run.map((row) => ({ requestId: row.request_id, text: stepText(row) })),
      });
      for (const row of run) lead.set(row.request_id, first);
    }
  }
  if (bursts.size === 0) return { items, bursts };
  const shown = new Set<string>();
  const folded: GuardApprovalRequest[] = [];
  for (const item of items) {
    const first = lead.get(item.request_id) ?? item;
    if (shown.has(first.request_id)) continue;
    shown.add(first.request_id);
    folded.push(first);
  }
  return { items: folded, bursts };
}

export const BrowserBurstContext = createContext<ReadonlyMap<string, BrowserBurst>>(new Map());

export function useBrowserBurst(requestId: string): BrowserBurst | null {
  return useContext(BrowserBurstContext).get(requestId) ?? null;
}
