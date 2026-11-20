import { expect, type Locator, type Page } from "@playwright/test";

import { daemonApi, type IntegrationState } from "./fixtures";

export type SeededRequest = {
  id: string;
  kind: string;
  preview: string;
  category: string;
  risk: "low" | "medium" | "high";
};

export type InboxSeed = {
  workspace: string;
  pendingCount: number;
  requests: Record<"shell" | "mcp" | "package" | "exfil" | "read_a" | "read_b", SeededRequest>;
};

// Every seeded artifact id carries this, so searching for it isolates the
// seeded rows from anything another area queued.
export const SEED_SEARCH = "inbox-e2e";

export function inboxSeed(state: IntegrationState): InboxSeed {
  return state.seeded["inbox"] as unknown as InboxSeed;
}

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function queue(page: Page): Locator {
  return page.getByRole("listbox", { name: "Review queue" });
}

export function queueRow(page: Page, preview: string): Locator {
  return queue(page).getByRole("option", { name: new RegExp(escapeRegExp(preview)) });
}

export async function searchQueue(page: Page, term: string): Promise<void> {
  await page.getByRole("searchbox", { name: "Search review queue" }).fill(term);
}

export function inboxNavLink(page: Page): Locator {
  return page.getByRole("navigation", { name: "Guard dashboard" }).getByRole("link", { name: /^Inbox\b/ });
}

type RequestRecord = {
  status: string;
  resolution_action: string | null;
  resolution_scope: string | null;
};

export async function requestRecord(state: IntegrationState, id: string): Promise<RequestRecord> {
  return daemonApi<RequestRecord>(state, `/v1/requests/${id}`);
}

export async function pendingCount(state: IntegrationState): Promise<number> {
  const runtime = await daemonApi<{ pending_count: number }>(state, "/v1/runtime");
  return runtime.pending_count;
}

export async function receiptDecision(state: IntegrationState, id: string): Promise<string | undefined> {
  const receipts = await daemonApi<{ items: Array<{ approval_request_id: string | null; policy_decision: string }> }>(
    state,
    "/v1/receipts?limit=200",
  );
  return receipts.items.find((item) => item.approval_request_id === id)?.policy_decision;
}

export async function savedDecisionArtifacts(state: IntegrationState): Promise<string[]> {
  const policy = await daemonApi<{ items: Array<{ artifact_id: string | null; action: string }> }>(state, "/v1/policy");
  return policy.items.filter((item) => item.action === "allow").map((item) => item.artifact_id ?? "");
}

/**
 * Press a decision button, then satisfy the approval gate if it asks. An allow
 * needs a fresh proof; a block does not, so the dialog is optional.
 */
export async function decide(
  page: Page,
  state: IntegrationState,
  button: Locator,
  requestId: string,
  confirmButtonName: string,
): Promise<void> {
  await button.click();
  const dialog = page.getByRole("dialog", { name: "Approval password required" });
  await expect
    .poll(async () => (await dialog.isVisible()) || (await requestRecord(state, requestId)).status === "resolved")
    .toBe(true);
  if (await dialog.isVisible()) {
    await dialog.getByLabel("Approval password").fill(state.approvalPassword);
    await dialog.getByRole("button", { name: confirmButtonName }).click();
    await expect(dialog).toBeHidden();
  }
}
