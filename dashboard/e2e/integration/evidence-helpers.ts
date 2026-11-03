import type { Locator, Page } from "@playwright/test";
import type { IntegrationState } from "./fixtures";

// Facts scripts/ci/dashboard_integration_seeds/evidence.py returns.
export type Featured = { receipt_id: string; name: string; harness: string; decision: string; category: string };

export type Disposition = { allowed: number; reviewed: number; blocked: number };

export type ReceiptFacts = {
  source_scope: string;
  total: number;
  page_size: number;
  by_harness: Record<string, number>;
  by_harness_disposition: Record<string, Disposition>;
  by_category: Record<string, number>;
  by_decision: Record<string, number>;
  by_disposition: Disposition;
  within_7_days: number;
  within_30_days: number;
  featured: Record<string, Featured>;
  newest_name: string;
  oldest_name: string;
};

export type CommandRecord = {
  command: string;
  harness: string;
  status: string;
  action: string | null;
  prompted: boolean;
  rules: string[];
  rule_titles: string[];
  extensions: string[];
};

export type CommandFacts = {
  total: number;
  records: Record<string, CommandRecord>;
  by_harness: Record<string, number>;
};

export function receiptFacts(state: IntegrationState): ReceiptFacts {
  return state.seeded.evidence.receipts as ReceiptFacts;
}

export function commandFacts(state: IntegrationState): CommandFacts {
  return state.seeded.evidence.commands as CommandFacts;
}

// Receipts seeded by this area, without anything other areas seeded.
export function receiptsUrl(facts: ReceiptFacts, query = ""): string {
  const scope = `sourceScope=${encodeURIComponent(facts.source_scope)}`;
  return `/evidence?${scope}${query ? `&${query}` : ""}`;
}

export function actionsTable(page: Page): Locator {
  return page.getByRole("table", { name: "Evidence actions" });
}

// Body rows of a table, without the header row.
export function bodyRows(table: Locator): Locator {
  return table.getByRole("rowgroup").last().getByRole("row");
}

export function rowByName(table: Locator, name: string | RegExp): Locator {
  return table.getByRole("row", { name });
}

// The row's title cell opens the detail panel; the app and category cells hold filter shortcuts.
export async function openRow(table: Locator, name: string | RegExp): Promise<void> {
  await rowByName(table, name).getByRole("cell").nth(1).click();
}

export function commandRecords(page: Page): Locator {
  return page.getByRole("region", { name: "Command activity records" });
}

// The table's body row whose command cell holds exactly this command.
export function commandRow(page: Page, command: string): Locator {
  return commandRecords(page).getByRole("row").filter({ has: page.getByText(command, { exact: true }) });
}

export function commandDetail(page: Page): Locator {
  return page.getByRole("complementary", { name: "Command activity detail" });
}

export function commandsUrl(query = ""): string {
  return `/evidence?view=commands${query ? `&${query}` : ""}`;
}

// Reads the number that follows a label in a flat text blob, e.g. "Lifetime actions 58".
export function numberAfter(text: string, label: string): number {
  const match = new RegExp(`${label}\\s*(\\d+)`, "i").exec(text.replace(/\s+/g, " "));
  if (!match) throw new Error(`no number after "${label}" in: ${text.slice(0, 200)}`);
  return Number(match[1]);
}
