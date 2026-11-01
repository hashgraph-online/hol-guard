import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Page } from "@playwright/test";
import { expect, type IntegrationState } from "./fixtures";
import type { ContextAgentProbe } from "./context-agent-probe";

type NativeReview = { request_id: string; decision_id: string; receipt_id: string };

export async function contextHistoryAndRepairFlow(page: Page, state: IntegrationState, native: NativeReview, probe: ContextAgentProbe) {
  async function ask(route: string, input: Record<string, unknown>) {
    const response = await page.request.post(`${state.origin}/v1/context-assistance/${route}`, {
      headers: { "x-guard-token": state.daemonToken }, data: { input },
    });
    expect(response.ok()).toBe(true);
    return (await response.json()).result;
  }
  const scopes = (await ask("workspace", { action: "list" })).scopes;
  const scope = scopes.find((scope: { app: string }) => scope.app === "dashboard");
  expect(scope).toBeTruthy();
  // The earlier release-only document need not rank for a native package
  // decision. Supply relevant fixture guidance, then prove it was cited.
  writeFileSync(resolve(state.workspace, "README.md"), "Guard native decision action package operation install deny review policy supporting project guidance. Package installation uses the original reviewed release procedure.\n");
  await ask("workspace-access", { action: "refresh", scope_id: scope.scope_id });
  const prepared = await ask("workspace", { action: "action", scope_id: scope.scope_id, decision_id: native.decision_id });
  expect(prepared.brief.citations.some((citation: { source: string }) => citation.source.startsWith("source:"))).toBe(true);
  await page.goto(`/evidence?selected=${native.receipt_id}`);
  const history = page.getByRole("region", { name: "Prepared context history", exact: true });
  await history.getByRole("button", { name: "Load prepared context history", exact: true }).click();
  const first = history.getByRole("button", { name: /^View prepared context 1/ });
  await expect(first).toContainText(native.decision_id);
  await first.click();
  const historical = history.getByRole("region", { name: "Historical prepared context", exact: true });
  await expect(historical.getByText(/Authenticated native Guard decision/)).toBeVisible();
  await expect(historical.getByText(/Same source version when checked/)).toBeVisible();
  writeFileSync(resolve(state.workspace, "README.md"), "Historical browser fixture now uses a revised release procedure.\n");
  await first.click();
  await expect(historical.getByText(/Changed since preparation/)).toBeVisible();
  await ask("workspace-access", { action: "refresh", scope_id: scope.scope_id });
  await ask("workspace", { action: "action", scope_id: scope.scope_id, decision_id: native.decision_id });
  await history.getByRole("button", { name: "Load prepared context history", exact: true }).click();
  await first.click();
  await history.getByRole("button", { name: /^View prepared context 2/ }).click();
  await historical.getByText("Compare with previously opened context", { exact: true }).click();
  await expect(historical.getByText("Both snapshots are historical.", { exact: false })).toBeVisible();
  writeFileSync(resolve(state.workspace, "README.md"), "\0unsafe current source");
  await history.getByRole("button", { name: /^View prepared context 2/ }).click();
  await expect(historical.getByText(/Retained text is withheld/)).toBeVisible();
  await expect(historical.getByText("Compare with previously opened context", { exact: true })).toHaveCount(0);
  writeFileSync(resolve(state.workspace, "README.md"), "Historical browser fixture now uses a revised release procedure.\n");

  await page.goto("/cigar?section=data");
  const repair = page.getByRole("region", { name: "Context data and repair controls", exact: true });
  await repair.getByRole("button", { name: "Refresh context data", exact: true }).click();
  const [download] = await Promise.all([
    page.waitForEvent("download"), repair.getByRole("button", { name: "Export context diagnostics", exact: true }).click(),
  ]);
  const path = await download.path();
  expect(path).toBeTruthy();
  const encoded = readFileSync(path!, "utf8");
  const diagnostics = JSON.parse(encoded);
  expect(diagnostics.schema).toBe("guard-context-diagnostics.v1");
  expect(diagnostics.runtime.python_version.slice(0, 2)).toEqual([3, 14]);
  expect(diagnostics.counts.history_entries).toBeGreaterThanOrEqual(2);
  expect(encoded).not.toContain(state.workspace);
  expect(encoded).not.toContain(state.guardHome);
  expect(encoded).not.toContain("unsafe current source");
  expect(encoded).not.toContain("Historical browser fixture");
  await repair.getByRole("button", { name: "Clear context history", exact: true }).click();
  const confirm = page.getByRole("dialog");
  await expect(confirm).toContainText("Guard approvals and evidence are unchanged.");
  await confirm.getByRole("button", { name: "Clear history", exact: true }).click();
  await expect(repair.getByText("Prepared context history cleared.", { exact: false })).toBeVisible();
  expect((await probe.request("get_context_status")).data.phase).toBe("authorized");
  await page.goto(`/evidence?selected=${native.receipt_id}`);
  await history.getByRole("button", { name: "Load prepared context history", exact: true }).click();
  await expect(history.getByText("No prepared context is retained for this selection.", { exact: true })).toBeVisible();
}

export async function clearContextFromRepair(page: Page) {
  await page.goto("/cigar?section=data");
  const repair = page.getByRole("region", { name: "Context data and repair controls", exact: true });
  await repair.getByRole("button", { name: "Clear all context data", exact: true }).click();
  const confirm = page.getByRole("dialog");
  await expect(confirm).toContainText("Grant access again to continue.");
  await confirm.getByRole("button", { name: "Clear context data", exact: true }).click();
  await expect(repair.getByText("Context data cleared.", { exact: false })).toBeVisible();
}
