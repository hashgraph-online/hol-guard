import { daemonApi, expect, expectNoErrorBoundary, test, type IntegrationState } from "./fixtures";
import type { Page } from "@playwright/test";
import { contextStatus } from "./context-status";
import { stopContextAssistance } from "./context-stop";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

async function save(page: Page, state: IntegrationState) {
  await page.getByRole("region", { name: "Save CIGAR preferences" }).getByRole("button", { name: "Save CIGAR preferences", exact: true }).click();
  const proof = page.getByRole("dialog");
  await proof.getByLabel("Approval password").fill(state.approvalPassword);
  await proof.getByRole("button", { name: "Save settings" }).click();
  await expect(proof).toHaveCount(0);
  await expect(page.getByText("Settings saved successfully.")).toBeVisible();
}
async function grant(page: Page, state: IntegrationState) {
  await page.getByRole("tab", { name: "Projects & AI apps", exact: true }).click();
  await page.getByLabel("Workspace folder", { exact: true }).fill(state.workspace);
  await page.getByLabel("Files relative to the workspace, one per line").fill("README.md");
  await page.getByRole("button", { name: "Grant review source access", exact: true }).click();
  const proof = page.getByRole("dialog");
  await proof.getByLabel("Approval password").fill(state.approvalPassword);
  await proof.getByRole("button", { name: "Grant source access", exact: true }).click();
  await expect(proof).toHaveCount(0);
}
test("private saved evidence survives runtime restart with fresh grants and can be removed while off", async ({ page, state }) => {
  test.setTimeout(240_000);
  test.skip(state.seeded.context_assistance?.candidateEnrolled !== true, "requires the explicitly approved installed candidate");
  const status = () => contextStatus(state);
  const scopes = () => daemonApi<{ result: { scopes: { scope_id: string }[] } }>(state,
    "/v1/context-assistance/workspace", { method: "POST", body: JSON.stringify({ input: { action: "list" } }) });
  const text = "Private durable workspace evidence requires fresh source permission after restart.";
  writeFileSync(resolve(state.workspace, "README.md"), text + "\n");
  try {
    await page.goto("/cigar?section=runtime");
    await page.getByRole("button", { name: "Refresh runtime list", exact: true }).click();
    const enabled = page.getByRole("switch", { name: "Use CIGAR on this machine", exact: true });
    if (await enabled.getAttribute("aria-checked") !== "true") await enabled.click();
    for (const label of ["Share context between paired AI connections", "Context for AI apps"]) {
      const toggle = page.getByRole("switch", { name: label, exact: true });
      if (await toggle.getAttribute("aria-checked") === "true") await toggle.click();
    }
    await page.getByText("Sources, limits and runtime details", { exact: true }).click();
    await page.getByRole("combobox", { name: "Evidence storage", exact: true }).selectOption("sqlite");
    await page.getByRole("spinbutton", { name: "Context history, saved evidence and shared-note retention in hours", exact: true }).fill("1");
    const files = page.getByRole("switch", { name: "Allow selected workspace documents", exact: true });
    if (await files.getAttribute("aria-checked") !== "true") await files.click();
    await save(page, state);
    await page.getByRole("button", { name: "Start context assistance", exact: true }).click();
    await expect.poll(async () => (await status()).runtime?.persistence_compile_verified, { timeout: 60_000 }).toBe(true);
    const ready = await status();
    expect(ready.effective_preferences.storage).toEqual({ mode: "sqlite", retention_hours: 1 });
    expect(ready.runtime?.shared_compile_verified).toBe(false);
    await grant(page, state);
    const firstScope = (await scopes()).result.scopes[0].scope_id;
    await page.getByLabel("What would you like context about?").fill("durable workspace evidence");
    await page.getByRole("button", { name: "Prepare cited context", exact: true }).click();
    await expect(page.getByRole("region", { name: "Prepared context", exact: true }).getByText(text, { exact: true })).toBeVisible();
    await stopContextAssistance(page);
    await expect.poll(async () => (await status()).requested_enabled).toBe(false);
    expect((await status()).runtime).toBeNull();

    await page.goto("/cigar?section=data");
    const saved = page.getByRole("region", { name: "Saved context evidence", exact: true });
    await expect(saved).toBeVisible();
    await expect(saved.getByText(/Saved data does not restore source or app permissions/)).toBeVisible();
    await expect(saved.locator("dt").filter({ hasText: "Saved workspace/app stores" }).locator("+ dd")).toHaveText("1");
    await expect(page.getByRole("button", { name: "Remove saved evidence", exact: true })).toBeEnabled();
    expect((await status()).runtime).toBeNull();

    await page.goto("/cigar?section=runtime");
    await page.getByRole("button", { name: "Refresh runtime list", exact: true }).click();
    await enabled.click();
    await save(page, state);
    await page.getByRole("button", { name: "Start context assistance", exact: true }).click();
    await expect.poll(async () => (await status()).runtime?.persistence_compile_verified, { timeout: 60_000 }).toBe(true);
    expect((await scopes()).result.scopes).toEqual([]);
    const old = await page.request.post(`${state.origin}/v1/context-assistance/workspace`, {
      headers: { "x-guard-token": state.daemonToken }, data: { input: { action: "compile", scope_id: firstScope, query: "durable evidence" } },
    });
    expect(old.status()).toBe(403);
    await grant(page, state);
    expect((await scopes()).result.scopes[0].scope_id).not.toBe(firstScope);
    await page.getByLabel("What would you like context about?").fill("durable workspace evidence");
    await page.getByRole("button", { name: "Prepare cited context", exact: true }).click();
    await expect(page.getByRole("region", { name: "Prepared context", exact: true }).getByText(text, { exact: true })).toBeVisible();
    await stopContextAssistance(page);
    await expect.poll(async () => (await status()).runtime).toBeNull();
    await page.goto("/cigar?section=data");
    await expect(saved).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    const remove = page.getByRole("button", { name: "Remove saved evidence", exact: true });
    await remove.focus(); await page.keyboard.press("Enter");
    const confirmation = page.getByRole("dialog");
    await expect(confirmation).toContainText("including inactive stores");
    await confirmation.getByRole("button", { name: "Remove saved evidence", exact: true }).click();
    await expect(confirmation).toHaveCount(0);
    await expect(saved.getByText("No saved evidence remains on this machine.", { exact: true })).toBeVisible();
    expect((await status()).runtime).toBeNull();
    await page.reload();
    await expect(saved.getByText("No saved evidence remains on this machine.", { exact: true })).toBeVisible();
    await expectNoErrorBoundary(page);
  } finally {
    await daemonApi(state, "/v1/context-assistance/stop", { method: "POST", body: "{}" });
  }
});
