import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import type { Page } from "@playwright/test";
import { contextStatus } from "./context-status";
import { stopContextAssistance } from "./context-stop";
import { daemonApi, expect, expectNoErrorBoundary, test, type IntegrationState } from "./fixtures";
import { decide, requestRecord } from "./inbox-helpers";

test.use({ actionTimeout: 15_000 });

async function save(page: Page, state: IntegrationState) {
  await page.getByRole("region", { name: "Save CIGAR preferences" }).getByRole("button", { name: "Save CIGAR preferences", exact: true }).click();
  const proof = page.getByRole("dialog");
  await proof.getByLabel("Approval password").fill(state.approvalPassword);
  await proof.getByRole("button", { name: "Save settings" }).click();
  await expect(proof).toHaveCount(0);
  await expect(page.getByText("Settings saved successfully.")).toBeVisible();
}

test("execution opt-in and browser approvals reach the installed native executor", async ({ page, state }) => {
  test.setTimeout(240_000);
  const seed = state.seeded.context_assistance;
  test.skip(seed?.candidateEnrolled !== true, "requires the explicitly approved installed candidate");
  const status = () => contextStatus(state);
  type Result = { code: number; request_id?: string; effect_unchanged?: boolean; output_not_retained?: boolean;
    expected_effect?: boolean; requires_consent?: boolean };
  const sink = (choice: string, action: string): Result => JSON.parse(execFileSync(String(seed.pythonExecutable), [
    "-B", resolve(import.meta.dirname, "../../../scripts/ci/dashboard_context_execution.py"),
    "--guard-home", state.guardHome, "--workspace", state.workspace, "--case", choice, "--action", action,
  ], { encoding: "utf8", timeout: 40_000 }));
  try {
    // The fixture explicitly asks before execution of even the captured
    // builtins. Approvals themselves must come through the browser below.
    expect(sink("allow-once", "configure")).toMatchObject({ code: 0, execution_review_required: true });
    await page.goto("/cigar?section=runtime");
    await page.getByRole("button", { name: "Refresh runtime list", exact: true }).click();
    const enabled = page.getByRole("switch", { name: "Use CIGAR on this machine", exact: true });
    await expect(enabled).toHaveAttribute("aria-checked", "false");
    await enabled.click();
    for (const label of ["Share context between paired AI connections", "Context for AI apps"]) {
      const toggle = page.getByRole("switch", { name: label, exact: true });
      if (await toggle.getAttribute("aria-checked") === "true") await toggle.click();
    }
    await page.getByText("Sources, limits and runtime details", { exact: true }).click();
    const execution = page.getByRole("switch", { name: "Associate native context with execution", exact: true });
    await expect(execution).toHaveAttribute("aria-checked", "false");
    await execution.focus();
    await page.keyboard.press("Space");
    await save(page, state);
    expect((await status()).effective_enabled).toBe(false);
    await page.getByRole("button", { name: "Start context assistance", exact: true }).click();
    await expect.poll(async () => (await status()).execution_ready, { timeout: 90_000 }).toBe(true);
    const ready = await status();
    expect(ready.runtime?.interpreter.version.slice(0, 2)).toEqual([3, 14]);
    expect(ready.runtime?.execution_handoff_verified).toBe(true);
    expect(ready.preferences.features.agent_context).toBe(false);
    expect(ready.preferences.features.shared_agents).toBe(false);
    const panel = page.getByRole("region", { name: "Native execution context observations", exact: true });
    await expect(panel.getByText(/Preparation is ready for Pi and Oh My Pi/)).toBeVisible();
    await expect(panel.getByText("No recent execution-context observations.", { exact: true })).toBeVisible();
    await page.getByRole("tab", { name: "Projects & AI apps", exact: true }).click();
    const consumer = page.getByRole("combobox", { name: "Context consumer", exact: true });
    expect(await consumer.locator("option").evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value)))
      .toEqual(["dashboard", "pi", "omp"]);
    await consumer.selectOption("omp");
    await page.getByLabel("Workspace folder", { exact: true }).fill(state.workspace);
    await page.getByRole("button", { name: "Grant review source access", exact: true }).click();
    const grantProof = page.getByRole("dialog");
    await expect(grantProof).toContainText("Oh My Pi");
    await grantProof.getByLabel("Approval password").fill(state.approvalPassword);
    await grantProof.getByRole("button", { name: "Grant source access", exact: true }).click();
    await expect(grantProof).toHaveCount(0);
    for (const choice of ["allow-once", "always-allow"]) {
      const queued = sink(choice, "prepare");
      expect(queued.code).toBe(125);
      expect(queued.request_id).toBeTruthy();
      await page.goto(`/requests/${queued.request_id}`);
      const duration = page.getByRole("group", { name: "How long should Guard allow it?", exact: true });
      const once = duration.getByRole("radio", { name: /^Run once/ });
      const always = duration.getByRole("radio", { name: /^Always allow this version in this project/ });
      await expect(once).toBeEnabled();
      await expect(always).toBeEnabled();
      if (choice === "always-allow") {
        await always.focus();
        await page.keyboard.press("Space");
        await expect(always).toBeChecked();
        await decide(page, state, page.getByRole("button", { name: "Always allow this version in this project", exact: true }),
          queued.request_id!, "Always allow this version in this project");
      } else {
        await once.focus();
        await page.keyboard.press("Space");
        await expect(once).toBeChecked();
        await decide(page, state, page.getByRole("button", { name: "Run once", exact: true }),
          queued.request_id!, "Run once");
      }
      expect((await requestRecord(state, queued.request_id!)).resolution_action).toBe("allow");
      expect(sink(choice, "execute")).toMatchObject({ code: 0, expected_effect: true });
      expect((await status()).execution_observations?.some((event) => event.phase === "completed"
        && event.association_applied && event.native_dispatch_acknowledged && !event.approval_grant
        && !event.send_boundary_atomicity)).toBe(true);
      expect(sink(choice, "replay")).toEqual({ code: 0, effect_unchanged: true, output_not_retained: true });
      expect(sink(choice, "new")).toMatchObject(choice === "always-allow"
        ? { code: 0, expected_effect: true } : { code: 125, expected_effect: false, requires_consent: true });
    }
    await page.goto("/cigar?section=runtime");
    await expect(panel.getByText("Native execution record completed", { exact: true }).first()).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    await stopContextAssistance(page);
    await expect.poll(async () => (await status()).runtime).toBeNull();
    expect((await status()).execution_observations).toEqual([]);
    expect(sink("always-allow", "after-stop")).toMatchObject({ code: 0, expected_effect: true });
    expect(sink("allow-once", "after-stop")).toMatchObject({ code: 125, requires_consent: true });
    await page.reload();
    await expect(enabled).toHaveAttribute("aria-checked", "false");
    await expectNoErrorBoundary(page);
  } finally {
    await daemonApi(state, "/v1/context-assistance/stop", { method: "POST", body: "{}" });
  }
});
