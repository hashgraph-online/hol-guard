import { expect, test } from "@playwright/test";

import { ExtensionControlApiError } from "../src/extension-controls-api";
import { protectionChangeErrorMessage } from "../src/protection-center/protection-change-error";

/**
 * The flow an operator actually runs first: open a tool they already have, set
 * one of its everyday capabilities to Allow, and save it. It broke in a real
 * install and no test caught it, because the installed coverage only ever
 * blocked a capability on an extension nobody runs. This drives the real
 * daemon, the real wheel and the real authority, with no stubbed responses.
 */

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const origin = requiredEnvironment("GUARD_INSTALLED_ORIGIN");
const session = requiredEnvironment("GUARD_INSTALLED_DASHBOARD_SESSION");
const policyPhase = process.env.GUARD_INSTALLED_POLICY_PHASE ?? "read-only";
const approvalPassword = process.env.GUARD_INSTALLED_APPROVAL_PASSWORD ?? "";
const extensionId = "command.git";
const permissionId = "command.git.permission.worktree";

type Page = import("@playwright/test").Page;

type EffectiveControls = {
  revision: number;
  controls: Array<{ target: { kind: string; target_id: string }; state: string }>;
  projection?: { permissions: Array<{ permission_id: string; effective_state: string; local_state: string }> };
};

async function openPolicy(page: Page) {
  await page.addInitScript(({ daemon, token }) => {
    sessionStorage.setItem("guard-token", token);
    sessionStorage.setItem("guardDaemon", daemon);
  }, { daemon: origin, token: session });
  await page.goto(`/extensions/${extensionId}?tab=policy`);
  expect(page.url()).not.toContain(session);
  await expect(page.getByTestId("protection-module-detail")).toBeVisible({ timeout: 30_000 });
  await expect(page.locator("#extension-policy-heading")).toHaveText("Protection settings");
  return page.locator(`[data-permission-id="${permissionId}"]`);
}

async function applyOneChange(page: Page): Promise<EffectiveControls> {
  expect(approvalPassword.length).toBeGreaterThan(20);
  await page.getByRole("button", { name: "Review 1 change" }).click();
  const dialog = page.getByRole("dialog", { name: "Review and apply 1 protection setting change" });
  // The daemon computes the real outcome before the review opens, and the
  // first one after a start is the slowest.
  await expect(dialog).toBeVisible({ timeout: 60_000 });
  await dialog.getByLabel("Approval password").fill(approvalPassword);
  await dialog.getByRole("button", { name: "Apply 1 reviewed change" }).click();
  const toast = page.getByTestId("extension-policy-applied-toast");
  try {
    // The toast carries the revision the panel saved. Waiting for a response
    // to the save instead would race the workspace's own refresh, which
    // answers 200 with the revision from before the mutation landed.
    await expect(toast).toContainText(/Applied · revision \d+/, { timeout: 60_000 });
  } catch (error) {
    // A failed save renders in the workspace alert. Report the sentence the
    // operator would have read, so a regression names the failure instead of
    // leaving a bare timeout.
    const alert = await page.getByRole("alert").first().innerText().catch(() => "<no alert rendered>");
    throw new Error(`saving the worktree setting failed: ${alert}`, { cause: error });
  }
  const revision = Number(/Applied · revision (\d+)/.exec(await toast.innerText())?.[1]);
  expect(Number.isInteger(revision)).toBe(true);
  const effective = await page.evaluate(async () => {
    const token = sessionStorage.getItem("guard-token") ?? "";
    const response = await fetch("/v1/extension-controls/effective", { headers: { "X-Guard-Dashboard-Session": token } });
    if (!response.ok) throw new Error(`effective controls answered ${response.status}`);
    return await response.json() as EffectiveControls;
  });
  // What the operator was told was saved has to be what the daemon now serves.
  expect(effective.revision).toBe(revision);
  return effective;
}

test("installed dashboard saves Allow on an everyday capability of an active tool", async ({ page }, testInfo) => {
  test.skip(policyPhase !== "apply", "the save runs before the deliberate daemon restart");
  test.setTimeout(180_000);
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));

  const row = await openPolicy(page);
  await expect(row).toBeVisible();
  await expect(row.getByRole("heading", { name: "Git worktree" })).toBeVisible();
  const allow = row.getByRole("radio", { name: "Allow" });
  await expect(allow).toBeEnabled();
  await allow.click();
  await expect(page.getByText("1 unsaved setting change.")).toBeVisible();

  const effective = await applyOneChange(page);
  expect(effective.revision).toBeGreaterThan(0);
  expect(effective.controls).toContainEqual({ target: { kind: "permission", target_id: permissionId }, state: "enabled" });
  expect(effective.projection?.permissions.find((permission) => permission.permission_id === permissionId)?.local_state)
    .toBe("enabled");
  await expect(page.getByRole("alert")).toHaveCount(0);

  const savedRow = await openPolicy(page);
  await expect(savedRow.getByRole("radio", { name: "Allow" })).toHaveAttribute("aria-checked", "true");
  await page.screenshot({ path: testInfo.outputPath("installed-git-worktree-allowed.png"), fullPage: true });
  expect(runtimeErrors).toEqual([]);
});

test("the saved Allow survives a daemon restart and can be returned to Recommended", async ({ page }) => {
  test.skip(policyPhase !== "verify", "persistence runs only after the workflow restarts the real daemon");
  test.setTimeout(180_000);
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));

  const row = await openPolicy(page);
  await expect(row.getByRole("radio", { name: "Allow" })).toHaveAttribute("aria-checked", "true");

  await row.getByRole("radio", { name: "Recommended" }).click();
  const effective = await applyOneChange(page);
  expect(effective.controls.some((control) =>
    control.target.kind === "permission" && control.target.target_id === permissionId)).toBe(false);
  const restored = await openPolicy(page);
  await expect(restored.getByRole("radio", { name: "Recommended" })).toHaveAttribute("aria-checked", "true");
  expect(runtimeErrors).toEqual([]);
});

test("a rejected save from the real daemon reads as a sentence, never a protocol code", async ({ page }) => {
  test.skip(policyPhase === "read-only", "runs once, alongside the save it protects");
  test.setTimeout(120_000);
  await openPolicy(page);
  // Ask the real daemon to apply against a revision that cannot exist. Nothing
  // is stubbed: this is the daemon's own rejection envelope.
  const rejection = await page.evaluate(async () => {
    const token = sessionStorage.getItem("guard-token") ?? "";
    const headers = { "Content-Type": "application/json", "X-Guard-Dashboard-Session": token };
    // Take the authority the daemon is actually serving, so the only thing
    // wrong with the request below is the revision it claims to amend. A
    // hand-written body would be refused for its shape instead, and that
    // rejection would prove nothing about a stale draft.
    const effective = await (await fetch("/v1/extension-controls/effective", { headers })).json() as {
      revision: number;
      catalog_digest: string;
      layers: unknown[];
    };
    const response = await fetch("/v1/extension-controls/preview", {
      method: "POST",
      headers,
      body: JSON.stringify({
        previous_revision: effective.revision + 1,
        catalog_digest: effective.catalog_digest,
        layers: effective.layers,
        actor_id: "installed-e2e",
        idempotency_key: "installed-e2e-stale-revision",
        nonce: "installed-e2e-stale-revision",
      }),
    });
    return { status: response.status, body: await response.json() as Record<string, unknown> };
  });

  // A bad session header or an unknown route would also answer >= 400, and
  // this case is only worth anything if the daemon rejected the stale revision
  // itself. Pin the envelope to the conflict codes that mutation can answer.
  expect(rejection.status).toBe(409);
  const code = rejection.body.error;
  expect(["authority_conflict", "catalog_conflict", "revision_conflict"]).toContain(code);
  const rendered = protectionChangeErrorMessage(
    new ExtensionControlApiError(
      code as string,
      rejection.status,
      code as string,
      typeof rejection.body.recovery === "object" && rejection.body.recovery !== null
        ? (rejection.body.recovery as { action?: string }).action
        : undefined,
      typeof rejection.body.cause === "string" ? rejection.body.cause : undefined,
    ),
  );
  expect(rendered).not.toContain(code as string);
  expect(rendered).not.toMatch(/\b[a-z]+(_[a-z]+){2,}\b/);
  expect(rendered.endsWith(".")).toBe(true);
});
