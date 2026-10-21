import { daemonApi, expect, expectNoErrorBoundary, test } from "./fixtures";

type Runtime = {
  managed_installs: { harness: string; active: boolean }[];
  protection_health: { checks: { check_id: string; status: string; reason_code?: string }[] };
};

type HomeSeed = { activeApps: string[]; inactiveApps: string[] };

const APP_LABELS: Record<string, string> = { "claude-code": "Claude Code", cursor: "Cursor", copilot: "Copilot" };

// The home seed connects two apps and leaves one connected app with inactive
// hooks, so Protect shows the degraded posture a real machine shows when one
// app's hooks stop working. Read that world back from the daemon first.
async function readSeededRuntime(state: Parameters<typeof daemonApi>[0]): Promise<{ runtime: Runtime; home: HomeSeed }> {
  const home = state.seeded.home as unknown as HomeSeed;
  const runtime = await daemonApi<Runtime>(state, "/v1/runtime");
  for (const harness of home.inactiveApps) {
    expect(runtime.managed_installs).toContainEqual(expect.objectContaining({ harness, active: false }));
  }
  expect(runtime.protection_health.checks).toContainEqual(
    expect.objectContaining({ check_id: "harness_hooks", status: "fail", reason_code: "one_or_more_hooks_inactive" }),
  );
  return { runtime, home };
}

test("Protect shows degraded posture, per-app protection and every app Guard can watch", async ({ page, state }) => {
  const { home } = await readSeededRuntime(state);
  await page.goto("/protect");
  await expectNoErrorBoundary(page);

  const status = page.getByRole("region", { name: "Protection status" });
  await expect(status.getByText("Degraded", { exact: true })).toBeVisible();
  await expect(status.getByRole("heading", { name: "App protection is degraded", level: 2 })).toBeVisible();

  // Each stat is a label with its value in the paragraph that follows it.
  const main = page.getByRole("main");
  const statValue = (label: string) => main.getByText(label, { exact: true }).locator("xpath=following-sibling::p[1]");
  await expect(statValue("Needs review")).toHaveText(/^\d+$/);
  await expect(statValue("History")).toHaveText(/^\d+$/);
  await expect(statValue("Watched apps")).toHaveText(/^[1-9]\d*$/);
  await expect(statValue("Runtime")).toHaveText("active");

  await expect(main.getByText("Protection by app", { exact: true })).toBeVisible();
  for (const harness of home.activeApps) {
    await expect(main.getByText(APP_LABELS[harness], { exact: true }).first()).toBeVisible();
  }

  await expect(main.getByText("App coverage", { exact: true })).toBeVisible();
  for (const app of ["Codex", "Claude Code", "Cursor"]) {
    await expect(main.getByRole("button", { name: new RegExp(`^${app}\\b`) })).toBeVisible();
  }
});

test("Protect explains what is failing and gates repair behind the approval password", async ({ page, state }) => {
  const { home } = await readSeededRuntime(state);
  await page.goto("/protect");
  const recovery = page.locator("#protection-recovery");
  // Where containment is unsupported (Linux), Guard repairs only the layers it
  // can and says so in the heading and the repair button.
  await expect(recovery.getByRole("heading", { name: /^(Restore local|Repair supported) protection$/ })).toBeVisible();
  await expect(recovery.getByRole("button", { name: /^Repair (supported )?protection$/ })).toBeEnabled();
  // Each connected app whose hooks are inactive gets its own repair entry.
  for (const harness of home.inactiveApps) {
    await expect(recovery.getByRole("button", { name: `Open ${APP_LABELS[harness]} repair` })).toBeEnabled();
  }
  await expect(recovery.getByText("Guard Cloud policy proof", { exact: true })).toBeVisible();
  await expect(recovery.getByRole("button", { name: "Connect Guard Cloud" })).toBeEnabled();

  // Repair details stay collapsed until asked for, then list each failing check.
  const details = recovery.getByRole("button", { name: "View repair details" });
  await expect(details).toHaveAttribute("aria-expanded", "false");
  await details.click();
  await expect(details).toHaveAttribute("aria-expanded", "true");
  const failing = recovery.getByRole("listitem").filter({ hasText: "App hooks" });
  await expect(failing).toContainText("Failed");
  await expect(failing).toContainText("One or more managed app hooks are inactive.");
  await details.click();
  await expect(details).toHaveAttribute("aria-expanded", "false");

  // Repair asks for local approval proof first. Open and cancel it, since a
  // repair would rewrite hooks and restart the daemon under test.
  await recovery.getByRole("button", { name: "Repair Guard" }).click();
  const dialog = page.getByRole("dialog", { name: "Repair Guard" });
  await expect(dialog.getByText("Enter local approval proof before Guard repairs")).toBeVisible();
  await expect(dialog.getByLabel("Approval password")).toBeEmpty();
  await expect(dialog.getByRole("button", { name: "Repair Guard" })).toBeDisabled();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toBeHidden();
});

test("Protect opens an unconnected app's page from its coverage row", async ({ page, state }) => {
  const { runtime } = await readSeededRuntime(state);
  // Codex is observed through seeded history but never connected.
  expect(runtime.managed_installs.map((install) => install.harness)).not.toContain("codex");
  await page.goto("/protect");
  await page.getByRole("main").getByRole("button", { name: /^Codex\b/ }).click();
  await expect.poll(() => new URL(page.url()).pathname).toBe("/apps/codex");
  await expectNoErrorBoundary(page);
  await expect(page.getByText("Codex is observed")).toBeVisible();
  await expect(page.getByText("Guard has seen activity but install is not active.")).toBeVisible();
  await expect(page.getByRole("tab", { name: "Overview" })).toBeVisible();
});

test("the repair page tells a blocked user their trusted settings are intact", async ({ page }) => {
  await page.goto("/protection/repair");
  await expectNoErrorBoundary(page);
  await expect(page.getByText("Trusted settings are protected")).toBeVisible();
  await page.getByRole("button", { name: "Back to Home" }).click();
  await expect(page).toHaveURL(/\/(?:[?#]|$)/);
});
