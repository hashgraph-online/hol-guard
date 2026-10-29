import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

import { daemonApi, expect, expectNoErrorBoundary, test, type IntegrationState } from "./fixtures";

type SeededScript = { script: string; name: string; options: string[] };
type Hook = { permission_decision: string | null; decision: string | null; reason_code: string | null };
type LocalCliList = { items: { cli_id: string; name: string }[] };

// The first save writes the control authority, which takes longer than the
// default wait.
const SAVE_TIMEOUT_MS = 60_000;
const repoRoot = resolve(import.meta.dirname, "../../..");
const python = process.env.DASHBOARD_E2E_PYTHON ?? "python3";

const seeded = (state: IntegrationState) => state.seeded.custom_cli_options as unknown as SeededScript;

// Sends one Claude Code Bash call through the daemon's hook route, the way a
// hook bridge does, and returns what Guard decided.
function hook(state: IntegrationState, command: string): Hook {
  const output = execFileSync(
    python,
    [resolve(repoRoot, "scripts/ci/dashboard_integration_hook.py"), state.guardHome, state.workspace, command],
    { cwd: repoRoot, encoding: "utf8", timeout: 45_000 },
  );
  return JSON.parse(output) as Hook;
}

// Claude Code runs a call Guard answers with no permission decision, so that
// counts as allowed unless the hook blocked it outright.
function outcome(result: Hook): string {
  if (result.permission_decision) return result.permission_decision;
  return result.decision === "block" ? "deny" : "allow";
}

test("a script's options load as separate commands, and Allow and Block are what the hook enforces", async ({ page, state }) => {
  test.setTimeout(240_000);
  const { script, name, options } = seeded(state);

  // Guard has not been told about the script, so it asks before running it.
  // The call also records the script as a detected custom extension.
  const before = hook(state, `${script} 1.0.0 --dry-run`);
  expect(outcome(before), JSON.stringify(before)).toBe("ask");

  let cliId = "";
  await expect
    .poll(async () => {
      const list = await daemonApi<LocalCliList>(state, "/v1/local-clis");
      cliId = list.items.find((item) => item.name === name)?.cli_id ?? "";
      return cliId;
    })
    .not.toBe("");

  await page.goto(`/extensions/local-cli/${encodeURIComponent(cliId)}`);
  await expectNoErrorBoundary(page);
  await expect(page.getByRole("heading", { name, level: 1 })).toBeVisible();

  // Its --help is rejected, so every variation comes from the script's source.
  await page.getByRole("button", { name: "Load commands" }).click();
  const row = (id: string) => page.locator(`article[data-command-id="${id}"]`);
  for (const option of options) {
    await expect(row(option), `${option} is listed`).toBeVisible({ timeout: SAVE_TIMEOUT_MS });
  }

  await row("--dry-run").getByRole("radio", { name: "Allow", exact: true }).click();
  await row("--skip-billing").getByRole("radio", { name: "Block", exact: true }).click();
  await expect(row("--dry-run").getByRole("radio", { name: "Allow", exact: true })).toHaveAttribute("aria-checked", "true");
  await expect(row("--skip-billing").getByRole("radio", { name: "Block", exact: true })).toHaveAttribute("aria-checked", "true");

  await page.getByRole("button", { name: "Add custom extension" }).click();
  const dialog = page.locator('[role="dialog"][aria-labelledby="custom-extension-review-title"]');
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("region", { name: "Permission changes" })).toContainText("--dry-run");
  await expect(dialog.getByRole("region", { name: "Permission changes" })).toContainText("--skip-billing");
  await dialog.getByLabel("Approval password").fill(state.approvalPassword);
  await dialog.getByRole("button", { name: "Confirm" }).click();
  await expect(dialog).toBeHidden({ timeout: SAVE_TIMEOUT_MS });

  // What was saved is what the hook enforces: the allowed option runs, the
  // blocked one is denied, and an option left on Recommended still asks.
  await expect.poll(() => outcome(hook(state, `${script} 1.0.0 --dry-run`)), { timeout: SAVE_TIMEOUT_MS }).toBe("allow");
  const blocked = hook(state, `${script} 1.0.0 --skip-billing`);
  expect(outcome(blocked), JSON.stringify(blocked)).toBe("deny");
  const unset = hook(state, `${script} 1.0.0 --repo acme/site`);
  expect(outcome(unset), JSON.stringify(unset)).toBe("ask");

  // The saved choices survive a reload.
  await page.reload();
  await expectNoErrorBoundary(page);
  await expect(row("--dry-run").getByRole("radio", { name: "Allow", exact: true })).toHaveAttribute("aria-checked", "true");
  await expect(row("--skip-billing").getByRole("radio", { name: "Block", exact: true })).toHaveAttribute("aria-checked", "true");
});
