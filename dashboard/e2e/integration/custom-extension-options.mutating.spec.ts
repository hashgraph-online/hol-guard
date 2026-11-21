import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

import { daemonApi, expect, expectNoErrorBoundary, readIntegrationState, test, type IntegrationState } from "./fixtures";

type SeededScript = { script: string; name: string; options: string[] };
type Hook = { permission_decision: string | null; decision: string | null; reason_code: string | null; reason: string };
type LocalCliList = {
  items: { cli_id: string; name: string; kind: string; state: string; commands: { command_id: string; state: string }[] }[];
};

// The first save writes the control authority, which takes longer than the
// default wait.
const SAVE_TIMEOUT_MS = 60_000;
const repoRoot = resolve(import.meta.dirname, "../../..");
// The setting may name a command with arguments, such as `uv run --no-sync python`.
const [python, ...pythonArgs] = (process.env.DASHBOARD_E2E_PYTHON ?? "python3").trim().split(/\s+/);

const seeded = (state: IntegrationState) => state.seeded.custom_cli_options as unknown as SeededScript;

// Sends one Claude Code Bash call through the daemon's hook route, the way a
// hook bridge does, and returns what Guard decided.
function hook(state: IntegrationState, command: string): Hook {
  const output = execFileSync(
    python,
    [...pythonArgs, resolve(repoRoot, "scripts/ci/dashboard_integration_hook.py"), state.guardHome, state.workspace, command],
    { cwd: repoRoot, encoding: "utf8", timeout: 45_000 },
  );
  return JSON.parse(output) as Hook;
}

// A call Guard wants a person to look at is refused with the review reason
// and queued in the Inbox; any other refusal is a block. A saved allow lifts
// the review but keeps its reason code, so the permission decision comes
// first. Claude Code runs a call Guard answers with no permission decision.
function outcome(result: Hook): "allow" | "review" | "deny" {
  if (result.permission_decision === "allow") return "allow";
  if (result.reason_code === "native_command_review_required" || result.permission_decision === "ask") return "review";
  if (result.permission_decision === "deny" || result.decision === "block") return "deny";
  return "allow";
}

// The calls that needed review sit in the Inbox. Clear them so the Inbox
// specs see only their own seeded requests, which all come from Codex.
test.afterAll(async () => {
  const state = await readIntegrationState();
  await daemonApi(state, "/v1/requests/clear", {
    method: "POST",
    body: JSON.stringify({ status: "pending", harness: "claude-code", approval_password: state.approvalPassword }),
  });
});

test("a script's options load as separate commands, and Allow and Block are what the hook enforces", async ({ page, state }) => {
  test.setTimeout(240_000);
  const { script, name, options } = seeded(state);

  // Guard has not been told about the script, so it wants a review before
  // running it. The call also records the script as a detected custom extension.
  const before = hook(state, `${script} 1.0.0 --dry-run`);
  expect(outcome(before), JSON.stringify(before)).toBe("review");

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

  // The daemon holds the choices the page saved.
  const savedStates = async () => {
    const list = await daemonApi<LocalCliList>(state, "/v1/local-clis");
    const item = list.items.find((entry) => entry.cli_id === cliId);
    return Object.fromEntries((item?.commands ?? []).map((command) => [command.command_id, command.state]));
  };
  await expect.poll(async () => (await savedStates())["--dry-run"]).toBe("allow");
  expect((await savedStates())["--skip-billing"]).toBe("block");

  // What was saved is what the hook enforces: the allowed option runs, the
  // blocked one is denied, and an option left on Recommended is still reviewed.
  let allowed = hook(state, `${script} 1.0.0 --dry-run`);
  for (let attempt = 0; attempt < 20 && outcome(allowed) !== "allow"; attempt += 1) {
    await new Promise((done) => setTimeout(done, 2_000));
    allowed = hook(state, `${script} 1.0.0 --dry-run`);
  }
  const listed = (await daemonApi<LocalCliList>(state, "/v1/local-clis")).items.find((entry) => entry.cli_id === cliId);
  expect(outcome(allowed), JSON.stringify({ allowed, kind: listed?.kind, state: listed?.state })).toBe("allow");
  const blocked = hook(state, `${script} 1.0.0 --skip-billing`);
  expect(outcome(blocked), JSON.stringify(blocked)).toBe("deny");
  const unset = hook(state, `${script} 1.0.0 --repo acme/site`);
  expect(outcome(unset), JSON.stringify(unset)).toBe("review");

  // The saved choices survive a reload.
  await page.reload();
  await expectNoErrorBoundary(page);
  await expect(row("--dry-run").getByRole("radio", { name: "Allow", exact: true })).toHaveAttribute("aria-checked", "true");
  await expect(row("--skip-billing").getByRole("radio", { name: "Block", exact: true })).toHaveAttribute("aria-checked", "true");
});
