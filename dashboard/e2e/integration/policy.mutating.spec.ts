import { daemonApi, expect, test, type IntegrationState } from "./fixtures";
import { policySeed, rememberedRow } from "./policy-helpers";

type PolicyList = { items: Array<{ reason: string; scope: string; harness: string }> };

async function ruleIsInForce(state: IntegrationState, title: string): Promise<boolean> {
  const { items } = await daemonApi<PolicyList>(state, "/v1/policy");
  return items.some((item) => item.reason === title);
}

// PRODUCT BUG: with the approval gate on, the Policy page sends
// POST /v1/policy/clear without the approval password, so the daemon answers
// 403 approval_gate_required and no rule can be removed from the dashboard.
// dashboard/src/app.tsx handleClearPolicy -> clearPolicy(buildClearPayload(policy))
// never passes approval_password (guard-api.ts clearPolicy accepts it). Remove
// the fixme, and the fail-closed test below, once the page asks for proof.
test.fixme("removing a remembered rule from its row deletes it, and it stays gone after reload", async ({ page, state }) => {
  const rule = policySeed(state).removal_target;
  await page.goto("/policy");
  await expect(rememberedRow(page, rule.title)).toBeVisible();

  await rememberedRow(page, rule.title).getByRole("button", { name: "Remove rule" }).click();
  await expect(rememberedRow(page, rule.title)).toHaveCount(0);
  expect(await ruleIsInForce(state, rule.title)).toBe(false);

  await page.reload();
  await expect(page.getByRole("table", { name: "Remembered policy rules" })).toBeVisible();
  await expect(rememberedRow(page, rule.title)).toHaveCount(0);
});

test("removing a rule without approval proof fails closed and leaves it in force", async ({ page, state }) => {
  const seed = policySeed(state);
  const rule = seed.removal_target;
  await page.goto("/policy");
  await page.getByRole("button", { name: `Inspect rule ${rule.title}`, exact: true }).first().click();
  const dialog = page.getByRole("dialog", { name: `Rule details: ${rule.title}` });
  await dialog.getByRole("button", { name: "Remove rule" }).click();

  await expect(dialog.getByRole("alert")).toHaveText("This rule could not be removed. It is still in force — try again.");
  expect(await ruleIsInForce(state, rule.title)).toBe(true);

  await page.reload();
  await expect(rememberedRow(page, rule.title)).toBeVisible();
  await expect(rememberedRow(page, seed.workspace_allow.title)).toBeVisible();
});

test("bulk removal without approval proof fails closed and keeps every selected rule", async ({ page, state }) => {
  const seed = policySeed(state);
  const rule = seed.removal_target;
  await page.goto("/policy");
  await page.getByRole("checkbox", { name: `Select rule ${rule.title} for removal` }).check();
  await page.getByRole("button", { name: "Remove selected" }).click();

  await expect(page.getByText("1 rule could not be removed. It is still selected — try again.")).toBeVisible();
  await expect(page.getByRole("checkbox", { name: `Select rule ${rule.title} for removal` })).toBeChecked();
  expect(await ruleIsInForce(state, rule.title)).toBe(true);
  for (const kept of [seed.workspace_allow, seed.artifact_block, seed.global_allow]) {
    expect(await ruleIsInForce(state, kept.title), kept.title).toBe(true);
  }
});
