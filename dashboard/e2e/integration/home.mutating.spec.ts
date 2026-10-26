import { daemonApi, expect, test } from "./fixtures";
import { appName, heroRegion } from "./home-helpers";

type PolicyList = { items: Array<{ harness: string; action: string; scope: string }> };

// claude-code is a seeded active app that no other area writes rules for.
const HARNESS = "claude-code";

test.describe("Home remembered decisions against the live daemon", () => {
  test("Reset remembered decisions clears one app's rules after the approval password", async ({ page, state }) => {
    await daemonApi(state, "/v1/policy/decisions", {
      method: "POST",
      body: JSON.stringify({
        harness: HARNESS,
        scope: "harness",
        action: "allow",
        reason: "Home e2e remembered decision",
        approval_password: state.approvalPassword,
      }),
    });
    const before = await daemonApi<PolicyList>(state, "/v1/policy");
    const mine = before.items.filter((rule) => rule.harness === HARNESS);
    expect(mine.length).toBeGreaterThan(0);
    const others = before.items.length - mine.length;

    await page.goto("/");
    await expect(heroRegion(page).getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.getByText("Reset remembered decisions", { exact: true })).toBeVisible();
    // The button is labelled with the app id, not its display name.
    await page.getByRole("button", { name: `Clear ${HARNESS}`, exact: true }).click();

    const dialog = page.getByRole("dialog", { name: "Confirm clear decisions" });
    await expect(dialog).toContainText(HARNESS);
    const confirm = dialog.getByRole("button", { name: "Clear decisions", exact: true });
    await expect(confirm).toBeDisabled();

    // Backing out leaves the rule in place.
    await dialog.getByRole("button", { name: "Keep decisions", exact: true }).click();
    await expect(dialog).toHaveCount(0);
    expect((await daemonApi<PolicyList>(state, "/v1/policy")).items.filter((rule) => rule.harness === HARNESS)).toHaveLength(
      mine.length,
    );

    await page.getByRole("button", { name: `Clear ${HARNESS}`, exact: true }).click();
    await dialog.getByRole("textbox", { name: "Approval password" }).fill(state.approvalPassword);
    await expect(confirm).toBeEnabled();
    await confirm.click();
    await expect(page.getByText(`Cleared for ${appName(HARNESS)}`, { exact: true })).toBeVisible();
    await expect(dialog).toHaveCount(0);

    // The daemon dropped this app's rules and nobody else's.
    const after = await daemonApi<PolicyList>(state, "/v1/policy");
    expect(after.items.filter((rule) => rule.harness === HARNESS)).toHaveLength(0);
    expect(after.items).toHaveLength(others);

    // The clear survives a reload. Home lists every active app while any
    // remembered decision exists, so the button only goes away once no app
    // has rules left; other areas' seeded rules keep the section in place.
    await page.reload();
    await expect(heroRegion(page).getByRole("heading", { level: 1 })).toBeVisible();
    expect((await daemonApi<PolicyList>(state, "/v1/policy")).items.filter((rule) => rule.harness === HARNESS)).toHaveLength(0);
    const resetSection = page.getByText("Reset remembered decisions", { exact: true });
    if (others === 0) {
      await expect(resetSection).toHaveCount(0);
    } else {
      await expect(resetSection).toBeVisible();
    }
  });

  test("a wrong approval password is refused and the rules stay", async ({ page, state }) => {
    await daemonApi(state, "/v1/policy/decisions", {
      method: "POST",
      body: JSON.stringify({
        harness: HARNESS,
        scope: "harness",
        action: "block",
        reason: "Home e2e remembered decision",
        approval_password: state.approvalPassword,
      }),
    });
    await page.goto("/");
    await page.getByRole("button", { name: `Clear ${HARNESS}`, exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Confirm clear decisions" });
    await dialog.getByRole("textbox", { name: "Approval password" }).fill("not-the-approval-password");
    await dialog.getByRole("button", { name: "Clear decisions", exact: true }).click();
    // Stays open with an error, and nothing was removed.
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText(/approval password is invalid/i)).toBeVisible();
    const kept = await daemonApi<PolicyList>(state, "/v1/policy");
    expect(kept.items.filter((rule) => rule.harness === HARNESS).length).toBeGreaterThan(0);

    // Leave no residue for later specs.
    await dialog.getByRole("textbox", { name: "Approval password" }).fill(state.approvalPassword);
    await dialog.getByRole("button", { name: "Clear decisions", exact: true }).click();
    await expect(dialog).toHaveCount(0);
    const after = await daemonApi<PolicyList>(state, "/v1/policy");
    expect(after.items.filter((rule) => rule.harness === HARNESS)).toHaveLength(0);
  });
});
