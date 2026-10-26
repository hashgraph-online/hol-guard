import type { Page } from "@playwright/test";

import { expect, expectNoErrorBoundary, test } from "./fixtures";
import { SETTINGS_SECTIONS, type SettingsSectionKey, sectionNav, settingsSeed } from "./settings-helpers";

// One control or heading that only its own section renders.
const SECTION_PROOF: Record<SettingsSectionKey, (page: Page) => ReturnType<Page["getByRole"]>> = {
  protection: (page) => page.getByRole("heading", { name: "Timing and features", level: 3 }),
  apps: (page) => page.getByRole("searchbox", { name: "Find an app" }),
  approval: (page) => page.getByRole("region", { name: "Local approval setup" }),
  notifications: (page) => page.getByRole("button", { name: "Set up alerts" }),
  rules: (page) => page.getByRole("region", { name: "Advanced rules" }),
  maintenance: (page) => page.getByRole("heading", { name: "Keep this machine tidy", level: 3 }),
};

test.describe("Settings against the live daemon", () => {
  test("every section opens from the sidebar and keeps the Save settings bar", async ({ page }) => {
    await page.goto("/settings");
    await expect(page.getByRole("heading", { name: "Protection", level: 1 })).toBeVisible();
    for (const section of SETTINGS_SECTIONS) {
      await sectionNav(page).getByRole("button", { name: section.nav }).click();
      await expect(SECTION_PROOF[section.key](page), section.key).toBeVisible();
      await expect.poll(() => new URL(page.url()).searchParams.get("section"), section.key).toBe(section.key);
      await expect(page.getByRole("region", { name: "Save settings" }).getByRole("button", { name: "Save settings" })).toBeVisible();
      await expectNoErrorBoundary(page);
    }
  });

  test("every section opens from its deep link", async ({ page }) => {
    for (const section of SETTINGS_SECTIONS) {
      await page.goto(`/settings?section=${section.key}`);
      await expect(SECTION_PROOF[section.key](page), section.key).toBeVisible();
      await expectNoErrorBoundary(page);
    }
    expect(page.url()).not.toContain("?guard-token");
  });

  test("Protection shows the daemon's real defaults", async ({ page, state }) => {
    const seed = settingsSeed(state);
    await page.goto("/settings?section=protection");
    await expect(page.getByRole("radio", { name: "Protected" }).first()).toBeChecked();
    await expect(page.getByRole("radio", { name: "Extra careful" })).not.toBeChecked();
    await expect(page.getByRole("radio", { name: "Watch" }).first()).not.toBeChecked();
    await expect(page.getByRole("combobox", { name: "Presentation mode" })).toHaveValue(/everyday/i);
    await expect(page.getByRole("spinbutton", { name: "How long to wait for your answer" })).toHaveValue(
      String(seed.approvalWaitTimeoutSeconds),
    );
    for (const name of ["Telemetry", "Cloud sync", "Billing features"]) {
      await expect(page.getByRole("switch", { name }), name).not.toBeChecked();
    }
    const review = page.getByRole("region", { name: "Cloud Review" });
    await expect(review.getByRole("button", { name: "Connect Guard Cloud" })).toBeVisible();
    await expect(page.getByRole("combobox", { name: "Cloud receipt privacy" })).toBeVisible();
  });

  test("Apps lists each protected app and filters by name", async ({ page }) => {
    await page.goto("/settings?section=apps");
    await expect(page.getByRole("heading", { name: "Protection by app", level: 3 })).toBeVisible();
    const codex = page.getByRole("group", { name: "Protection for Codex" });
    const opencode = page.getByRole("group", { name: "Protection for OpenCode" });
    await expect(codex.getByRole("radio", { name: "Protected" })).toBeChecked();
    await expect(codex.getByRole("radio", { name: "Watch" })).not.toBeChecked();
    await expect(opencode).toBeVisible();

    await page.getByRole("searchbox", { name: "Find an app" }).fill("codex");
    await expect(codex).toBeVisible();
    await expect(opencode).toHaveCount(0);
  });

  test("Approval gate shows the gate the integration home turned on", async ({ page }) => {
    await page.goto("/settings?section=approval");
    const setup = page.getByRole("region", { name: "Local approval setup" });
    await expect(setup.getByRole("checkbox", { name: "Ask for proof on allow decisions" })).toBeChecked();
    await expect(setup.getByRole("checkbox", { name: "Also ask before block decisions" })).not.toBeChecked();
    await expect(setup.getByRole("button", { name: "Change password" })).toBeVisible();
    await expect(setup.getByRole("combobox", { name: "Cooldown after approval" })).toHaveValue("0");
    await expect(setup.getByRole("button", { name: "Set up authenticator" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "When Guard blocks a request", level: 3 })).toBeVisible();
    await expect(page.getByRole("radio", { name: /^Find a safe alternative/ })).toBeChecked();
    await expect(page.getByRole("radio", { name: /^Ask me for approval/ })).not.toBeChecked();
  });

  test("Notifications offers desktop alert setup", async ({ page }) => {
    await page.goto("/settings?section=notifications");
    await expect(page.getByRole("button", { name: "Set up alerts" })).toBeEnabled();
    await expectNoErrorBoundary(page);
  });

  test("Protection rules keeps risky-action choices locked until Custom fine-tuning", async ({ page }) => {
    await page.goto("/settings?section=rules");
    await expect(page.getByRole("region", { name: "Advanced rules" }).getByRole("button", { name: "Use Custom fine-tuning" })).toBeEnabled();
    await expect(page.getByRole("heading", { name: "Risky action types", level: 3 })).toBeVisible();
    const choices = page.getByRole("combobox", { name: "Guard should" });
    expect(await choices.count()).toBeGreaterThan(5);
    for (const choice of await choices.all()) {
      await expect(choice).toBeDisabled();
    }
  });

  test("Data & repair lists every maintenance action without running one", async ({ page }) => {
    await page.goto("/settings?section=maintenance");
    for (const name of [
      "Clear approvals",
      "Clear review queue",
      "Clear evidence",
      "Export settings",
      "Import settings",
      "Export diagnostics",
      "Reset settings",
      "Repair Guard",
    ]) {
      await expect(page.getByRole("button", { name, exact: true }), name).toBeVisible();
    }
  });

  test("Export settings downloads the daemon's live settings", async ({ page, state }) => {
    const seed = settingsSeed(state);
    await page.goto("/settings?section=maintenance");
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export settings", exact: true }).click();
    const file = await download;
    expect(file.suggestedFilename()).toMatch(/^guard-settings-.*\.json$/);
    const stream = await file.createReadStream();
    const chunks: Buffer[] = [];
    for await (const chunk of stream) chunks.push(chunk as Buffer);
    const exported = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
      settings: { approval_wait_timeout_seconds: number };
    };
    expect(exported.settings.approval_wait_timeout_seconds).toBe(seed.approvalWaitTimeoutSeconds);
  });

  test("searching settings finds matches and reports when nothing matches", async ({ page }) => {
    await page.goto("/settings");
    const search = page.getByRole("searchbox", { name: "Search settings" });
    await search.fill("zzz-no-such-setting");
    await expect(page.getByText("No settings match your search.")).toBeVisible();
    await search.fill("package");
    await expect(page.getByText("Matching fine-tuning rules")).toBeVisible();
    await expect(page.getByText("No settings match your search.")).toHaveCount(0);
  });
});
