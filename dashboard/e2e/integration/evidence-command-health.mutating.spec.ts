import { expect, test } from "./fixtures";
import { commandsUrl } from "./evidence-helpers";

const ANALYTICS = "**/v1/command-activity/analytics?*";

test.describe("evidence: command evidence repair", () => {
  test("Repair evidence runs Guard's repair and the notice clears", async ({ page }) => {
    // Show the notice until the repair has run, then let the daemon's real
    // analytics through.
    let repaired = false;
    await page.route(ANALYTICS, async (route) => {
      const response = await route.fetch();
      if (repaired) {
        await route.fulfill({ response });
        return;
      }
      const payload = (await response.json()) as { health: Record<string, unknown> };
      payload.health = { ...payload.health, status: "degraded", last_error_class: "post_record_failed" };
      await route.fulfill({ response, json: payload });
    });

    await page.goto(commandsUrl());
    const summary = page.getByRole("region", { name: "Command activity summary" });
    const notice = summary.getByRole("status").filter({ hasText: "Counts may be incomplete." });
    await expect(notice).toContainText("Guard could not save some command results.");

    const repair = page.waitForResponse((response) => new URL(response.url()).pathname === "/v1/protection/repair");
    repaired = true;
    await notice.getByRole("button", { name: "Repair evidence" }).click();
    const response = await repair;
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({ repaired: true, check_ids: ["decision_stream"] });

    await expect(notice).toHaveCount(0);
    await expect(summary.getByText("Commands checked")).toBeVisible();
  });
});
