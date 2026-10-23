import type { Page } from "@playwright/test";
import { daemonApi, expect, expectNoErrorBoundary, test, type IntegrationState } from "./fixtures";
import { commandsUrl } from "./evidence-helpers";

type Health = {
  status: "healthy" | "degraded";
  persistence_errors: number;
  last_error_class: string | null;
};
type HealthFacts = { error_class: string; active_errors_after_seed: number };

const ANALYTICS = "**/v1/command-activity/analytics?*";
const REPAIR = "**/v1/protection/repair";

function healthFacts(state: IntegrationState): HealthFacts {
  return state.seeded.command_health as HealthFacts;
}

function notice(page: Page) {
  return page.getByRole("region", { name: "Command activity summary" }).getByRole("status").filter({ hasText: "Counts may be incomplete." });
}

// Serves the daemon's real analytics with health forced back to degraded, so a
// spec can see the notice after the daemon has already repaired the store.
async function forceDegradedAnalytics(page: Page, errorClass: string): Promise<void> {
  await page.route(ANALYTICS, async (route) => {
    const response = await route.fetch();
    const payload = (await response.json()) as { health: Health };
    payload.health = { ...payload.health, status: "degraded", last_error_class: errorClass };
    await route.fulfill({ response, json: payload });
  });
}

test.describe("evidence: command evidence health", () => {
  test("a past evidence write failure repairs itself without the user doing anything", async ({ page, state }) => {
    const facts = healthFacts(state);
    // The seed really left the store degraded.
    expect(facts.active_errors_after_seed).toBeGreaterThan(0);

    await page.goto(commandsUrl());
    await expectNoErrorBoundary(page);
    await expect(page.getByRole("region", { name: "Command activity summary" }).getByText("Commands checked")).toBeVisible();
    await expect(notice(page)).toHaveCount(0);

    // The failure stays on record; only the stale degraded flag is gone.
    const { health } = await daemonApi<{ health: Health }>(state, "/v1/command-activity/analytics?days=30");
    expect(health.status).toBe("healthy");
    expect(health.persistence_errors).toBeGreaterThan(0);
    expect(health.last_error_class).toBe(facts.error_class);
  });

  test("a notice Guard cannot clear names the cause and points to Protect repair", async ({ page, state }) => {
    await forceDegradedAnalytics(page, healthFacts(state).error_class);
    let repairRequests = 0;
    await page.route(REPAIR, async (route) => {
      repairRequests += 1;
      expect(route.request().postDataJSON()).toEqual({ check_id: "decision_stream" });
      await route.fulfill({
        status: 409,
        json: {
          repaired: false,
          repair_scope: "local_integrity",
          check_ids: [],
          failed_check_ids: ["decision_stream"],
          check_reasons: { decision_stream: "decision_stream_degraded" },
          message: "Guard could not verify the command evidence store.",
        },
      });
    });

    await page.goto(commandsUrl());
    await expect(notice(page)).toContainText("Last recorded problem: Guard could not save some command checks.");
    await notice(page).getByRole("button", { name: "Repair evidence" }).click();

    await expect(notice(page)).toContainText("Guard could not verify the command evidence store.");
    const protect = notice(page).getByRole("link", { name: "Open Protect repair" });
    await expect(protect).toHaveAttribute("href", /\/protection\/repair/);
    expect(repairRequests).toBe(1);
  });
});
