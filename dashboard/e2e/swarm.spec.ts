import { expect, test } from "@playwright/test";
import { makeAgent, swarmFixture, swarmUrl } from "./swarm-fixture";

test("project map, inspector, list and CIGAR present actual capabilities", async ({ page }, info) => {
  await page.setViewportSize({ width: 1520, height: 1050 });
  const errors: string[] = []; page.on("pageerror", (error) => errors.push(error.message));
  const state = await swarmFixture(page);
  await page.goto(swarmUrl);
  await expect(page.getByRole("heading", { name: "Swarm." })).toBeVisible();
  await expect(page.locator(".swarm-node")).toHaveCount(4);
  await page.getByRole("button", { name: /^Codex: Build the Swarm/ }).click();
  await expect(page.getByRole("complementary", { name: "Agent details" })).toBeVisible();
  await page.getByRole("tab", { name: "Context" }).click();
  await expect(page.getByText("3 completed context calls reported by this CLI.")).toBeVisible();
  await expect(page.getByText(/does not confirm this agent has access/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Stop agent", exact: true })).toBeEnabled();
  await page.getByRole("tab", { name: "Activity", exact: true }).click();
  await page.screenshot({ path: info.outputPath("swarm-desktop.png"), fullPage: true });
  await page.getByRole("button", { name: /^Gemini CLI:/ }).click();
  await expect(page.getByText(/Continue in your Gemini CLI window/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Stop agent", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Close agent details" }).click();
  await page.getByRole("button", { name: "List view" }).click();
  await expect(page.locator(".swarm-stage--list")).toBeVisible();
  await page.getByRole("navigation", { name: "Swarm projects" }).getByRole("button", { name: /docs-site/ }).click();
  await expect(page.locator(".swarm-node")).toHaveCount(2);
  await page.getByRole("textbox", { name: "Search agents and projects" }).fill("published API");
  await expect(page.locator(".swarm-node")).toHaveCount(1);
  expect(state.calls.filter((c) => /workspace-grant|authorize|activate/.test(c.path))).toEqual([]);
  expect(errors).toEqual([]);
});

test("launch, queue instructions and stop use explicit owned-run actions", async ({ page }) => {
  const state = await swarmFixture(page);
  await page.goto(swarmUrl);
  await page.getByRole("button", { name: "New agent", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Start a new agent" });
  await dialog.getByLabel("Project directory").fill("/Projects/guard-dashboard");
  await expect(dialog.getByText(/2 agents are already working here/)).toBeVisible();
  await dialog.getByLabel("What should it do?").fill("Review $(do-not-execute) as literal task text");
  await dialog.getByRole("button", { name: "Start agent", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.locator(".swarm-inspector-task")).toHaveText("Review $(do-not-execute) as literal task text");
  await page.getByLabel("Next instruction").fill("Focus next on the retry behavior");
  await page.getByRole("button", { name: "Send instruction", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "Instruction accepted" })).toBeVisible();
  await page.getByRole("button", { name: "Stop agent", exact: true }).click();
  await expect(page.getByText(/Changes already made to files will remain/)).toBeVisible();
  await page.getByRole("button", { name: "Stop this agent", exact: true }).click();
  await expect(page.locator(".swarm-inspector .swarm-status")).toHaveText("Stopped");
  const action = state.calls.find((c) => c.path === "/v1/swarm/action" && c.body.action === "message")!;
  expect(action.body).toMatchObject({ run_id: "new-1", epoch: "service-1", expected_revision: 1, text: "Focus next on the retry behavior" });
  expect(state.launches).toBe(1);
});

test("an uncertain launch retry reuses the same request", async ({ page }) => {
  const state = await swarmFixture(page, []); state.loseLaunchReply = true;
  await page.goto(swarmUrl);
  await page.getByRole("button", { name: "New agent", exact: true }).click();
  await page.getByLabel("Project directory").fill("/Projects/new-app");
  await page.getByLabel("What should it do?").fill("Review this project");
  await page.getByRole("button", { name: "Start agent", exact: true }).click();
  await expect(page.getByText(/The launch may have succeeded/)).toBeVisible();
  await expect(page.getByLabel("What should it do?")).toBeDisabled();
  await page.getByRole("button", { name: "Check launch", exact: true }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(state.launches).toBe(1);
  const launches = state.calls.filter((c) => c.path === "/v1/swarm/launch");
  expect(launches[0].body).toEqual(launches[1].body);
});

test("disconnect preserves observations and disables launch and control", async ({ page }) => {
  const state = await swarmFixture(page);
  await page.goto(swarmUrl);
  await page.getByRole("button", { name: /^Codex: Build the Swarm/ }).click();
  state.offline = true;
  await page.getByRole("button", { name: "Refresh agents" }).click();
  await expect(page.getByText(/Showing the last confirmed agents/)).toBeVisible();
  await expect(page.locator(".swarm-node")).toHaveCount(4);
  await expect(page.getByRole("button", { name: "New agent", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Stop agent", exact: true })).toBeDisabled();
});

test("empty state, dialog keyboard behavior and narrow layout", async ({ page }, info) => {
  const state = await swarmFixture(page, []);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(swarmUrl);
  await expect(page.getByRole("heading", { name: "Your next project starts here" })).toBeVisible();
  const newAgent = page.getByRole("button", { name: "New agent", exact: true });
  await newAgent.click();
  await expect(page.getByRole("button", { name: "Close new agent" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(newAgent).toBeFocused();
  state.snapshot.agents = [makeAgent({ task: "A long task title that must wrap without pushing the project list outside the viewport" })];
  await page.getByRole("button", { name: "Refresh agents" }).click();
  await expect(page.locator(".swarm-node")).toHaveCount(1);
  await page.locator(".swarm-node").click();
  await expect(page.getByLabel("Next instruction")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: info.outputPath("swarm-mobile.png"), fullPage: true });
  await page.setViewportSize({ width: 320, height: 760 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
