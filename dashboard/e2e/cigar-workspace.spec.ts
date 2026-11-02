import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { defaultSettingsPayload, emptyInventoryPayload, emptyPoliciesPayload, emptyReceiptsPayload, freeStateSnapshot } from "./fixture-states";
import { chooseMenuOption } from "./select-menu";

const ready = JSON.parse(readFileSync(new URL("../src/context-assistance/fixtures/intent-state.json", import.meta.url), "utf8")).native_test.ready_observation;
const catalog = JSON.parse(readFileSync(new URL("../../integrations/cigar/release-catalog.v1.json", import.meta.url), "utf8"));
const updatePreferences = { mode: "manual", allow_preview: false, retain_last_good: true };
const updateSettings = { schema: "guard-cigar-update-preferences.v1", requested: updatePreferences, effective: updatePreferences,
  revision: "sha256:" + "a".repeat(64), diagnostic: null, locked_settings: [],
  capabilities: { modes: ["manual", "notify"], automatic_preparation: false, automatic_selection: false, retention_reduction: false } };
const releases = { schema: "guard-cigar-releases.v1", host_platform: "darwin-arm64", builds: catalog.builds, interpreter_builds: catalog.interpreters,
  catalog: { source: "bundled", fresh_for_preparation: true, diagnostic: null, trust_configured: false, trust_diagnostic: null,
    remote_feed_configured: false, feed_diagnostic: null, activation_granted: false } };
const installation = { runtime_id: ready.preferences.runtime_id, qualification: "local_candidate", python_version: [3, 14, 7], platform: "darwin-arm64", worker_fingerprint: ready.runtime.worker_fingerprint };

type Call = { path: string; method: string; body: any };
const readOnlyActions = new Set(["preferences", "list"]);
const writes = (calls: Call[]) => calls.filter((call) => call.method === "POST"
  && (call.path.startsWith("/v1/context-assistance") || call.path === "/v1/settings") && !readOnlyActions.has(call.body?.input?.action));

async function fixture(page: Page, registered = true, savedEnabled = false) {
  const calls: Call[] = [];
  let status = { ...ready, availability: savedEnabled ? "unavailable" : "off", requested_enabled: savedEnabled, effective_enabled: false,
    runtime: null, last_check: null, diagnostic: savedEnabled ? "runtime_not_verified" : null, job: null, qualification: null,
    preferences: { ...ready.preferences, enabled: savedEnabled, runtime_id: savedEnabled ? installation.runtime_id : "" },
    effective_preferences: { ...ready.effective_preferences, enabled: savedEnabled, runtime_id: savedEnabled ? installation.runtime_id : "" },
    installation_options: null };
  let settings = { ...defaultSettingsPayload, settings: { ...defaultSettingsPayload.settings,
    context_assistance: status.preferences, context_assistance_requested: status.preferences,
    approval_gate: { enabled: true, configured: true, cooldown_seconds: 0, cooldown_active: false,
      cooldown_expires_at: null, locked_until: null, fail_closed: false, strict_all_decisions: false,
      totp_enabled: false, totp_pending: false } } };
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const body = request.postDataJSON();
    calls.push({ path, method: request.method(), body });
    let result: unknown = {};
    const versions = (value: unknown) => ({ schema: "guard-cigar-versions-result.v1", result: value, state: status });
    if (path.endsWith("/initialize")) result = { auth_token: "e2e-cigar-session" };
    else if (path === "/v1/runtime") result = freeStateSnapshot;
    else if (path === "/v1/requests") result = { items: [], next_cursor: null, total_pending_count: 0, total_count: 0, status: "pending" };
    else if (path === "/v1/receipts") result = emptyReceiptsPayload;
    else if (path === "/v1/policy") result = emptyPoliciesPayload;
    else if (path === "/v1/inventory") result = emptyInventoryPayload;
    else if (path === "/v1/settings") {
      if (request.method() === "POST") {
        settings = { ...settings, settings: { ...settings.settings, ...body.settings } };
        settings.settings.context_assistance_requested = settings.settings.context_assistance;
        status = { ...status, preferences: settings.settings.context_assistance,
          effective_preferences: settings.settings.context_assistance,
          requested_enabled: settings.settings.context_assistance.enabled,
          availability: settings.settings.context_assistance.enabled ? "unavailable" : "off",
          diagnostic: settings.settings.context_assistance.enabled ? "runtime_not_verified" : null };
      }
      result = settings;
    } else if (path === "/v1/context-assistance/versions" && request.method() === "GET") result = versions(releases);
    else if (path === "/v1/context-assistance/interpreters") result = versions({ interpreters: [] });
    else if (path === "/v1/context-assistance/jobs") result = versions({ jobs: [] });
    else if (body?.input?.action === "preferences") result = versions(updateSettings);
    else if (path === "/v1/context-assistance/installations") result = { ...status, installation_options: registered ? [installation] : [] };
    else if (path === "/v1/context-assistance") result = status;
    else if (path === "/v1/context-assistance/activate") {
      status = { ...status, availability: "ready", effective_enabled: true, runtime: ready.runtime,
        diagnostic: null, qualification: "local_candidate" };
      result = status;
    } else if (path === "/v1/context-assistance/stop") {
      status = { ...status, availability: "off", effective_enabled: false, requested_enabled: false,
        runtime: null, diagnostic: null, preferences: { ...status.preferences, enabled: false },
        effective_preferences: { ...status.effective_preferences, enabled: false } };
      settings = { ...settings, settings: { ...settings.settings, context_assistance: status.preferences } };
      result = status;
    } else if (path === "/v1/context-assistance/workspace" && body.input.action === "list") {
      result = { schema: "guard-cigar-workspace-result.v1", data_role: true, result: { scopes: [] } };
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(result) });
  });
  return calls;
}

for (const width of [1440, 790, 390, 320]) {
  test("CIGAR navigation, setup and guide at " + width + "px", async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const calls = await fixture(page);
    await page.goto("/cigar?guardDaemon=http://127.0.0.1:4175");
    await expect(page.getByRole("heading", { name: "CIGAR", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Give your AI the right pages, not the whole book." })).toBeVisible();
    await expect(page.getByRole("button", { name: "Turn on CIGAR", exact: true })).toBeEnabled();
    await expect(page.getByRole("heading", { name: "Three steps, and only the first is needed", exact: true })).toBeVisible();
    await expect(page.locator(".cigar-hero, .cigar-panel").getByText(/save[sd]? tokens|faster|smarter/i).filter({ visible: true })).toHaveCount(0);
    await expect(page.locator('[data-navigation-item="cigar"][aria-current="page"]:visible').first()).toBeVisible();
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath("cigar-overview-" + width + ".png"), fullPage: true });
    const guideTab = page.getByRole("tab", { name: "How it works", exact: true });
    await guideTab.click();
    await expect(page.getByRole("heading", { name: "Do I need to install anything?", exact: true })).toBeVisible();
    await page.getByText("Does CIGAR save me tokens or make my AI faster?", { exact: true }).click();
    await expect(page.getByText(/CIGAR does not promise either/)).toBeVisible();
    await guideTab.focus();
    await page.keyboard.press("Home");
    await expect(page.getByRole("tab", { name: "Overview", exact: true })).toBeFocused();
    await page.keyboard.press("ArrowRight");
    await expect(page.getByRole("tab", { name: "Settings", exact: true })).toBeFocused();
    await expect(page.getByText("Selected runtime", { exact: true })).toBeVisible();
    await page.getByRole("tab", { name: "Projects & AI apps", exact: true }).click();
    await expect(page.getByText("Turn on CIGAR first", { exact: true })).toBeVisible();
    expect(writes(calls)).toEqual([]);
    expect(errors).toEqual([]);
  });
}

test("a computer without CIGAR offers one click and changes nothing until it is pressed", async ({ page }) => {
  const calls = await fixture(page, false);
  await page.goto("/cigar?guardDaemon=http://127.0.0.1:4175&section=runtime");
  await expect(page.getByRole("button", { name: "Turn on CIGAR", exact: true }).first()).toBeEnabled();
  await expect(page.getByText("Waiting for Guard's safety check", { exact: true })).toHaveCount(0);
  expect(writes(calls)).toEqual([]);
});

test("CIGAR saves with the existing approval proof, starts explicitly, and keeps a global off switch", async ({ page }) => {
  const calls = await fixture(page, true, true);
  await page.goto("/cigar?guardDaemon=http://127.0.0.1:4175&section=runtime");
  await chooseMenuOption(page.getByRole("combobox", { name: "Context size" }), "low_memory");
  await expect(page.getByText("Save your changes first", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Turn on CIGAR", exact: true }).first()).toBeDisabled();
  const save = page.getByRole("region", { name: "Save CIGAR preferences" });
  await save.getByRole("button", { name: "Save CIGAR preferences", exact: true }).click();
  const proof = page.getByRole("dialog");
  await expect(proof).toBeVisible();
  await proof.getByLabel("Approval password").fill("cigar-ui-test-proof");
  await proof.getByRole("button", { name: "Save settings", exact: true }).click();
  await expect(proof).toHaveCount(0);
  await expect(page.locator(".cigar-status")).toHaveText("Not started");
  const start = page.getByRole("button", { name: "Turn on CIGAR", exact: true }).first();
  await expect(start).toBeEnabled();
  expect(calls.some((call) => call.path === "/v1/context-assistance/activate")).toBe(false);
  // Preferences are saved and the runtime is selected, so turning on needs no second approval.
  await start.click();
  await expect(proof).toHaveCount(0);
  await expect(page.locator(".cigar-status")).toHaveText("Ready");
  await page.getByRole("tab", { name: "How it works", exact: true }).click();
  await page.getByRole("button", { name: "Turn off CIGAR", exact: true }).click();
  await expect(page.locator(".cigar-status")).toHaveText("Off");
  await expect(page.getByRole("tab", { name: "How it works", exact: true })).toHaveAttribute("aria-selected", "true");
  expect(calls.filter((call) => call.path === "/v1/context-assistance/activate")).toHaveLength(1);
  expect(calls.filter((call) => call.path === "/v1/context-assistance/stop")).toHaveLength(1);
  const saves = calls.filter((call) => call.path === "/v1/settings" && call.method === "POST");
  expect(saves).toHaveLength(1);
  expect(saves[0].body.settings.approval_gate.current_password).toBe("cigar-ui-test-proof");
  expect(saves[0].body.settings.context_assistance.enabled).toBe(true);
});

test("a saved runtime starts from the top of the guide and leads to actual context access", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const calls = await fixture(page, true, true);
  await page.goto("/cigar?guardDaemon=http://127.0.0.1:4175&section=guide");
  await expect(page.locator(".cigar-status")).toHaveText("Not started");
  const start = page.getByRole("button", { name: "Turn on CIGAR", exact: true });
  await expect(start).toBeInViewport();
  expect(calls.some((call) => call.path === "/v1/context-assistance/activate")).toBe(false);
  await start.click();
  await expect(page.locator(".cigar-status")).toHaveText("Ready");
  await expect(page.getByRole("tab", { name: "How it works", exact: true })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("button", { name: "Pick a project folder", exact: true }).click();
  await expect(page.getByRole("tab", { name: "Projects & AI apps", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByText("No workspace has context access.", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Workspace folder", { exact: true })).toBeEnabled();
  expect(calls.filter((call) => call.path === "/v1/context-assistance/activate")).toHaveLength(1);
  expect(calls.some((call) => call.path === "/v1/settings" && call.method === "POST")).toBe(false);
  expect(calls.some((call) => call.path === "/v1/context-assistance/workspace-grant")).toBe(false);
});

for (const width of [1440, 390]) {
  test("guided CIGAR lessons resume without changing runtime or access at " + width + "px", async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(() => {
      Object.defineProperty(navigator, "clipboard", { configurable: true, value: {
        writeText: async (text: string) => { (window as any).__cigarCopiedQuestion = text; },
      } });
    });
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const calls = await fixture(page);
    await page.goto("/cigar?guardDaemon=http://127.0.0.1:4175&section=tutorials");
    await expect(page.locator(".cigar-heading p")).toHaveText("A context helper for your AI that runs on your computer.");
    await expect(page.getByRole("heading", { name: "Make CIGAR useful for your next task", exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("cigar-tutorials-" + width + ".png"), fullPage: true });
    await page.getByRole("button", { name: /Start walkthrough.*Prepare your first cited brief/ }).click();
    const walkthrough = page.getByRole("complementary", { name: "Prepare your first cited brief", exact: true });
    await expect(walkthrough).toBeVisible();
    await expect(walkthrough.getByText("Step 1 of 6 · learning progress", { exact: true })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Settings", exact: true })).toHaveAttribute("aria-selected", "true");
    for (let index = 0; index < 3; index++) await walkthrough.getByRole("button", { name: "Next step", exact: true }).click();
    await expect(walkthrough.getByText("Step 4 of 6 · learning progress", { exact: true })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Projects & AI apps", exact: true })).toHaveAttribute("aria-selected", "true");
    await walkthrough.getByRole("button", { name: "Copy question", exact: true }).click();
    await expect(walkthrough.getByRole("status")).toContainText("Question copied");
    expect(await page.evaluate(() => (window as any).__cigarCopiedQuestion)).toContain("native Guard policy");
    const saved = await page.evaluate(() => JSON.parse(sessionStorage.getItem("hol-guard:cigar-tutorial:v1") ?? "null"));
    expect(saved).toEqual({ schema: 1, tutorial: "first-brief", step: 3 });
    await walkthrough.getByRole("button", { name: "Exit walkthrough", exact: true }).click();
    await expect(walkthrough).toHaveCount(0);
    await page.getByRole("button", { name: /Resume walkthrough.*Prepare your first cited brief/ }).click();
    await expect(walkthrough.getByText("Step 4 of 6 · learning progress", { exact: true })).toBeVisible();
    await walkthrough.getByRole("button", { name: "Restart this walkthrough", exact: true }).click();
    await expect(walkthrough.getByText("Step 1 of 6 · learning progress", { exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("cigar-walkthrough-" + width + ".png"), fullPage: true });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await expect(page.locator(".cigar-status")).toHaveText("Off");
    expect(writes(calls)).toEqual([]);
    expect(errors).toEqual([]);
  });
}

test("how CIGAR works explains scoped graphs, budgets and evidence interactively", async ({ page }) => {
  const calls = await fixture(page);
  await page.goto("/cigar?guardDaemon=http://127.0.0.1:4175&section=guide");
  await expect(page.getByRole("heading", { name: "Context Intelligence Graph Agentic Runtime", exact: true })).toBeVisible();
  await page.getByRole("button", { name: /Build a scoped graph/ }).click();
  await expect(page.getByRole("region", { name: /Build a scoped graph/ })).toContainText("organized context store");
  await page.getByRole("button", { name: /Compile a cited brief/ }).click();
  await expect(page.getByRole("region", { name: /Compile a cited brief/ })).toContainText("does not change an AI model's own context window");
  await page.getByRole("button", { name: /Use it with Guard and apps/ }).click();
  await expect(page.getByRole("region", { name: /Use it with Guard and apps/ })).toContainText("Guard makes and enforces command decisions");
  await page.getByRole("button", { name: "Try a guided walkthrough", exact: true }).click();
  await expect(page.getByRole("tab", { name: "Tutorials", exact: true })).toHaveAttribute("aria-selected", "true");
  expect(writes(calls)).toEqual([]);
});
