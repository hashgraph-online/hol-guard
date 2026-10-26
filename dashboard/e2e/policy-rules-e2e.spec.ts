import { test, expect, type Page } from "@playwright/test";
import {
  freeStateSnapshot,
  paidStateSnapshot,
  connectedCloudExceptionsPayload,
  pendingCloudExceptionRequestsPayload,
  emptyReceiptsPayload,
  emptyInventoryPayload,
  defaultSettingsPayload,
} from "./fixture-states";

const DAEMON_PARAM = "?guardDaemon=http://127.0.0.1:4175";

type Policy = Record<string, unknown>;

const basePolicies: Policy[] = [
  {
    decision_id: 1, harness: "claude-code", scope: "workspace", artifact_id: "family:tool-action",
    workspace: "/work/shop-app", workspace_label: "shop-app", publisher: null, action: "allow",
    reason: "git push origin main", source: "local", updated_at: "2026-10-19T10:00:00Z",
    remembered_command: "git push origin main", source_receipt_id: "receipt-aaa111",
  },
  {
    decision_id: 2, harness: "codex", scope: "artifact", artifact_id: "family:tool-action",
    workspace: "/work/shop-app", workspace_label: "shop-app", publisher: null, action: "block",
    reason: "rm -rf build", source: "local", updated_at: "2026-10-18T10:00:00Z",
    remembered_command: "rm -rf build", source_receipt_id: "receipt-bbb222",
  },
  {
    decision_id: 4, harness: "codex", scope: "global", artifact_id: "family:tool-action",
    workspace: null, workspace_label: null, publisher: null, action: "allow",
    reason: "shell commands", source: "local", updated_at: "2026-10-19T09:00:00Z",
    remembered_command: "any shell command", source_receipt_id: "receipt-ddd444",
  },
  {
    decision_id: 3, harness: "claude-code", scope: "workspace", artifact_id: "family:package-request",
    workspace: "/work/shop-app", workspace_label: "shop-app", publisher: null, action: "allow",
    reason: "npm install", source: "cloud-sync", updated_at: "2026-10-17T10:00:00Z",
    remembered_command: "npm install left-pad", source_receipt_id: "receipt-ccc333",
  },
];

async function mountStateful(page: Page, snapshot: unknown = freeStateSnapshot) {
  const state = { policies: structuredClone(basePolicies), clearCalls: [] as Record<string, unknown>[] };
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const json = (body: unknown) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
    if (path.includes("/initialize")) return json({ auth_token: "e2e-token-e2e" });
    if (path.includes("/runtime")) return json(snapshot);
    if (path.includes("/policy/clear")) {
      const payload = request.postDataJSON() as Record<string, unknown>;
      state.clearCalls.push(payload);
      // Mirror the daemon contract: artifact clears one decision, workspace
      // clears its workspace decisions, global+all clears global decisions.
      state.policies = state.policies.filter((policy) => {
        // The clear payload carries source; the daemon only clears decisions
        // from that source, so a local clear never touches cloud rules.
        if (payload.source && policy.source !== payload.source) return true;
        if (payload.all === true && payload.scope === "global") return policy.scope !== "global";
        if (payload.scope === "artifact") return !(policy.harness === payload.harness && policy.artifact_id === payload.artifact_id && policy.scope === "artifact");
        if (payload.scope === "workspace") return !(policy.harness === payload.harness && policy.workspace === payload.workspace);
        return true;
      });
      return json({ cleared: 1, harness: payload.harness ?? null, source: payload.source ?? null });
    }
    if (path.includes("/policy/cloud-exception-requests")) return json(pendingCloudExceptionRequestsPayload);
    if (path.includes("/policy/cloud-exceptions")) return json(connectedCloudExceptionsPayload);
    if (path.endsWith("/policy")) return json({ items: state.policies, cloud_exceptions: [] });
    if (path.includes("/receipts")) return json(emptyReceiptsPayload);
    if (path.includes("/settings")) return json(defaultSettingsPayload);
    if (path.includes("/inventory")) return json(emptyInventoryPayload);
    return json({});
  });
  return state;
}

test.describe("Rules & exceptions end to end", () => {
  test("remove one rule, bulk remove the rest, exports carry what is shown", async ({ page }) => {
    const state = await mountStateful(page);
    await page.goto(`/policy${DAEMON_PARAM}`);
    await expect(page.getByText("1 broad allow deserves a second look")).toBeVisible();

    // Single removal through the row action clears exactly that decision.
    const localSection = page.locator("#remembered-rules-list");
    await page.getByRole("button", { name: "Remove rule" }).first().click();
    await expect(page.getByText(/Guard will allow "git push origin main"/)).toHaveCount(0);
    expect(state.clearCalls.length).toBe(1);

    // Bulk removal: select the remaining local rule, global stays unselectable.
    await expect(page.getByLabel(/Select rule any shell command/)).toHaveCount(0);
    await page.getByLabel(/Select rule rm -rf build/).check();
    await page.getByRole("button", { name: "Remove selected" }).click();
    await expect(page.getByText(/Guard will block "rm -rf build"/)).toHaveCount(0);
    expect(state.clearCalls.length).toBe(2);
    // The global rule is still a local rule — it remains, without a checkbox.
    await expect(localSection.getByText(/Guard will allow matching actions on every project/)).toBeVisible();

    // The cloud rule survived both local clears.
    await expect(page.getByText(/Guard will allow "npm install left-pad"/).first()).toBeVisible();

    // Export downloads what the list shows: survivors in, removed rules out.
    await page.getByRole("button", { name: /^More/ }).click();
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("button", { name: "Export CSV" }).click(),
    ]);
    expect(await download.suggestedFilename()).toContain("csv");
    const csvPath = await download.path();
    expect(csvPath).toBeTruthy();
    const { readFileSync } = await import("node:fs");
    const csv = readFileSync(csvPath!, "utf8");
    expect(csv).toContain("any shell command");
    expect(csv).toContain("npm install left-pad");
    expect(csv).not.toContain("git push origin main");
    expect(csv).not.toContain("rm -rf build");
    void localSection;
  });

  test("sort, search, filters and pagination state stay consistent", async ({ page }) => {
    await mountStateful(page);
    await page.goto(`/policy${DAEMON_PARAM}`);

    await page.getByLabel("Search remembered rules").fill("left-pad");
    await expect(page.getByText(/Showing 1 of 4 remembered rules/)).toBeVisible();
    await page.getByRole("button", { name: "Clear", exact: true }).click();
    await expect(page.getByText(/Showing/)).toHaveCount(0);

    const actionSwitch = page.getByRole("group", { name: "Filter by action" });
    await actionSwitch.getByRole("button", { name: /^Allow/ }).click();
    await expect(page.getByText(/Guard will block/)).toHaveCount(0);
    await actionSwitch.getByRole("button", { name: /^All actions/ }).click();

    await page.getByRole("button", { name: /^More/ }).click();
    await page.getByLabel("Filter by app").selectOption("codex");
    const localSection = page.locator("#remembered-rules-list");
    await expect(localSection.getByText(/Guard will allow "git push origin main"/)).toHaveCount(0);
    await expect(localSection.getByText(/Guard will block "rm -rf build"/)).toBeVisible();
    await page.getByLabel("Filter by app").selectOption("");

    // Column-header sorts the toolbar select does not offer are named honestly.
    await page.getByRole("button", { name: /Sort by Source/ }).first().click();
    await expect(page.getByLabel("Sort rules")).toHaveValue("source:asc");
    await expect(page.getByLabel("Sort rules").locator("option:checked")).toHaveText("Custom (column sort)");
    await page.getByLabel("Sort rules").selectOption("updated:desc");
    await expect(page.getByLabel("Sort rules")).toHaveValue("updated:desc");
  });

  test("inspector removes a rule and closes only on success", async ({ page }) => {
    const state = await mountStateful(page);
    await page.goto(`/policy${DAEMON_PARAM}`);
    await page.getByRole("button", { name: "Inspect rule rm -rf build" }).first().click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await dialog.getByRole("button", { name: "Remove rule" }).click();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(page.getByText(/Guard will block "rm -rf build"/)).toHaveCount(0);
    expect(state.clearCalls.length).toBe(1);
  });

  test("cloud exceptions tab loads groups, filters and detail", async ({ page }) => {
    await mountStateful(page, paidStateSnapshot);
    await page.goto(`/policy${DAEMON_PARAM}#policy-view=cloud-exceptions`);
    await expect(page.getByText("Active on this device").first()).toBeVisible();
    await expect(page.getByText("Active synced")).toBeVisible();
    await page.getByLabel("Search exceptions").fill("e2e-active");
    await expect(page.getByText("codex:project:e2e-active").first()).toBeVisible();
    const groups = page.locator('[aria-label="Cloud exception groups"]');
    await page.getByLabel("Search exceptions").fill("no-match-zzz");
    await expect(groups.getByText("codex:project:e2e-active")).toHaveCount(0);
    await page.getByLabel("All scopes").selectOption("workspace");
    await page.getByLabel("Search exceptions").fill("");
    await expect(groups.getByText("codex:project:e2e-active")).toHaveCount(0);
  });

  test("how guard decides tab links to settings and extensions", async ({ page }) => {
    await mountStateful(page);
    await page.goto(`/policy${DAEMON_PARAM}#policy-view=how-guard-decides`);
    await expect(page.getByText("Policy explains. Settings configures.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Open protection rules" })).toBeVisible();
  });

  test("evidence selects render with the styled treatment", async ({ page }) => {
    await page.route("**/v1/**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      const json = (body: unknown) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
      if (path.includes("/initialize")) return json({ auth_token: "e2e-token-evidence" });
      if (path.includes("/runtime")) return json(freeStateSnapshot);
      if (path.includes("/receipts")) {
        return json({
          items: [{
            receipt_id: "receipt-evidence-1", harness: "codex", artifact_id: "artifact-evidence-1",
            artifact_hash: "hash-evidence-1", artifact_name: "Recorded codex command",
            policy_decision: "allow", capabilities_summary: "Local command", changed_capabilities: [],
            provenance_summary: "codex --version", user_override: null, source_scope: null,
            timestamp: new Date().toISOString(),
          }],
        });
      }
      if (path.endsWith("/policy")) return json({ items: [], cloud_exceptions: [] });
      if (path.includes("/settings")) return json(defaultSettingsPayload);
      if (path.includes("/inventory")) return json(emptyInventoryPayload);
      return json({});
    });
    await page.goto(`/evidence${DAEMON_PARAM}`);
    const select = page.getByLabel("Time period");
    await expect(select).toBeVisible();
    const appearance = await select.evaluate((el) => getComputedStyle(el).appearance);
    expect(appearance).toBe("none");
    await select.selectOption({ index: 1 });
    await expect(page.getByText("Recorded codex command").first()).toBeVisible();
  });
});
