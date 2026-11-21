import { expect, test, type Page } from "@playwright/test";
import { resolveProofDir } from "./proof-dir";
import { defaultSettingsPayload, emptyInventoryPayload, emptyPoliciesPayload, emptyReceiptsPayload, freeStateSnapshot } from "./fixture-states";

const summary = {
  schema: "guard-native-local-business-review-summary.v1", version: 1, request_id: "business-test",
  request_snapshot_digest: "a".repeat(64), prepared_input_binding: "b".repeat(64),
  service: "google_gmail", operation: "mail_send", audience_kind: "named", audience_expansion_state: "known",
  recipient_count: 3, record_count: 1, byte_count: 24, attachment_count: 0, inspection_state: "unknown",
  sensitivity_labels: ["confidential"], snapshot_fact_completeness: "known",
  account_currentness: "not_asserted", execution_state: "not_checked",
};
const approval = {
  request_id: "business-test", harness: "codex", artifact_id: "business-ui-fixture", artifact_name: "Send email",
  artifact_type: "tool_action_request", artifact_hash: "fixture", publisher: "codex-local",
  policy_action: "require-reapproval", recommended_scope: "artifact", allowed_scopes: ["artifact"],
  scope_restrictions: ["provider_account_unverified_once_only"], changed_fields: ["command"], source_scope: "project",
  config_path: "project-config.json", workspace: null, launch_target: null, transport: "stdio", review_command: "",
  approval_url: "", status: "pending", resolution_action: null, resolution_scope: null, reason: null,
  created_at: "2026-10-05T00:00:00Z", resolved_at: null, action_envelope_json: null, decision_v2_json: null,
};

async function mount(page: Page, nextSummary: () => unknown, displayOnly = false, nativeFailure: "with-sql" | "empty" | null = null, summaryStatus = 200, detailReadFailure: boolean | (() => boolean) = false) {
  const request = displayOnly ? { ...approval, harness: "native-business", created_at: "",
    allowed_scopes: [], recommended_scope: null, native_business_review_display_only: true } : approval;
  await page.route("**/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "business-ui-fixture-session" };
    else if (path.endsWith("/runtime")) body = { ...freeStateSnapshot, pending_count: 1 };
    else if (path.endsWith("/business-summary")) {
      body = nextSummary();
      if (summaryStatus === 404) {
        await route.fulfill({ status: 404, contentType: "text/html", body: "<h1>Not found</h1>" });
        return;
      }
      if (body && typeof body === "object" && "error" in body && body.error === "native_local_business_summary_read_failed") {
        await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify(body) });
        return;
      }
    }
    else if (path.endsWith("/requests/business-test")) {
      if (typeof detailReadFailure === "function" ? detailReadFailure() : detailReadFailure) {
        await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({
          error: "native_local_business_queue_read_failed",
          message: "Saved request details could not be verified. Refresh this request or return to the queue.",
        }) });
        return;
      }
      body = request;
    }
    else if (path.endsWith("/requests")) body = { items: nativeFailure === "empty" ? [] : [request], next_cursor: null,
      total_pending_count: nativeFailure === "empty" ? 0 : 1, total_count: nativeFailure === "empty" ? 0 : 1, status: "pending",
      ...(nativeFailure ? { native_business_queue_error: "native_local_business_queue_read_failed" } : {}) };
    else if (path.endsWith("/receipts/latest")) {
      await route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ error: "not_found" }) });
      return;
    }
    else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) body = defaultSettingsPayload;
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/diff")) body = null;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  await page.goto(`${nativeFailure === "empty" ? "/inbox" : "/requests/business-test"}?guardDaemon=http://127.0.0.1:4277`);
}

for (const state of ["with-sql", "empty"] as const) {
  test(`native discovery failure is visible with ${state}`, async ({ page }) => {
    await mount(page, () => summary, false, state);
    await expect(page.getByText("Saved business requests could not be loaded.")).toBeVisible();
    await expect(page.getByText("Other Guard requests remain available.", { exact: false })).toBeVisible();
    await expect(page.getByRole("button", { name: "Refresh queue", exact: true })).toBeVisible();
    if (state === "empty") {
      await expect(page.getByText("All clear", { exact: true })).toHaveCount(0);
      await expect(page.getByText("Nothing to review", { exact: true })).toHaveCount(0);
    }
    if (state === "with-sql") {
      await expect(page.getByRole("region", { name: "Saved business action details" })).toHaveCount(0);
    }
  });
}

for (const [name, width, height] of [["desktop", 1280, 900], ["phone", 390, 844]] as const) {
test(`native projected detail is explicitly read-only on ${name}`, async ({ page }) => {
  await page.setViewportSize({ width, height });
  await mount(page, () => summary, true);
  await expect(page.getByText("Review is not connected yet")).toBeVisible();
  await expect(page.getByText("This saved business request is read-only.", { exact: false })).toBeVisible();
  await expect(page.getByText("From Native business workflow", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /Approve|Block once|Stop this/ })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Saved business action details" })).toBeVisible();
  await expect(page.getByText("Saved request", { exact: true })).toHaveCount(0);
  await expect(page.getByText("What was stopped", { exact: false })).toHaveCount(0);
  await expect(page.getByText("What would happen without Guard?", { exact: true })).toHaveCount(0);
  const panel = page.getByRole("region", { name: "Saved business action details" });
  const bounds = await panel.boundingBox();
  expect(bounds).not.toBeNull();
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(width);
});
}

for (const [name, width, height] of [["desktop", 1280, 900], ["phone", 390, 844]] as const) {
  test(`saved summary stays honest and readable on ${name}`, async ({ page }) => {
    await page.setViewportSize({ width, height });
    await mount(page, () => summary, true);
    const panel = page.getByRole("region", { name: "Saved business action details" });
    await expect(panel).toBeVisible();
    await expect(panel).toContainText("Send email · Gmail");
    await expect(panel).toContainText("does not verify the work account");
    await expect(panel).toContainText("or confirm execution");
    await expect(panel).toContainText("Counts alone do not establish");
    await expect(panel).not.toContainText("a".repeat(64));
    await expect(panel.getByRole("button")).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    if (name === "phone") {
      const queue = page.getByRole("button", { name: /^Queue \(/ });
      expect((await queue.boundingBox())!.height).toBeGreaterThanOrEqual(44);
      await queue.click();
      const search = page.getByRole("searchbox", { name: "Search review queue" });
      expect((await search.boundingBox())!.height).toBeGreaterThanOrEqual(44);
      await page.getByRole("button", { name: "Show filters", exact: true }).click();
      for (const label of ["Sort review queue", "Filter requests from date", "Filter requests to date"]) {
        expect((await page.getByLabel(label).boundingBox())!.height).toBeGreaterThanOrEqual(44);
      }
      await queue.click();
      const notice = page.getByText("This saved business request is read-only.", { exact: false });
      await notice.scrollIntoViewIfNeeded();
      const noticeBounds = (await notice.boundingBox())!;
      const navigationBounds = (await page.getByTestId("mobile-bottom-navigation").boundingBox())!;
      expect(noticeBounds.y + noticeBounds.height).toBeLessThanOrEqual(navigationBounds.y);
      await page.screenshot({ path: `${resolveProofDir()}/business-summary-phone-bottom.png`, fullPage: true });
      await page.locator(".guard-shell-content").evaluate(element => { element.scrollTop = 0; });
    }
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: `${resolveProofDir()}/business-summary-${name}.png`, fullPage: true });
  });
}

test("malformed metadata is unavailable and refresh recovers", async ({ page }) => {
  let value: unknown = { ...summary, subject: "private-canary" };
  await mount(page, () => value, true);
  await expect(page.getByText("Saved business details could not be loaded.")).toBeVisible();
  await expect(page.getByText("private-canary")).toHaveCount(0);
  value = summary;
  await page.getByRole("button", { name: "Refresh details" }).click();
  await expect(page.getByRole("region", { name: "Saved business action details" })).toBeVisible();
});

test("non-JSON optional-summary 404 omits the panel without a read error", async ({ page }) => {
  const summaryResponse = page.waitForResponse(response => response.url().endsWith("/business-summary"));
  await mount(page, () => null, true, null, 404);
  const response = await summaryResponse;
  expect(response.status()).toBe(404);
  await expect(page.getByText("Review is not connected yet")).toBeVisible();
  await expect(page.getByRole("region", { name: "Saved business action details" })).toHaveCount(0);
  await expect(page.getByText("Saved business details could not be loaded.")).toHaveCount(0);
});

test("unverified request lookup shows recovery guidance without declaring it missing", async ({ page }) => {
  let unavailable = true;
  await mount(page, () => summary, true, null, 200, () => unavailable);
  await expect(page.getByText("Saved request details could not be verified. Refresh this request or return to the queue.")).toBeVisible();
  await expect(page.getByText("This request is no longer waiting.")).toHaveCount(0);
  await expect(page.getByRole("button", { name: /^Approve|^Block once|^Stop this/ })).toHaveCount(0);
  unavailable = false;
  await page.getByRole("button", { name: "Refresh request", exact: true }).click();
  await expect(page.getByRole("region", { name: "Saved business action details" })).toBeVisible();
  await expect(page.getByText("Saved request details could not be verified. Refresh this request or return to the queue.")).toHaveCount(0);
});

test("native read failure offers refresh instead of disappearing", async ({ page }) => {
  let value: unknown = { error: "native_local_business_summary_read_failed" };
  await mount(page, () => value, true);
  await expect(page.getByText("Saved business details could not be loaded.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Refresh details" })).toBeVisible();
  value = summary;
  await page.getByRole("button", { name: "Refresh details" }).click();
  await expect(page.getByRole("region", { name: "Saved business action details" })).toBeVisible();
});

test("SQL review does not request inapplicable native details", async ({ page }) => {
  let reads = 0;
  await mount(page, () => { reads += 1; return { error: "native_local_business_summary_read_failed" }; });
  await expect(page.getByText("Paused action", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Saved business action details" })).toHaveCount(0);
  await expect(page.getByText("Saved business details could not be loaded.")).toHaveCount(0);
  expect(reads).toBe(0);
});
