import { expect, test, type Page } from "@playwright/test";

import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  emptyReceiptsPayload,
  freeStateSnapshot,
} from "./fixture-states";

const DAEMON = "guardDaemon=http://127.0.0.1:4175";
const SECRET_SENTINEL = "secret_sentinel_value";

const activity = {
  activity_id: "activity:01",
  occurred_at: "2026-07-19T12:00:00+00:00",
  harness: "codex",
  hook_phase: "pre",
  execution_status: "allowed_unconfirmed",
  proof_level: "pre_hook",
  policy_action: "allow",
  decision_reason_code: SECRET_SENTINEL,
  controlling_rule_id: "command.git.fetch",
  parse_confidence: "exact",
  uncertainty_class: null,
  match_count: 1,
  prompted: false,
  approval_reuse_status: "not-applicable",
  receipt_link_status: "not_applicable",
  receipt_id: null,
  evaluation_latency_bucket: "le_2_ms",
  persistence_latency_bucket: "le_1_ms",
  feedback_label: null,
  schema_version: "1.0.0",
  matches: [{
    ordinal: 0,
    extension_id: "command.git",
    extension_version: "1.0.0",
    rule_id: "command.git.fetch",
    rule_version: "1.0.0",
    match_class: "safe_variant",
    severity: "low",
    default_floor: "review",
    safe_variant_id: "command.git.fetch.public",
    effect_classes: ["remote-state-read"],
    schema_version: "1.0.0",
  }],
};

const dimensions = {
  harness: [{ value: "codex", count: 1 }],
  extension: [{ value: "command.git", count: 1 }],
  rule: [{ value: "command.git.fetch", count: 1 }],
  disposition: [{ value: "allow", count: 1 }],
  execution_status: [{ value: "allowed_unconfirmed", count: 1 }],
  prompt_status: [{ value: "not_prompted", count: 1 }],
  proof_level: [{ value: "pre_hook", count: 1 }],
  latency: [{ value: "le_2_ms", count: 1 }],
};

async function mountCommandFixture(page: Page): Promise<{
  activityQueries: string[];
  feedbackLabels: string[];
  setActivityDelay: (milliseconds: number) => void;
  setActivityMode: (mode: "normal" | "empty" | "error") => void;
  setActivityCount: (count: number) => void;
}> {
  const activityQueries: string[] = [];
  const feedbackLabels: string[] = [];
  let activityDelay = 0;
  let activityMode: "normal" | "empty" | "error" = "normal";
  let activityCount = 1;
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    let body: unknown = {};
    if (path.includes("/initialize")) body = { auth_token: "e2e-command-token" };
    else if (path.endsWith("/runtime")) body = freeStateSnapshot;
    else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) body = defaultSettingsPayload;
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/command-activity/events")) {
      await route.fulfill({ status: 200, contentType: "text/event-stream", body: "" });
      return;
    } else if (path.endsWith("/command-activity/analytics")) {
      body = {
        schema_version: "guard.command-activity-api.v1",
        window: { from: "2026-04-21", through: "2026-07-19", days: 90 },
        scope: {
          dimension: url.searchParams.get("dimension"),
          dimension_value: url.searchParams.get("dimension_value"),
        },
        commands_checked: activityCount,
        trend: [{ day: "2026-07-18", count: 0 }, { day: "2026-07-19", count: 1 }],
        dimensions,
        dimension_breakdowns_scope: "global",
        feedback: [],
        health: { status: "healthy", dropped_events: 0, persistence_errors: 0, last_error_class: null, last_error_at: null },
      };
    } else if (path.endsWith("/command-extensions")) {
      body = { schema_version: 2, source: "built-in", items: [], next_cursor: null };
    } else if (path.endsWith("/command-activity/feedback")) {
      const payload = request.postDataJSON() as { activity_id: string; label: string };
      feedbackLabels.push(payload.label);
      body = { schema_version: "guard.command-activity-api.v1", activity_id: payload.activity_id, label: payload.label, created_at: activity.occurred_at, updated_at: activity.occurred_at, changed: true };
    } else if (path.endsWith("/command-activity")) {
      activityQueries.push(url.search);
      if (activityDelay > 0) await new Promise((resolve) => setTimeout(resolve, activityDelay));
      if (activityMode === "error") {
        await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: SECRET_SENTINEL }) });
        return;
      }
      body = {
        schema_version: "guard.command-activity-api.v1",
        items: activityMode === "empty"
          ? []
          : Array.from({ length: activityCount }, (_, index) => ({
              ...activity,
              activity_id: `activity:${index.toString().padStart(3, "0")}`,
              harness: url.searchParams.get("harness") ?? activity.harness,
            })),
        next_cursor: null,
      };
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  return {
    activityQueries,
    feedbackLabels,
    setActivityDelay: (milliseconds) => {
      activityDelay = milliseconds;
    },
    setActivityMode: (mode) => {
      activityMode = mode;
    },
    setActivityCount: (count) => {
      activityCount = count;
    },
  };
}

test("Commands evidence renders with zero receipts and keeps private fields hidden", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  const fixture = await mountCommandFixture(page);
  await page.goto(`/evidence?view=commands&${DAEMON}`);
  await expect(page.getByRole("heading", { name: "Commands" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "Allowed; execution not confirmed" })).toBeVisible();
  const trend = page.getByRole("img", { name: /2026-07-18: 0; 2026-07-19: 1$/ });
  await expect(trend).toBeVisible();
  await expect.poll(() => trend.evaluate((element) => {
    const zeroDay = element.children.item(element.children.length - 2)?.firstElementChild as HTMLElement | null;
    return zeroDay?.style.height ?? null;
  })).toBe("0%");
  await expect.poll(() => trend.locator(":scope > div > div").last().evaluate((element) => {
    const durationSeconds = Number.parseFloat(getComputedStyle(element).transitionDuration);
    return Number.isFinite(durationSeconds) ? durationSeconds : 1;
  })).toBeLessThanOrEqual(0.001);
  const detailsButton = page.getByRole("button", { name: "Details" });
  await detailsButton.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("complementary", { name: "Command activity detail" })).toBeFocused();
  await expect(page.getByText("Other recorded reason")).toBeVisible();
  await expect(page.getByText(SECRET_SENTINEL)).toHaveCount(0);
  await page.getByRole("button", { name: "Should not have interrupted" }).click();
  await expect.poll(() => fixture.feedbackLabels).toEqual(["should_not_have_interrupted"]);
  await page.getByRole("button", { name: "Close command activity detail" }).click();
  await expect(detailsButton).toBeFocused();
  await expect.poll(() => new URL(page.url()).searchParams.get("guardDaemon")).toBe("http://127.0.0.1:4175");
});

test("Commands exposes bounded empty and error states", async ({ page }) => {
  const fixture = await mountCommandFixture(page);
  fixture.setActivityMode("empty");
  await page.goto(`/evidence?view=commands&${DAEMON}`);
  await expect(page.getByRole("heading", { name: "No command activity" })).toBeVisible();

  fixture.setActivityMode("error");
  await page.reload();
  await expect(page.getByText("Command activity is unavailable.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Try again" }).first()).toBeVisible();
  await expect(page.getByText(SECRET_SENTINEL)).toHaveCount(0);
});

test("Commands remains responsive with a full 100-row page", async ({ context, page }, testInfo) => {
  const fixture = await mountCommandFixture(page);
  fixture.setActivityCount(100);
  await context.tracing.start({ screenshots: true, snapshots: true });
  await page.goto(`/evidence?view=commands&${DAEMON}`);
  const detailsButtons = page.getByRole("button", { name: "Details" });
  await expect(detailsButtons).toHaveCount(100);
  const lastButton = detailsButtons.last();
  const interactionMs = await lastButton.evaluate(async (button) => {
    const started = performance.now();
    button.click();
    await new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));
    return performance.now() - started;
  });
  await expect(page.getByRole("complementary", { name: "Command activity detail" })).toBeVisible();
  expect(interactionMs).toBeLessThan(250);
  await context.tracing.stop({ path: testInfo.outputPath("command-activity-100-row-trace.zip") });
});

test("Commands deep links keep active filters visible outside aggregate options", async ({ page }) => {
  const fixture = await mountCommandFixture(page);
  await page.goto(`/evidence?view=commands&command_harness=cursor&command_extension=command.custom&command_rule=command.custom.read&command_status=attempted&${DAEMON}`);
  await expect.poll(() => new URL(page.url()).searchParams.get("command_harness")).toBe("cursor");
  await expect.poll(() => new URL(page.url()).searchParams.get("command_extension")).toBe("command.custom");
  await expect.poll(() => new URL(page.url()).searchParams.get("command_rule")).toBe("command.custom.read");
  await expect(page.getByRole("combobox", { name: "App", exact: true })).toHaveValue("cursor");
  await expect(page.getByRole("combobox", { name: "Extension", exact: true })).toHaveValue("command.custom");
  await expect(page.getByRole("combobox", { name: "Rule", exact: true })).toHaveValue("command.custom.read");
  await expect(page.getByRole("combobox", { name: "Execution proof" })).toHaveValue("attempted");
  await expect.poll(() => fixture.activityQueries.some((query) => {
    const params = new URLSearchParams(query);
    return params.get("harness") === "cursor"
      && params.get("extension_id") === "command.custom"
      && params.get("rule_id") === "command.custom.read"
      && params.get("execution_status") === "attempted";
  })).toBe(true);
});

test("App Commands view enforces exact harness scope", async ({ page }) => {
  const fixture = await mountCommandFixture(page);
  await page.goto(`/apps/codex?tab=activity&activity=commands&${DAEMON}`);
  await expect(page.getByRole("tab", { name: "Command protection" })).toBeVisible();
  await expect(page.getByText("Global only")).toHaveCount(3);
  await expect.poll(() => fixture.activityQueries.some((query) => new URLSearchParams(query).get("harness") === "codex")).toBe(true);
  await expect(page.getByRole("combobox", { name: "App", exact: true })).toHaveCount(0);
  fixture.setActivityDelay(250);
  await page.getByRole("combobox", { name: "Execution proof" }).selectOption("confirmed_success");
  await expect(page.getByLabel("Loading command activity", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Command activity records")).toHaveCount(0);
  await expect(page.getByText("Summary and trend totals do not include every active filter below.")).toBeVisible();
  await expect.poll(() => new URL(page.url()).searchParams.get("command_status")).toBe("confirmed_success");
  await expect.poll(() => new URL(page.url()).searchParams.has("command_harness")).toBe(false);
  fixture.activityQueries.length = 0;
  await page.evaluate(() => {
    window.history.pushState({}, "", "/apps/claude?tab=activity&activity=commands&guardDaemon=http://127.0.0.1:4175");
    window.dispatchEvent(new PopStateEvent("popstate"));
  });
  await expect(page.getByRole("heading", { name: "Claude" })).toBeVisible();
  await expect.poll(() => fixture.activityQueries.length > 0).toBe(true);
  await expect.poll(() => fixture.activityQueries.every((query) => new URLSearchParams(query).get("harness") === "claude")).toBe(true);
});

test("Home card is conditional and Commands stays usable on mobile", async ({ page }) => {
  await mountCommandFixture(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`/?${DAEMON}`);
  await expect(page.getByRole("heading", { name: "Commands checked" })).toBeVisible();
  await page.getByRole("button", { name: "Open command activity" }).click();
  await expect(page).toHaveURL(/view=commands/);
  await expect(page.getByRole("heading", { name: "Commands" })).toBeVisible();
  const records = page.getByLabel("Command activity records");
  await expect(records).toBeVisible();
  const tableLayout = await records.evaluate((element) => {
    const scroller = element.firstElementChild as HTMLElement;
    const table = scroller.querySelector("table");
    return { clientWidth: scroller.clientWidth, scrollWidth: scroller.scrollWidth, tableWidth: table?.getBoundingClientRect().width ?? 0 };
  });
  expect(tableLayout.tableWidth).toBeGreaterThan(700);
  expect(tableLayout.scrollWidth).toBeGreaterThan(tableLayout.clientWidth);
  await expect.poll(
    () => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth),
  ).toBeLessThanOrEqual(1);
});
