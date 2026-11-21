import { expect, test } from "@playwright/test";

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const origin = requiredEnvironment("GUARD_INSTALLED_ORIGIN");
const session = requiredEnvironment("GUARD_INSTALLED_DASHBOARD_SESSION");
const policyPhase = process.env.GUARD_INSTALLED_POLICY_PHASE ?? "read-only";
const approvalPassword = process.env.GUARD_INSTALLED_APPROVAL_PASSWORD ?? "";
const extensionId = "command.api-gateway";
const permissionId = "command.api-gateway.permission.delete";
const governedRuleId = "command.api-gateway.delete";
const REVIEW_TIMEOUT_MS = 60_000;

async function installSession(page: import("@playwright/test").Page) {
  await page.addInitScript(({ daemon, token }) => {
    sessionStorage.setItem("guard-token", token);
    sessionStorage.setItem("guardDaemon", daemon);
  }, { daemon: origin, token: session });
}

async function expectSecretSafeUrl(page: import("@playwright/test").Page) {
  expect(page.url()).not.toContain(session);
  if (approvalPassword) expect(page.url()).not.toContain(approvalPassword);
  expect(page.url()).not.toContain("guard-token");
  expect(page.url()).not.toContain("#");
}

async function expectNoHorizontalOverflow(page: import("@playwright/test").Page) {
  const report = await page.evaluate(() => {
    const root = document.documentElement;
    const overflow = root.scrollWidth - root.clientWidth;
    const offenders = [...document.querySelectorAll<HTMLElement>("body *")]
      .map((element) => {
        const rect = element.getBoundingClientRect();
        const style = getComputedStyle(element);
        return {
          tag: element.tagName.toLowerCase(),
          className: typeof element.className === "string" ? element.className.slice(0, 180) : "",
          text: (element.innerText || "").replace(/\s+/g, " ").trim().slice(0, 100),
          left: Math.round(rect.left),
          right: Math.round(rect.right),
          width: Math.round(rect.width),
          display: style.display,
          position: style.position,
        };
      })
      .filter((item) => item.display !== "none" && (item.right > root.clientWidth + 4 || item.left < -4))
      .sort((a, b) => Math.max(b.right - root.clientWidth, -b.left) - Math.max(a.right - root.clientWidth, -a.left))
      .slice(0, 12);
    return {
      overflow,
      clientWidth: root.clientWidth,
      scrollWidth: root.scrollWidth,
      innerWidth: window.innerWidth,
      outerWidth: window.outerWidth,
      screenWidth: window.screen.width,
      rootFontSize: getComputedStyle(root).fontSize,
      lgMatches: window.matchMedia("(min-width: 64rem)").matches,
      offenders,
    };
  });
  expect(report, JSON.stringify(report, null, 2)).toMatchObject({ overflow: expect.any(Number) });
  expect(report.overflow, JSON.stringify(report, null, 2)).toBeLessThanOrEqual(4);
}

async function openPolicy(page: import("@playwright/test").Page) {
  await installSession(page);
  await page.goto(`/extensions/${extensionId}?tab=policy`);
  await expectSecretSafeUrl(page);
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();
  await expect(page.locator("#extension-policy-heading")).toHaveText("Protection settings");
  return page.locator(`[data-permission-id="${permissionId}"]`);
}

type EffectiveControls = {
  revision: number;
  controls: Array<{ target: { kind: string; target_id: string }; state: string }>;
  projection?: { permissions: Array<{ permission_id: string; effective_state: string; local_state: string }> };
};

/**
 * The revision the panel says it saved. Waiting for a response to the apply is
 * a race: the workspace also refreshes the effective controls while the
 * mutation is in flight, and that earlier read answers 200 with the revision
 * from before the save. The toast appears only once the save has landed.
 */
async function appliedRevision(page: import("@playwright/test").Page): Promise<number> {
  const toast = page.getByTestId("extension-policy-applied-toast");
  try {
    // The first save on a freshly started daemon writes the authority and
    // recomputes the projection, which takes longer than the default wait.
    await expect(toast).toContainText(/Applied · revision \d+/, { timeout: 60_000 });
  } catch (error) {
    // A refused save renders in the workspace alert. Report the sentence the
    // operator would have read, so a regression names the failure instead of
    // leaving a bare timeout.
    const alert = await page.getByRole("alert").first().innerText().catch(() => "<no alert rendered>");
    throw new Error(`applying the reviewed change failed: ${alert}`, { cause: error });
  }
  const text = await toast.innerText();
  const revision = Number(/Applied · revision (\d+)/.exec(text)?.[1]);
  expect(Number.isInteger(revision)).toBe(true);
  return revision;
}

/** The controls the daemon serves, read back through the dashboard's own session. */
async function readEffective(page: import("@playwright/test").Page): Promise<EffectiveControls> {
  return page.evaluate(async () => {
    const token = sessionStorage.getItem("guard-token") ?? "";
    const response = await fetch("/v1/extension-controls/effective", { headers: { "X-Guard-Dashboard-Session": token } });
    if (!response.ok) throw new Error(`effective controls answered ${response.status}`);
    return await response.json() as {
      revision: number;
      controls: Array<{ target: { kind: string; target_id: string }; state: string }>;
      projection?: { permissions: Array<{ permission_id: string; effective_state: string; local_state: string }> };
    };
  });
}

async function authenticateAndApply(page: import("@playwright/test").Page, count = 1): Promise<EffectiveControls> {
  expect(approvalPassword.length).toBeGreaterThan(20);
  const dialog = page.getByRole("dialog", { name: `Review and apply ${count} protection setting change${count === 1 ? "" : "s"}` });
  await expect(dialog).toBeVisible({ timeout: REVIEW_TIMEOUT_MS });
  await dialog.getByLabel("Approval password").fill(approvalPassword);
  await dialog.getByRole("button", { name: `Apply ${count} reviewed change${count === 1 ? "" : "s"}` }).click();
  const revision = await appliedRevision(page);
  const effective = await readEffective(page);
  // What the operator was told was saved has to be what the daemon now serves.
  expect(effective.revision).toBe(revision);
  return effective;
}

/**
 * Distance from the toolbar to the tool count, sampled in one frame. The
 * catalog scrolls inside the workspace, so a document- or viewport-relative
 * top moves whenever clicking the trigger scrolls it into view, which is not
 * a layout shift. The gap between the two elements only changes if the filter
 * popover actually pushes the catalog down.
 */
async function catalogCountOffset(page: import("@playwright/test").Page): Promise<number> {
  return page.evaluate(() => {
    const toolbar = document.querySelector('[data-testid="catalog-filters"]');
    const count = document.querySelector('[data-testid="catalog-tool-count"]');
    if (!toolbar || !count) throw new Error("the catalog toolbar or tool count is missing");
    return count.getBoundingClientRect().top - toolbar.getBoundingClientRect().top;
  });
}

async function openDeveloperDetails(page: import("@playwright/test").Page) {
  await page.getByRole("tab", { name: "Technical details" }).click();
  await expect(page.getByRole("tab", { name: "Technical details" })).toHaveAttribute("aria-selected", "true");
  await page.getByTestId("protection-more-detail").locator("summary").click();
  await expect(page.getByRole("heading", { name: "Detections" })).toBeVisible();
}

test("installed Protection Center keeps canonical routes and real-daemon inspection", async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const extensionResponses: { path: string; status: number }[] = [];
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (/^\/v[12]\/extension-controls/.test(url.pathname)) extensionResponses.push({ path: url.pathname, status: response.status() });
  });

  await page.addInitScript(({ daemon, token }) => {
    sessionStorage.setItem("guard-token", token);
    sessionStorage.setItem("guardDaemon", daemon);
  }, { daemon: origin, token: session });

  await page.goto("/extensions");
  await expectSecretSafeUrl(page);
  await expect(page.getByRole("heading", { name: "Extensions", level: 1 })).toBeVisible();
  // The first catalog read on a fresh installed daemon prepares the native
  // runtime, so it gets longer than the default wait. If it never loads, the
  // failure names what the workspace showed and what the daemon answered.
  await expect(page.getByRole("heading", { name: "All tools" })).toBeAttached({ timeout: 30_000 }).catch(async (error: unknown) => {
    const workspace = await page.getByTestId("extensions-workspace").innerText({ timeout: 2_000 }).catch(() => "<absent>");
    throw new Error(
      `${String(error)}\nworkspace: ${workspace.slice(0, 600)}\nextension-controls: ${JSON.stringify(extensionResponses)}\npage errors: ${JSON.stringify(runtimeErrors)}`,
    );
  });
  await expect(page.getByRole("heading", { name: "All tools" })).toBeVisible();
  await expect(page.getByTestId("catalog-tool-count")).toHaveText(/^[1-9]\d* tools$/);
  await expect(page.getByRole("button", { name: /Git/ }).first()).toBeVisible();
  await expect(page.getByPlaceholder(/Search any command Guard watches/)).toBeVisible();
  await expect(page.getByTestId("catalog-filters")).toBeVisible();
  // The filter popover stays collapsed until asked for, and the catalog list
  // does not move when it opens.
  const filtersTrigger = page.getByTestId("catalog-filters").getByRole("button", { name: /^Filters/ });
  await expect(page.getByRole("group", { name: "Trust" })).toBeHidden();
  await expect(page.getByRole("group", { name: "Kind" })).toBeHidden();
  await expect(page.getByRole("group", { name: "Area" })).toBeHidden();
  const toolCountOffset = await catalogCountOffset(page);
  await filtersTrigger.click();
  await expect(filtersTrigger).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByRole("group", { name: "Trust" })).toBeVisible();
  await expect(page.getByRole("group", { name: "Kind" })).toBeVisible();
  await expect(page.getByRole("group", { name: "Area" })).toBeVisible();
  await expect(page.getByTestId("catalog-tool-count")).toHaveText(/^[1-9]\d* tools$/);
  const toolCountOffsetOpen = await catalogCountOffset(page);
  expect(Math.abs(toolCountOffsetOpen - toolCountOffset)).toBeLessThanOrEqual(1);
  const externalFilter = page.getByTestId("catalog-filters").getByRole("button", { name: /^External,/ });
  await expect(externalFilter).toBeVisible();
  await externalFilter.click();
  await expect(externalFilter).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("catalog-filter-count")).toHaveText(/^\d+ of \d+ tools$/);
  await expect(page.getByRole("button", { name: "Remove External trust filter" })).toBeVisible();
  // A pointer outside the popover dismisses it without clearing the selection.
  // The popover overlays the catalog, so the outside target must be above it.
  await page.getByRole("heading", { name: "Extensions", level: 1 }).click();
  await expect(page.getByRole("group", { name: "Trust" })).toBeHidden();
  await expect(filtersTrigger).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByRole("button", { name: "Remove External trust filter" })).toBeVisible();
  // "f" reopens the popover from anywhere on the page, like "/" focuses search.
  await page.getByTestId("catalog-tool-count").click();
  await page.keyboard.press("f");
  await expect(filtersTrigger).toHaveAttribute("aria-expanded", "true");
  await page.getByRole("button", { name: "Clear all 1 filter" }).click();
  await expect(externalFilter).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByRole("button", { name: "Remove External trust filter" })).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(filtersTrigger).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByRole("heading", { name: /^(Protected|Finish setup|Needs repair|Protection limited|Emergency Lockdown active)$/ })).toBeVisible();
  // The landing is a catalog: no activity feed, no cloud status box, no health
  // check, and no second search surface.
  await expect(page.getByRole("heading", { name: "Recent decisions" })).toHaveCount(0);
  await expect(page.getByRole("complementary", { name: "Cloud continuity" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Run health check" })).toHaveCount(0);
  await expect(page.getByText("Browse all extensions")).toHaveCount(0);
  await expect(page.getByText("Check protection health")).toHaveCount(0);

  await page.screenshot({ path: testInfo.outputPath("installed-extension-catalog.png"), fullPage: true });
  await page.screenshot({ path: testInfo.outputPath("installed-protection-center-simple.png"), fullPage: false });

  // One search box reaches patterns across tools and matches tool names.
  await page.getByPlaceholder(/Search any command Guard watches/).fill("git");
  await expect(page.getByLabel(/patterns/).first()).toBeVisible();
  await expect(page.getByLabel("Matching tools")).toBeVisible();
  await page.getByPlaceholder(/Search any command Guard watches/).fill("");
  await expect(page.getByLabel("Matching tools")).toHaveCount(0);

  for (const width of [320, 390, 720, 800, 1024, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    // The shell deliberately animates desktop sidebar padding. Validate the
    // settled responsive layout rather than sampling that 200 ms transition.
    await page.waitForTimeout(250);
    await expect(page.getByRole("heading", { name: "Extensions", level: 1 })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    const screenshotName = width === 720
      ? "installed-protection-center-simple-zoom-200.png"
      : `installed-protection-center-simple-${width}.png`;
    await page.screenshot({ path: testInfo.outputPath(screenshotName), fullPage: false });
  }
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.waitForTimeout(250);

  for (const moduleId of ["command.git", "command.github", "command.package.node"]) {
    await page.goto(`/extensions/${moduleId}`);
    await expectSecretSafeUrl(page);
    await expect(page.getByTestId("protection-module-detail")).toBeVisible();
    await openDeveloperDetails(page);
    await expect(
      page.locator("dt", { hasText: "Extension ID" }).locator("xpath=following-sibling::dd[1]").getByText(moduleId, { exact: true }),
    ).toBeVisible();
    await expect(page.getByRole("heading", { name: "Detections" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Protection setting identifiers" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Test Lab" })).toHaveCount(0);
    await expect(page.getByRole("tab", { name: "Activity" })).toHaveCount(1);
  }

  await page.goto("/extensions/command.git");
  await expectSecretSafeUrl(page);
  await page.getByRole("tab", { name: "Activity" }).click();
  await expect(page.getByRole("heading", { name: "Recent Extension decisions" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Test Lab", exact: true })).toBeVisible();
  const labCommand = "git reset --hard HEAD~1";
  await page.getByLabel("Command to check").fill(labCommand);
  const labResponsePromise = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.pathname === "/v1/extension-controls/test" && response.status() === 200;
  });
  await page.getByRole("button", { name: "Check safely" }).click();
  const labResponse = await labResponsePromise;
  const labPayload = await labResponse.json() as { decision?: unknown };
  expect(JSON.stringify(labPayload)).not.toContain(labCommand);
  const labDecision = labPayload.decision;
  expect(["allowed", "ask-first", "blocked"]).toContain(labDecision);
  const expectedLabTitle = {
    allowed: "Guard would allow this",
    "ask-first": "Guard would ask first",
    blocked: "Guard would block this",
  }[labDecision as "allowed" | "ask-first" | "blocked"];
  await expect(
    page.getByRole("status").filter({ hasText: expectedLabTitle }),
  ).toContainText(expectedLabTitle);
  await expect(page.getByRole("alert")).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("installed-protection-test-lab.png"), fullPage: true });
  await openDeveloperDetails(page);
  await expect(page.getByRole("table").getByText("Destructive Git reset", { exact: true })).toBeVisible();
  await expect(page.getByText("command.git.hard-reset", { exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("installed-extension-rule-detail.png"), fullPage: true });

  await page.getByTestId("protection-module-detail").getByRole("button", { name: "Extensions" }).click();
  await expect(page.getByRole("heading", { name: "Extensions", level: 1 })).toBeVisible();
  await page.goBack();
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();

  await expect.poll(() => extensionResponses.length).toBeGreaterThan(1);
  // The installed daemon serves the bounded v2 catalog; the full v1 catalog is never read.
  expect(extensionResponses.some((response) => response.path === "/v2/extension-controls/catalog/index" && response.status === 200)).toBe(true);
  expect(extensionResponses.some((response) => response.path === "/v2/extension-controls/catalog/extensions/command.git/rules" && response.status === 200)).toBe(true);
  expect(extensionResponses.some((response) => response.path === "/v1/extension-controls/catalog")).toBe(false);
  expect(extensionResponses.some((response) => response.path === "/v1/extension-controls/effective" && response.status === 200)).toBe(true);
  // A daemon still preparing its catalog read model answers a v2 catalog read
  // with 503 and the dashboard retries it; every other answer is a success.
  expect(extensionResponses.every((response) =>
    (response.status >= 200 && response.status < 300)
    || response.status === 304
    || (response.status === 503 && response.path.startsWith("/v2/extension-controls/catalog/")),
  )).toBe(true);
  expect(runtimeErrors).toEqual([]);
});

test("installed dashboard previews and proof-applies a permission block", async ({ page }, testInfo) => {
  test.skip(policyPhase !== "apply", "policy apply phase runs before the deliberate daemon restart");
  test.setTimeout(180_000);
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  const row = await openPolicy(page);
  await expect(row).toBeVisible();
  await expect(row.getByRole("radio", { name: "Block" })).toBeEnabled();
  await row.getByRole("radio", { name: "Block" }).click();
  await expect(page.getByText("1 unsaved setting change.")).toBeVisible();
  await page.getByRole("button", { name: "Review 1 change" }).click();
  const review = page.getByRole("dialog", { name: "Review and apply 1 protection setting change" });
  // The first preview on a freshly started daemon computes the real outcome
  // from the native runtime, which takes longer than the default wait.
  await expect(review).toBeVisible({ timeout: REVIEW_TIMEOUT_MS });
  await expect(review.getByText("Protection review", { exact: true }).first()).toBeVisible();
  await review.getByText("Developer details", { exact: true }).click();
  await expect(review.getByText(governedRuleId, { exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("installed-extension-policy-preview.png"), fullPage: true });

  const effective = await authenticateAndApply(page);
  expect(effective.revision).toBeGreaterThan(0);
  expect(effective.controls).toContainEqual({ target: { kind: "permission", target_id: permissionId }, state: "disabled" });
  expect(effective.projection?.permissions.find((permission) => permission.permission_id === permissionId)?.effective_state).toBe("blocked");
  await expectSecretSafeUrl(page);
  const appliedRow = await openPolicy(page);
  await expect(appliedRow.getByRole("radio", { name: "Block" })).toHaveAttribute("aria-checked", "true");
  await page.screenshot({ path: testInfo.outputPath("installed-extension-policy-applied.png"), fullPage: true });
  expect(runtimeErrors).toEqual([]);
});

test("permission authority persists across daemon restart and can be proof-restored", async ({ page }, testInfo) => {
  test.skip(policyPhase !== "verify", "persistence phase runs only after the workflow restarts the real daemon");
  test.setTimeout(180_000);
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  const row = await openPolicy(page);
  await expect(row.getByRole("radio", { name: "Block" })).toHaveAttribute("aria-checked", "true");
  await page.screenshot({ path: testInfo.outputPath("installed-extension-policy-persisted.png"), fullPage: true });

  await row.getByRole("radio", { name: "Recommended" }).click();
  await page.getByRole("button", { name: "Review 1 change" }).click();
  await expect(page.getByRole("dialog", { name: "Review and apply 1 protection setting change" })).toBeVisible({ timeout: REVIEW_TIMEOUT_MS });
  const effective = await authenticateAndApply(page);
  expect(effective.controls.some((control) => control.target.kind === "permission" && control.target.target_id === permissionId)).toBe(false);
  const restoredRow = await openPolicy(page);
  await expect(restoredRow.getByRole("radio", { name: "Recommended" })).toHaveAttribute("aria-checked", "true");
  await page.screenshot({ path: testInfo.outputPath("installed-extension-policy-restored.png"), fullPage: true });
  await expectSecretSafeUrl(page);
  expect(runtimeErrors).toEqual([]);
});
