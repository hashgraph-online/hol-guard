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

async function installSession(page: import("@playwright/test").Page) {
  await page.addInitScript(({ daemon, token }) => {
    sessionStorage.setItem("guard-token", token);
    sessionStorage.setItem("guardDaemon", daemon);
  }, { daemon: origin, token: session });
}

async function expectSecretSafeUrl(page: import("@playwright/test").Page) {
  expect(page.url()).not.toContain(session);
  expect(page.url()).not.toContain(approvalPassword);
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

async function authenticateAndApply(page: import("@playwright/test").Page, count = 1) {
  expect(approvalPassword.length).toBeGreaterThan(20);
  const dialog = page.getByRole("dialog", { name: `Review and apply ${count} protection setting change${count === 1 ? "" : "s"}` });
  await expect(dialog).toBeVisible();
  await dialog.getByLabel("Approval password").fill(approvalPassword);
  const effectiveResponse = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.pathname === "/v1/extension-controls/effective" && response.status() === 200;
  });
  await dialog.getByRole("button", { name: `Apply ${count} reviewed change${count === 1 ? "" : "s"}` }).click();
  const response = await effectiveResponse;
  return response.json() as Promise<{
    revision: number;
    controls: Array<{ target: { kind: string; target_id: string }; state: string }>;
    projection?: { permissions: Array<{ permission_id: string; effective_state: string; local_state: string }> };
  }>;
}

async function selectDensity(page: import("@playwright/test").Page, density: "Simple" | "Advanced" | "Developer") {
  const radio = page.getByRole("radio", { name: density });
  if (!(await radio.isVisible())) {
    await page.getByTestId("protection-more-detail").locator("summary").click();
    await expect(radio).toBeVisible();
  }
  await radio.click();
  await expect(radio).toHaveAttribute("aria-checked", "true");
}

test("installed Protection Center keeps canonical routes and real-daemon inspection", async ({ page }, testInfo) => {
  const extensionResponses: { path: string; status: number }[] = [];
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (url.pathname.startsWith("/v1/extension-controls")) extensionResponses.push({ path: url.pathname, status: response.status() });
  });

  await page.addInitScript(({ daemon, token }) => {
    sessionStorage.setItem("guard-token", token);
    sessionStorage.setItem("guardDaemon", daemon);
  }, { daemon: origin, token: session });

  await page.goto("/extensions");
  await expectSecretSafeUrl(page);
  await expect(page.getByRole("heading", { name: "Extensions", level: 1 })).toBeVisible();
  await expect(page.getByRole("heading", { name: /^(In use|Ready)$/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Guard is watching the tools your agent uses." })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Recent decisions" })).toBeVisible();
  const cloudContinuity = page.getByRole("complementary", { name: "Cloud continuity" });
  await expect(cloudContinuity).toBeVisible();
  await expect(cloudContinuity).not.toContainText("while Cloud status is checked");
  await expect(cloudContinuity).toContainText("Local protection is active");
  await expect(page.getByRole("heading", { name: /^(Protected|Finish setup|Needs repair|Protection limited|Emergency Lockdown active)$/ })).toBeVisible();

  await page.getByText("Check protection health", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Protection health check" })).toBeVisible();
  const healthCheck = page.getByRole("button", { name: "Run health check" });
  await healthCheck.click();
  await expect(page.getByRole("status").filter({ hasText: /Protection health check passed|need attention/ })).toBeVisible();

  await page.getByText("Browse all extensions", { exact: true }).click();
  const advancedFilters = page.getByRole("button", { name: /Advanced filters/ });
  await expect(advancedFilters).toHaveAttribute("aria-expanded", "false");
  await advancedFilters.click();
  await expect(advancedFilters).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByPlaceholder(/Search by name, command, or risk/)).toBeVisible();

  const setupSteps = page.getByRole("button", { name: "Show setup steps" });
  if (await setupSteps.count()) {
    await setupSteps.click();
    await expect(page.getByText("Finish local enrollment", { exact: true })).toBeVisible();
  }

  await selectDensity(page, "Simple");
  await page.screenshot({ path: testInfo.outputPath("installed-extension-catalog.png"), fullPage: true });
  await page.screenshot({ path: testInfo.outputPath("installed-protection-center-simple.png"), fullPage: false });
  await selectDensity(page, "Advanced");
  await page.screenshot({ path: testInfo.outputPath("installed-protection-center-advanced.png"), fullPage: false });
  await selectDensity(page, "Developer");
  await expect(page.getByText("Developer policy details")).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("installed-protection-center-developer.png"), fullPage: false });
  await selectDensity(page, "Simple");

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
    await selectDensity(page, "Developer");
    await page.getByText("Developer details", { exact: true }).click();
    await expect(
      page.locator("dt", { hasText: "Extension ID" }).locator("xpath=following-sibling::dd[1]").getByText(moduleId, { exact: true }),
    ).toBeVisible();
    await expect(page.getByRole("heading", { name: "Detections" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Protection setting identifiers" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Test Lab" })).toHaveCount(0);
    await expect(page.getByRole("tab", { name: "Activity" })).toHaveCount(0);
  }

  await page.goto("/extensions/command.git");
  await expectSecretSafeUrl(page);
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
  await selectDensity(page, "Developer");
  await page.getByText("Developer details", { exact: true }).click();
  await expect(page.getByRole("table").getByText("Destructive Git reset", { exact: true })).toBeVisible();
  await expect(page.getByText("command.git.hard-reset", { exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("installed-extension-rule-detail.png"), fullPage: true });

  await page.getByTestId("protection-module-detail").getByRole("button", { name: "Extensions" }).click();
  await expect(page.getByRole("heading", { name: "Extensions", level: 1 })).toBeVisible();
  await page.goBack();
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();

  await expect.poll(() => extensionResponses.length).toBeGreaterThan(1);
  expect(extensionResponses.some((response) => response.path === "/v1/extension-controls/catalog" && response.status === 200)).toBe(true);
  expect(extensionResponses.some((response) => response.path === "/v1/extension-controls/effective" && response.status === 200)).toBe(true);
  expect(extensionResponses.every((response) => response.status >= 200 && response.status < 300)).toBe(true);
  expect(runtimeErrors).toEqual([]);
});

test("installed dashboard previews and proof-applies a permission block", async ({ page }, testInfo) => {
  test.skip(policyPhase !== "apply", "policy apply phase runs before the deliberate daemon restart");
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  const row = await openPolicy(page);
  await expect(row).toBeVisible();
  await expect(row.getByRole("radio", { name: "Block" })).toBeEnabled();
  await row.getByRole("radio", { name: "Block" }).click();
  await expect(page.getByText("1 unsaved setting change.")).toBeVisible();
  await page.getByRole("button", { name: "Review 1 change" }).click();
  const review = page.getByRole("dialog", { name: "Review and apply 1 protection setting change" });
  await expect(review.getByText("Protection review", { exact: true }).first()).toBeVisible();
  await review.getByText("Developer details", { exact: true }).click();
  await expect(review.getByText(governedRuleId, { exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("installed-extension-policy-preview.png"), fullPage: true });

  const effective = await authenticateAndApply(page);
  expect(effective.revision).toBeGreaterThan(0);
  await expect(page.getByTestId("extension-policy-applied-toast")).toContainText(`Applied · revision ${effective.revision}`);
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
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  const row = await openPolicy(page);
  await expect(row.getByRole("radio", { name: "Block" })).toHaveAttribute("aria-checked", "true");
  await page.screenshot({ path: testInfo.outputPath("installed-extension-policy-persisted.png"), fullPage: true });

  await row.getByRole("radio", { name: "Recommended" }).click();
  await page.getByRole("button", { name: "Review 1 change" }).click();
  await expect(page.getByRole("dialog", { name: "Review and apply 1 protection setting change" })).toBeVisible();
  const effective = await authenticateAndApply(page);
  expect(effective.controls.some((control) => control.target.kind === "permission" && control.target.target_id === permissionId)).toBe(false);
  const restoredRow = await openPolicy(page);
  await expect(restoredRow.getByRole("radio", { name: "Recommended" })).toHaveAttribute("aria-checked", "true");
  await page.screenshot({ path: testInfo.outputPath("installed-extension-policy-restored.png"), fullPage: true });
  await expectSecretSafeUrl(page);
  expect(runtimeErrors).toEqual([]);
});
