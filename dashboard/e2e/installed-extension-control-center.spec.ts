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
const expectedExtensionCount = 77;

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

async function openDeveloperDetails(page: import("@playwright/test").Page) {
  await page.getByRole("tab", { name: "Technical details" }).click();
  await expect(page.getByRole("tab", { name: "Technical details" })).toHaveAttribute("aria-selected", "true");
  await page.getByTestId("protection-more-detail").locator("summary").click();
  await expect(page.getByRole("heading", { name: "Detections" })).toBeVisible();
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
  await expect(page.getByRole("heading", { name: "All tools" })).toBeVisible();
  await expect(page.getByText(`${expectedExtensionCount} tools`)).toBeVisible();
  await expect(page.getByRole("button", { name: /Git/ }).first()).toBeVisible();
  await expect(page.getByPlaceholder(/Search any command Guard watches/)).toBeVisible();
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
  }

  await openDeveloperDetails(page);
  await expect(page.getByText("command.api-gateway", { exact: true })).toBeVisible();
  await expect(page.getByText(governedRuleId, { exact: true })).toBeVisible();
  expect(runtimeErrors).toEqual([]);
  expect(extensionResponses.every((entry) => entry.status < 400), JSON.stringify(extensionResponses, null, 2)).toBe(true);
});

test("installed dashboard previews and proof-applies a permission block", async ({ page }) => {
  test.skip(policyPhase !== "apply", "apply phase only");
  const permission = await openPolicy(page);
  await permission.getByRole("radio", { name: "Block" }).check();
  await expect(page.getByText("1 unsaved change")).toBeVisible();
  await page.getByRole("button", { name: "Review changes" }).click();
  const payload = await authenticateAndApply(page);
  expect(payload.controls.some((control) => control.target.kind === "permission" && control.target.target_id === permissionId && control.state === "block")).toBe(true);
  expect(payload.projection?.permissions.some((permission) => permission.permission_id === permissionId && permission.effective_state === "block")).toBe(true);
});

test("permission authority persists across daemon restart and can be proof-restored", async ({ page }) => {
  test.skip(policyPhase !== "verify", "verify phase only");
  const permission = await openPolicy(page);
  await expect(permission.getByRole("radio", { name: "Block" })).toBeChecked();
  await permission.getByRole("radio", { name: "Inherit" }).check();
  await page.getByRole("button", { name: "Review changes" }).click();
  const payload = await authenticateAndApply(page);
  expect(payload.controls.some((control) => control.target.kind === "permission" && control.target.target_id === permissionId)).toBe(false);
});
