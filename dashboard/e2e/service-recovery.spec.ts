import { expect, test, type Page } from "@playwright/test";

const DAEMON = "guardDaemon=http://127.0.0.1:4781";

async function mountOfflineDashboard(page: Page, desktopEmbedded = false): Promise<string[]> {
  const requestedPaths: string[] = [];
  await page.route("**/v1/**", async (route) => {
    requestedPaths.push(new URL(route.request().url()).pathname);
    await route.abort();
  });
  await page.goto(`/?${DAEMON}${desktopEmbedded ? "&desktop_embed=1" : ""}`);
  await expect(page.getByTestId("service-recovery-panel")).toBeVisible();
  return requestedPaths;
}

test("browser-only recovery shows local steps without a dead-service restart action", async ({ page }) => {
  await page.addInitScript(() => {
    delete (window as unknown as { __HOL_GUARD_RECOVERY__?: unknown }).__HOL_GUARD_RECOVERY__;
    delete (window as unknown as { __HOL_GUARD_RECOVERY_BRIDGE__?: unknown }).__HOL_GUARD_RECOVERY_BRIDGE__;
  });
  const requestedPaths = await mountOfflineDashboard(page);

  await expect(page.getByText("A browser tab cannot restart Guard through a service that is not responding.")).toBeVisible();
  await expect(page.getByTestId("service-recovery-instructions")).toBeVisible();
  await expect(page.getByTestId("service-recovery-command")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Open recovery", exact: true })).toHaveCount(0);

  await page.getByRole("button", { name: "Retry connection", exact: true }).click();
  await expect(page.getByTestId("service-recovery-panel")).toBeVisible();
  expect(requestedPaths.every((pathname) => !pathname.includes("recovery"))).toBe(true);
});

test("desktop_embed is only a display hint and cannot create a native recovery capability", async ({ page }) => {
  await page.addInitScript(() => {
    delete (window as unknown as { __HOL_GUARD_RECOVERY__?: unknown }).__HOL_GUARD_RECOVERY__;
    delete (window as unknown as { __HOL_GUARD_RECOVERY_BRIDGE__?: unknown }).__HOL_GUARD_RECOVERY_BRIDGE__;
  });
  await mountOfflineDashboard(page, true);

  await expect(page.getByTestId("service-recovery-instructions")).toBeVisible();
  await expect(page.getByRole("button", { name: "Open recovery", exact: true })).toHaveCount(0);
});

test("host-injected native capability performs one visible handoff and does not claim restart", async ({ page }) => {
  let handoffPath = "";
  await page.route("**/__hol_guard_recovery__", async (route) => {
    handoffPath = new URL(route.request().url()).pathname;
    await route.abort();
  });
  await page.addInitScript(() => {
    const openRecovery = () => {
      const target = new URL("/__hol_guard_recovery__", window.location.origin);
      window.location.assign(target.toString());
    };
    Object.defineProperty(window, "__HOL_GUARD_RECOVERY_BRIDGE__", {
      configurable: false,
      enumerable: false,
      value: Object.freeze({
        schema: "hol-guard-dashboard-recovery.v1",
        protocol: "hol-guard-recovery.v1",
        capabilities: Object.freeze(["open_recovery"]),
        installMode: "desktop-bundled",
        openRecovery,
      }),
      writable: false,
    });
  });
  const requestedPaths = await mountOfflineDashboard(page, true);

  const openRecovery = page.getByRole("button", { name: "Open recovery", exact: true });
  await expect(openRecovery).toBeVisible();
  await expect(page.getByText("Confirm Restart Guard there; this tab did not restart the service.")).toHaveCount(0);
  await openRecovery.click();
  await expect.poll(() => handoffPath).toBe("/__hol_guard_recovery__");
  expect(requestedPaths.every((pathname) => !pathname.includes("recovery"))).toBe(true);
});
