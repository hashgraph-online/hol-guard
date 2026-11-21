import { expect, expectNoErrorBoundary, test } from "./fixtures";
import {
  actionsCheckedToday,
  appName,
  appsList,
  expectedActivityLine,
  expectedDailyStory,
  expectedHero,
  expectedPackageProtection,
  formatCount,
  heroRegion,
  homeSeed,
  loadLiveHome,
  packageRegion,
  statTile,
} from "./home-helpers";

// Home keys "today" by the browser's local day; the daemon keys it by UTC.
test.use({ timezoneId: "UTC" });

test.describe("Home against the live daemon", () => {
  test("the hero headline, badge and call to action follow the daemon's protection and queue state", async ({ page, state }) => {
    const live = await loadLiveHome(state);
    const hero = expectedHero(live);
    await page.goto("/");
    await expect(page.getByRole("navigation", { name: "Guard dashboard" }).getByRole("link", { name: "Home", exact: true })).toHaveAttribute(
      "aria-current",
      "page",
    );
    // Protection shows "Checking" for a few seconds while proofs load, so
    // wait for the settled headline.
    const region = heroRegion(page);
    await expect(region.getByRole("heading", { level: 1, name: hero.headline })).toBeVisible();
    await expect(region.getByText(hero.badge, { exact: true })).toBeVisible();
    await expect(region.getByRole("button", { name: hero.cta, exact: true })).toBeVisible();
    await expect(region.getByRole("button", { name: "How Guard works", exact: true })).toBeVisible();
    await expectNoErrorBoundary(page);
    expect(page.url()).not.toContain("guard-token");
  });

  test("the hero call to action opens the area it names", async ({ page, state }) => {
    const hero = expectedHero(await loadLiveHome(state));
    await page.goto("/");
    await heroRegion(page).getByRole("button", { name: hero.cta, exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe(hero.target);
    await expectNoErrorBoundary(page);
  });

  test("hero facts count connected apps, today's checks and the last decision", async ({ page, state }) => {
    const live = await loadLiveHome(state);
    const hero = expectedHero(live);
    await page.goto("/");
    const region = heroRegion(page);
    await expect(region.getByRole("heading", { level: 1, name: hero.headline })).toBeVisible();

    const facts = region.getByRole("listitem");
    // Apps in the hero equal the apps listed as active further down.
    const activeApps = appsList(page).getByRole("listitem").filter({ hasText: "Active" });
    const activeCount = await activeApps.count();
    const seeded = homeSeed(state);
    expect(activeCount).toBeGreaterThanOrEqual(seeded.activeApps.length);
    const connected = live.queued > 0 || hero.badge === "Protected" ? "protected" : "connected";
    await expect(facts.filter({ hasText: /apps? (protected|connected)$/ })).toHaveText(
      `${formatCount(activeCount)} app${activeCount === 1 ? "" : "s"} ${connected}`,
    );
    if (live.queued === 0) {
      const checked = actionsCheckedToday(live);
      // The seed records three decisions "now", so today is never empty.
      expect(checked).toBeGreaterThanOrEqual(Object.keys(seeded.receipts).length);
      await expect(facts.filter({ hasText: /checked today$/ })).toHaveText(
        `${formatCount(checked)} action${checked === 1 ? "" : "s"} checked today`,
      );
      await expect(facts.filter({ hasText: /^Last decision / })).toHaveCount(1);
    } else {
      await expect(facts.filter({ hasText: "Your apps keep working while you decide" })).toHaveCount(1);
    }
  });

  test("the stats row matches the daemon's pending, app and receipt counts", async ({ page, state }) => {
    const live = await loadLiveHome(state);
    await page.goto("/");
    await expect(page.getByText("Your Guard stats", { exact: true })).toBeVisible();
    const activeCount = await appsList(page).getByRole("listitem").filter({ hasText: "Active" }).count();
    await expect(statTile(page, "Pending", formatCount(live.queued))).toBeVisible();
    await expect(statTile(page, "Apps", formatCount(activeCount))).toBeVisible();
    await expect(statTile(page, "Recorded", formatCount(live.runtime.receipt_count))).toBeVisible();
    expect(live.runtime.receipt_count).toBeGreaterThanOrEqual(Object.keys(homeSeed(state).receipts).length);
  });

  test("apps at a glance shows seeded apps as active or needing setup", async ({ page, state }) => {
    const seeded = homeSeed(state);
    // Grok comes from the supply chain seed; the others from this one.
    const active = ["claude-code", "cursor", ...(state.seeded.supply_chain ? [String(state.seeded.supply_chain.app)] : [])];
    expect(seeded.activeApps).toEqual(expect.arrayContaining(["claude-code", "cursor"]));
    await page.goto("/");
    const list = appsList(page);
    for (const harness of active) {
      await expect(list.getByRole("button", { name: `${appName(harness)} Active`, exact: true }), harness).toBeVisible();
    }
    for (const harness of seeded.inactiveApps) {
      await expect(list.getByRole("button", { name: `${appName(harness)} Needs setup`, exact: true }), harness).toBeVisible();
    }
    // Apps that need setup sort below every active app.
    const rows = await list.getByRole("listitem").allInnerTexts();
    const position = (name: string) => rows.findIndex((row) => row.includes(name));
    for (const harness of seeded.inactiveApps) {
      for (const running of active) expect(position(appName(harness))).toBeGreaterThan(position(appName(running)));
    }
  });

  test("an app row opens that app's detail page", async ({ page, state }) => {
    const seeded = homeSeed(state);
    await page.goto("/");
    await appsList(page).getByRole("button", { name: "Cursor Active", exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe("/apps/cursor");
    await expect(page.getByRole("navigation", { name: "Breadcrumb" })).toContainText("Cursor");
    await expect(page.getByRole("tablist", { name: "App detail tabs" })).toBeVisible();

    // An app that was never connected offers setup instead of protection.
    const inactive = seeded.inactiveApps[0];
    expect(inactive).toBe("copilot");
    await page.goto("/");
    await appsList(page).getByRole("button", { name: `${appName(inactive)} Needs setup`, exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe(`/apps/${inactive}`);
    await expect(page.getByRole("heading", { level: 2, name: "Copilot needs setup" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Connect app", exact: true })).toBeVisible();
  });

  test("package manager protection mirrors the daemon's supply chain snapshot", async ({ page, state }) => {
    const live = await loadLiveHome(state);
    const expected = expectedPackageProtection(live.runtime);
    // The seed installs shims, so Guard knows the managers but none run protected.
    expect(expected.managers.length).toBeGreaterThan(0);
    await page.goto("/");
    const region = packageRegion(page);
    await expect(region.getByText(expected.label, { exact: true })).toBeVisible();
    if (expected.shimDir) await expect(region.getByText(expected.shimDir, { exact: true })).toBeVisible();
    if (expected.tag) await expect(region.getByText(expected.tag, { exact: true })).toBeVisible();

    // The coverage table can start open or shut depending on how many managers there are.
    const show = region.getByRole("button", { name: "Show all managers", exact: true });
    if (await show.isVisible()) await show.click();
    await expect(region.getByRole("button", { name: "Hide managers", exact: true })).toHaveAttribute("aria-expanded", "true");
    const table = region.getByRole("table", { name: "Package manager coverage" });
    for (const manager of expected.managers) {
      const status = expected.protectedManagers.includes(manager) ? "Protected" : "Unprotected";
      await expect(table.getByRole("row", { name: `${manager} ${status}`, exact: true }), manager).toBeVisible();
    }
    await expect(table.getByRole("rowgroup").getByRole("row")).toHaveCount(expected.managers.length);

    await region.getByRole("button", { name: "Hide managers", exact: true }).click();
    await expect(table).toHaveCount(0);
    await expect(region.getByRole("button", { name: "Show all managers", exact: true })).toHaveAttribute("aria-expanded", "false");
  });

  test("package manager protection links lead to the supply chain area", async ({ page, state }) => {
    const expected = expectedPackageProtection((await loadLiveHome(state)).runtime);
    const entry = {
      unprotected: ["Set up protection", "View supply chain"],
      unknown: ["Set up protection", "View supply chain"],
      staged: ["Finish activation"],
      partial: ["View full supply chain status"],
      protected: [],
    }[expected.status];
    expect(entry.length, `no way into supply chain for a ${expected.status} machine`).toBeGreaterThan(0);
    for (const name of entry) {
      await page.goto("/");
      await packageRegion(page).getByRole("button", { name, exact: true }).click();
      await expect.poll(() => new URL(page.url()).pathname, name).toBe("/supply-chain");
      await expect(page.getByRole("heading", { level: 1, name: "Supply Chain" })).toBeVisible();
      }
  });

  test("today's summary and recent protection come from the recorded receipts", async ({ page, state }) => {
    const live = await loadLiveHome(state);
    await page.goto("/");
    await expect(page.getByRole("button", { name: /^(Today so far|Needs your attention)/ })).toBeVisible();
    const story = expectedDailyStory(live);
    expect(story, "the seed records decisions today").not.toBeNull();
    await expect(page.getByText(story as string, { exact: true })).toBeVisible();

    // Recent protection lists the latest three decisions, newest first.
    const latest = live.runtime.latest_receipts.slice(0, 3);
    const heading = page.getByText("Recent protection", { exact: true });
    await expect(heading).toBeVisible();
    for (const receipt of latest) {
      const line = expectedActivityLine(receipt);
      if (line) await expect(page.getByText(line, { exact: true }), receipt.receipt_id).toBeVisible();
    }
  });

  test("activity and insights links open the matching evidence views", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Review today's activity", exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname + new URL(page.url()).search).toBe("/evidence?time=today");
    await expectNoErrorBoundary(page);

    await page.goto("/");
    await page.getByRole("button", { name: "See all insights →", exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname + new URL(page.url()).search).toBe("/evidence?view=insights");
    await expectNoErrorBoundary(page);
  });

  test("the cloud card reports local-only protection and offers sync only with nothing to review", async ({
    page,
    state,
  }) => {
    const live = await loadLiveHome(state);
    expect(live.runtime.cloud_state).toBe("local_only");
    await page.goto("/");
    await expect(page.getByText("Cloud sync", { exact: true })).toBeVisible();
    await expect(page.getByText("Offline, free", { exact: true })).toBeVisible();
    const openSync = page.getByRole("button", { name: "Open sync settings", exact: true });
    // Home keeps the cloud upsell out of the way while reviews are waiting.
    // The full suite seeds the inbox, so this branch is the one CI takes.
    if (live.queued > 0) {
      await expect(openSync).toHaveCount(0);
      return;
    }
    await openSync.click();
    await expect.poll(() => new URL(page.url()).pathname).toBe("/settings");
    await expectNoErrorBoundary(page);
  });

  test("the how-it-works walkthrough collapses and the hero button reopens it", async ({ page }) => {
    await page.goto("/");
    const section = page.getByRole("region", { name: "How Guard protects you" });
    const toggle = section.getByRole("button", { name: /^How Guard protects you/ });
    await expect(toggle).toHaveAttribute("aria-expanded", /^(true|false)$/);
    // Start from a known state, whatever the receipt count made the default.
    if ((await toggle.getAttribute("aria-expanded")) === "true") await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(section.getByRole("list", { name: "Sample session" })).toHaveCount(0);

    await heroRegion(page).getByRole("button", { name: "How Guard works", exact: true }).click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(section.getByRole("list", { name: "Sample session" })).toBeVisible();
    await expect(section.getByText("A demonstration. Nothing runs on your computer.")).toBeVisible();
  });

  test("the shortcuts and share dialogs open and close without leaving Home", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Show shortcuts", exact: true }).click();
    const help = page.getByRole("dialog", { name: "Keyboard shortcuts help" });
    await expect(help).toBeVisible();
    await expect(help.getByRole("heading", { level: 2, name: "Keyboard shortcuts" })).toBeVisible();
    await help.getByRole("button", { name: "Close help", exact: true }).click();
    await expect(help).toHaveCount(0);

    // Sharing needs Guard Cloud, so a local-only machine is asked to connect.
    await page.getByRole("button", { name: "Share your Guard stats publicly", exact: true }).click();
    const share = page.getByRole("dialog", { name: "Share your Guard stats" });
    await expect(share.getByText("Connection required", { exact: true })).toBeVisible();
    await expect(share.getByRole("button", { name: "Connect Guard Cloud", exact: true })).toBeVisible();
    await share.getByRole("button", { name: "Close", exact: true }).click();
    await expect(share).toHaveCount(0);
    expect(new URL(page.url()).pathname).toBe("/");
  });
});
