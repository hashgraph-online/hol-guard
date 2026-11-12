import { expect, expectNoErrorBoundary, daemonApi, test } from "./fixtures";

type RuntimeSnapshot = {
  pending_count: number;
  receipt_count: number;
  cloud_state?: string | null;
  cloud_sync_health?: { state: string } | null;
};

// The figure only claims a sync state the daemon reports; anything else reads
// "Unavailable". A pairing reads "On" only while current sync health is landing.
const PAIRED_ACTIVE_LABEL: Record<string, string> = {
  healthy: "On",
  pending: "On",
  failed: "Not syncing",
  degraded: "Not syncing",
  stale: "Not syncing",
  disabled: "Off",
};

function expectedSyncLabel(runtime: RuntimeSnapshot): string {
  if (runtime.cloud_state === "paired_active") {
    return PAIRED_ACTIVE_LABEL[runtime.cloud_sync_health?.state ?? ""] ?? "Unavailable";
  }
  if (runtime.cloud_state === "paired_waiting") return "First sync";
  if (runtime.cloud_state === "local_only") return "Off";
  return "Unavailable";
}

// Every outbound link the About page may show: name -> destination. A change
// here is a change to what the page sends people to, so review it as one.
const EXTERNAL_LINKS: ReadonlyArray<{ name: string; href: string; count: number }> = [
  { name: "Read Guard docs", href: "https://hol.org/guard/docs", count: 1 },
  { name: "View source", href: "https://github.com/hashgraph-online/hol-guard", count: 1 },
  { name: "Get started", href: "https://hol.org/guard/install", count: 1 },
  { name: "Guard Cloud", href: "https://hol.org/guard", count: 1 },
  { name: "CI docs", href: "https://hol.org/guard/docs/plugin-scanner/report-formats-and-ci", count: 1 },
  { name: "Explore partner programs", href: "https://hol.org", count: 1 },
  { name: "Learn about affiliates", href: "https://hol.org/guard/affiliates", count: 1 },
];

const FORBIDDEN_PARAMS = ["guard-token", "guardDaemon", "workspace", "device", "install", "user", "referral", "ref"];

test.describe("About against the live daemon", () => {
  test("renders the trust contract, data map, standards map and pathways", async ({ page }) => {
    await page.goto("/about");
    await expect(page.getByRole("navigation", { name: "Guard dashboard" }).getByRole("link", { name: "About", exact: true })).toHaveAttribute(
      "aria-current",
      "page",
    );
    await expect(page.getByRole("heading", { level: 1, name: "About HOL Guard" })).toBeVisible();
    await expectNoErrorBoundary(page);

    const main = page.getByRole("main");
    await expect(main.getByRole("heading", { level: 2, name: "Trust Contract" })).toBeVisible();
    for (const card of [
      "Local decisions stay local",
      "Receipts are inspectable",
      "Cloud sync is optional",
      "Built around open standards",
      "Registries",
      "Identity",
      "Receipts",
      "Privacy",
      "Payments",
      "Communication",
      "Protect locally",
      "Sync with your team",
      "Validate packages in CI",
    ]) {
      await expect(main.getByRole("heading", { level: 3, name: card, exact: true }), card).toBeVisible();
    }
    // Each section names itself with a real heading rather than a mono label
    // above one, so the page can be navigated by its sections.
    for (const section of [
      "Where your data goes",
      "Open standards map",
      "Choose your path",
      "Standards partner program",
      "Affiliate starter kit",
    ]) {
      await expect(main.getByRole("heading", { level: 2, name: section, exact: true }), section).toBeVisible();
    }
    // The page promises no remote calls on first render and shows no controls.
    await expect(main.getByRole("button")).toHaveCount(0);
  });

  test("Fig. 1 shows this daemon's version, sync state, receipts and pending count", async ({ page, state }) => {
    const runtime = await daemonApi<RuntimeSnapshot>(state, "/v1/runtime");
    const update = await daemonApi<{ current_version: string }>(state, "/v1/update/status");
    await page.goto("/about");
    await expect(page.getByRole("heading", { level: 1, name: "About HOL Guard" })).toBeVisible();

    // Each readout on the figure is a label next to its value, so its text reads label+value.
    const chip = (label: string, value: string) => page.getByRole("main").getByText(`${label}${value}`, { exact: true });
    await expect(chip("Guard version", update.current_version)).toBeVisible();
    await expect(chip("Sync", expectedSyncLabel(runtime))).toBeVisible();
    await expect(chip("Receipts", new Intl.NumberFormat("en-US").format(runtime.receipt_count))).toBeVisible();
    await expect(
      chip("Local protection", runtime.pending_count > 0 ? `${runtime.pending_count} pending` : "Active"),
    ).toBeVisible();
    // The seeded pages feed real receipts, so an empty count would mean the
    // figure reads nothing from the daemon.
    expect(runtime.receipt_count).toBeGreaterThan(0);
    expect(update.current_version).toMatch(/^\d+\.\d+\.\d+/);
  });

  test("every external link is https, opens in a new tab safely and carries no session or device data", async ({ page, state }) => {
    await page.goto("/about");
    const main = page.getByRole("main");
    await expect(main.getByRole("heading", { level: 1, name: "About HOL Guard" })).toBeVisible();

    for (const link of EXTERNAL_LINKS) {
      const anchors = main.getByRole("link", { name: link.name, exact: true });
      await expect(anchors, link.name).toHaveCount(link.count);
      for (let index = 0; index < link.count; index += 1) {
        const anchor = anchors.nth(index);
        await expect(anchor).toHaveAttribute("href", link.href);
        await expect(anchor).toHaveAttribute("target", "_blank");
        await expect(anchor).toHaveAttribute("rel", /\bnoopener\b/);
        await expect(anchor).toHaveAttribute("rel", /\bnoreferrer\b/);
      }
    }

    // Sweep every anchor on the page, not only the ones named above, so a new
    // link cannot slip in with a token, a local address or a tracking param.
    const hrefs = await main.getByRole("link").evaluateAll((nodes) => nodes.map((node) => node.getAttribute("href") ?? ""));
    expect(hrefs.length).toBe(EXTERNAL_LINKS.reduce((total, link) => total + link.count, 0));
    for (const href of hrefs) {
      const url = new URL(href);
      expect(url.protocol, href).toBe("https:");
      expect(url.username + url.password, href).toBe("");
      expect(url.hash, href).toBe("");
      expect(url.search, href).toBe("");
      expect(url.hostname, href).toMatch(/^(hol\.org|github\.com)$/);
      for (const param of FORBIDDEN_PARAMS) expect(url.searchParams.has(param), `${param} in ${href}`).toBe(false);
      expect(href).not.toContain(state.session);
      expect(href).not.toContain(state.daemonToken);
      expect(href).not.toContain(new URL(state.origin).host);
    }
  });

  test("the address bar never carries the session", async ({ page, state }) => {
    await page.goto("/about");
    await expect(page.getByRole("heading", { level: 1, name: "About HOL Guard" })).toBeVisible();
    expect(page.url()).not.toContain("guard-token");
    expect(page.url()).not.toContain(state.session);
  });

  test("the affiliate starter kit states its terms", async ({ page }) => {
    await page.goto("/about");
    const main = page.getByRole("main");
    await expect(main.getByRole("heading", { level: 2, name: "Affiliate starter kit" })).toBeVisible();
    await expect(main.getByText("Commission", { exact: true })).toBeVisible();
    await expect(main.getByText("25%", { exact: true })).toBeVisible();
    await expect(main.getByText("Duration", { exact: true })).toBeVisible();
    await expect(main.getByText("12 months", { exact: true })).toBeVisible();
    await expect(main.getByText("Cookie window", { exact: true })).toBeVisible();
    await expect(main.getByText("120 days", { exact: true })).toBeVisible();
  });
});
