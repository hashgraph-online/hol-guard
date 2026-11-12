import { readFileSync } from "node:fs";
import { expect, expectNoErrorBoundary, test } from "./fixtures";
import {
  actionsTable,
  bodyRows,
  numberAfter,
  openRow,
  receiptFacts,
  receiptsUrl,
  rowByName,
} from "./evidence-helpers";

const count = (n: number) => `${n} action${n === 1 ? "" : "s"}`;

test.describe("evidence: all actions", () => {
  test("summarizes the seeded receipts and pages the list", async ({ page, state }) => {
    const facts = receiptFacts(state);
    await page.goto(receiptsUrl(facts));
    await expectNoErrorBoundary(page);

    await expect(page.getByRole("heading", { name: "All actions", level: 1 })).toBeVisible();
    const strip = page.getByLabel("Evidence summary").filter({ hasText: "Apps seen" });
    const apps = Object.keys(facts.by_harness).length;
    await expect(strip).toContainText(
      new RegExp(`Total\\s*${facts.total}\\s*Stopped\\s*${facts.by_disposition.blocked}\\s*Apps seen\\s*${apps}`),
    );
    await expect(page.getByText(count(facts.total), { exact: true })).toBeVisible();

    // Newest first, one page of rows, then Load more brings in the rest.
    const table = actionsTable(page);
    await expect(bodyRows(table)).toHaveCount(facts.page_size);
    await expect(bodyRows(table).first()).toContainText(facts.newest_name);
    await page.getByRole("button", { name: "Load more" }).click();
    await expect(bodyRows(table)).toHaveCount(facts.total);
    await expect(bodyRows(table).last()).toContainText(facts.oldest_name);
    await expect(page.getByRole("button", { name: "Load more" })).toHaveCount(0);
  });

  test("decision filter narrows the list and the URL", async ({ page, state }) => {
    const facts = receiptFacts(state);
    await page.goto(receiptsUrl(facts));
    const decision = page.getByRole("combobox", { name: "Decision filter" });
    const table = actionsTable(page);

    await decision.selectOption({ label: "Stopped" });
    await expect(page.getByText(count(facts.by_disposition.blocked), { exact: true })).toBeVisible();
    await expect(bodyRows(table)).toHaveCount(facts.by_disposition.blocked);
    for (const key of ["env", "rm", "ssh"]) {
      await expect(rowByName(table, facts.featured[key].name)).toBeVisible();
    }
    await expect(page).toHaveURL(/decision=block/);

    await decision.selectOption({ label: "Reviewed" });
    await expect(bodyRows(table)).toHaveCount(facts.by_disposition.reviewed);
    // review, require-reapproval and sandbox-required all count as reviewed.
    for (const key of ["fetch", "npm", "hidden", "skill"]) {
      await expect(rowByName(table, facts.featured[key].name)).toBeVisible();
    }
    await expect(rowByName(table, facts.featured.env.name)).toHaveCount(0);

    await decision.selectOption({ label: "Allowed" });
    await expect(page.getByText(count(facts.by_disposition.allowed), { exact: true })).toBeVisible();
    // A warning is still an allowed action.
    await page.getByRole("button", { name: "Load more" }).click();
    await expect(rowByName(table, facts.featured.mcp.name)).toBeVisible();
    await expect(rowByName(table, facts.featured.env.name)).toHaveCount(0);
  });

  test("time filter keeps recent actions and empties on a day with none", async ({ page, state }) => {
    const facts = receiptFacts(state);
    await page.goto(receiptsUrl(facts));
    const time = page.getByRole("combobox", { name: "Time period" });

    await time.selectOption({ label: "Last 7 days" });
    await expect(page.getByText(count(facts.within_7_days), { exact: true })).toBeVisible();
    await expect(page).toHaveURL(/time=last7d/);
    await time.selectOption({ label: "Last 30 days" });
    await expect(page.getByText(count(facts.within_30_days), { exact: true })).toBeVisible();
    await time.selectOption({ label: "All time" });
    await expect(page.getByText(count(facts.total), { exact: true })).toBeVisible();

    // Receipts are seeded days back, so none landed today.
    await time.selectOption({ label: "Today" });
    await expect(page.getByText("No actions match")).toBeVisible();
    await expect(actionsTable(page)).toHaveCount(0);
  });

  test("app, category and scope filters combine and clear", async ({ page, state }) => {
    const facts = receiptFacts(state);
    await page.goto(receiptsUrl(facts));
    const table = actionsTable(page);

    await page.getByRole("button", { name: "Toggle more filters" }).click();
    await page.getByRole("combobox", { name: "App filter" }).selectOption({ label: "Cursor" });
    await expect(page.getByText(count(facts.by_harness.cursor), { exact: true })).toBeVisible();
    await expect(page).toHaveURL(/harness=cursor/);
    await expect(page.getByRole("button", { name: "Remove filter: Cursor" })).toBeVisible();

    await page.getByRole("combobox", { name: "Category filter" }).selectOption({ label: "Destructive" });
    await expect(bodyRows(table)).toHaveCount(1);
    await expect(rowByName(table, /rm -rf \.\/dist/)).toBeVisible();
    await expect(page).toHaveURL(/category=destructive/);

    // Removing one chip leaves the others in place.
    await page.getByRole("button", { name: "Remove filter: Cursor" }).click();
    await expect(page).not.toHaveURL(/harness=/);
    await expect(page).toHaveURL(/category=destructive/);
    await expect(bodyRows(table)).toHaveCount(1);

    await page.getByRole("button", { name: "Clear all", exact: true }).click();
    await expect(page).not.toHaveURL(/category=|sourceScope=/);
    await expect(page.getByText("evidence-e2e")).toHaveCount(0);
    // Without the scope filter the list holds at least the seeded rows.
    await expect(page.getByText(/^\d+ total$/)).toBeVisible();

    // A different scope matches nothing.
    await page.goto(receiptsUrl({ ...facts, source_scope: "evidence-e2e-missing" }));
    await expect(page.getByText("No actions match")).toBeVisible();
  });

  test("row shortcuts filter by app and category", async ({ page, state }) => {
    const facts = receiptFacts(state);
    await page.goto(receiptsUrl(facts));
    const table = actionsTable(page);

    await rowByName(table, facts.featured.env.name).getByRole("button", { name: "Filter by app Codex" }).click();
    await expect(page.getByText(count(facts.by_harness.codex), { exact: true })).toBeVisible();
    await expect(page).toHaveURL(/harness=codex/);

    await rowByName(table, facts.featured.env.name)
      .getByRole("button", { name: "Filter by category Secret read" })
      .click();
    await expect(page.getByText(count(facts.by_category.secret), { exact: true })).toBeVisible();
    await expect(bodyRows(table)).toHaveCount(facts.by_category.secret);
    await expect(rowByName(table, facts.featured.ssh.name)).toBeVisible();
    await expect(page).toHaveURL(/category=secret/);
  });

  test("search matches names, apps and reports an empty result", async ({ page, state }) => {
    const facts = receiptFacts(state);
    await page.goto(receiptsUrl(facts));
    const search = page.getByRole("searchbox", { name: "Search evidence" });
    const table = actionsTable(page);

    await search.fill("base64");
    await expect(bodyRows(table)).toHaveCount(1);
    await expect(rowByName(table, facts.featured.hidden.name)).toBeVisible();
    await expect(page).toHaveURL(/search=base64/);

    // Search also covers the app id and the receipt id.
    await search.fill("opencode");
    await expect(page.getByText(count(facts.by_harness.opencode), { exact: true })).toBeVisible();
    await search.fill(facts.featured.ssh.receipt_id);
    await expect(bodyRows(table)).toHaveCount(1);
    await expect(rowByName(table, facts.featured.ssh.name)).toBeVisible();

    await search.fill("no-such-evidence-anywhere");
    await expect(page.getByText("No actions match")).toBeVisible();
    await expect(page.getByRole("button", { name: 'Remove filter: "no-such-evidence-anywhere"' })).toBeVisible();
    await page.getByRole("button", { name: 'Remove filter: "no-such-evidence-anywhere"' }).click();
    await expect(search).toHaveValue("");
    await expect(actionsTable(page)).toBeVisible();
  });

  test("column headers sort the list", async ({ page, state }) => {
    const facts = receiptFacts(state);
    await page.goto(receiptsUrl(facts));
    const table = actionsTable(page);
    const first = bodyRows(table).first();

    await expect(table.getByRole("button", { name: "Sort by Time, descending" })).toBeVisible();
    await table.getByRole("button", { name: "Sort by Time, descending" }).click();
    await expect(table.getByRole("button", { name: "Sort by Time, ascending" })).toBeVisible();
    await expect(first).toContainText(facts.oldest_name);
    await expect(page).toHaveURL(/sort=oldest/);

    await table.getByRole("button", { name: "Sort by What happened" }).click();
    await expect(first).toContainText(facts.featured.fetch.name);
    await expect(page).toHaveURL(/sort=artifact/);

    await table.getByRole("button", { name: "Sort by App" }).click();
    await expect(first).toContainText("Claude Code");
    await expect(page).toHaveURL(/sort=app/);

    await table.getByRole("button", { name: "Sort by Category" }).click();
    await expect(first).toContainText(facts.featured.sqlite.name);
    await expect(page).toHaveURL(/sort=category/);

    await table.getByRole("button", { name: "Sort by Decision" }).click();
    await expect(first).toContainText(facts.featured.write.name);
    await expect(page).toHaveURL(/sort=decision/);
  });

  test("filters, sort and the open action survive a reload", async ({ page, state }) => {
    const facts = receiptFacts(state);
    await page.goto(receiptsUrl(facts));
    await page.getByRole("combobox", { name: "Decision filter" }).selectOption({ label: "Stopped" });
    await page.getByRole("searchbox", { name: "Search evidence" }).fill("read");
    await actionsTable(page).getByRole("button", { name: "Sort by Time, descending" }).click();
    await openRow(actionsTable(page), facts.featured.ssh.name);
    await expect(page).toHaveURL(new RegExp(`selected=${facts.featured.ssh.receipt_id}`));
    await expect(page).toHaveURL(/decision=block/);
    await expect(page).toHaveURL(/search=read/);
    await expect(page).toHaveURL(/sort=oldest/);

    await page.reload();
    await expect(page.getByRole("combobox", { name: "Decision filter" })).toHaveValue("block");
    await expect(page.getByRole("searchbox", { name: "Search evidence" })).toHaveValue("read");
    await expect(actionsTable(page).getByRole("button", { name: "Sort by Time, ascending" })).toBeVisible();
    // "read" within stopped actions: the .env and id_ed25519 reads.
    await expect(bodyRows(actionsTable(page))).toHaveCount(2);
    await expect(bodyRows(actionsTable(page)).first()).toContainText(facts.featured.ssh.name);
    const dialog = page.getByRole("dialog", { name: "Evidence action detail" });
    await expect(dialog).toContainText(facts.featured.ssh.name);
  });

  test("detail panel explains a stopped shell command", async ({ page, state }) => {
    const facts = receiptFacts(state);
    await page.goto(receiptsUrl(facts));
    await openRow(actionsTable(page), /rm -rf \.\/dist/);

    const detail = page.getByRole("dialog", { name: "Evidence action detail" });
    await expect(detail).toBeVisible();
    await expect(page).toHaveURL(new RegExp(`selected=${facts.featured.rm.receipt_id}`));
    await expect(detail).toContainText("Shell command");
    await expect(detail).toContainText("rm -rf ./dist");
    await expect(detail).toContainText("Cursor");
    await expect(detail).toContainText("Guard blocked it");
    await expect(detail).toContainText("Next safe step");
    await expect(detail.getByRole("list", { name: "Evidence timeline" })).toContainText("Action received");
    await expect(detail.getByRole("list", { name: "Evidence timeline" })).toContainText("Stopped");

    await detail.getByRole("button", { name: "Technical details" }).click();
    await expect(detail).toContainText(facts.featured.rm.receipt_id);
    await expect(detail).toContainText(facts.source_scope);
    await expect(detail.getByRole("button", { name: "Copy receipt ID to clipboard" })).toBeVisible();

    await detail.getByRole("button", { name: "Close detail panel" }).click();
    await expect(detail).toHaveCount(0);
    await expect(page).not.toHaveURL(/selected=/);
  });

  test("detail panel names review states from a deep link", async ({ page, state }) => {
    const facts = receiptFacts(state);
    const detail = page.getByRole("dialog", { name: "Evidence action detail" });
    const cases: Array<[string, string]> = [
      ["fetch", "Needs review"],
      ["hidden", "Needs fresh approval"],
      ["skill", "Sandbox required"],
      ["mcp", "Allowed with warning"],
    ];
    for (const [key, label] of cases) {
      const item = facts.featured[key];
      await page.goto(receiptsUrl(facts, `selected=${item.receipt_id}`));
      await expect(detail).toContainText(item.name);
      await expect(detail).toContainText(label);
    }
  });

  test("export downloads the filtered rows as CSV and JSON", async ({ page, state }) => {
    const facts = receiptFacts(state);
    await page.goto(receiptsUrl(facts));
    await page.getByRole("button", { name: "Export evidence" }).click();
    const drawer = page.getByRole("dialog", { name: "Export evidence" });
    await expect(drawer).toContainText(`${facts.total} records`);

    const csvDownload = page.waitForEvent("download");
    await drawer.getByRole("button", { name: "Download CSV" }).click();
    const csv = await csvDownload;
    expect(csv.suggestedFilename()).toMatch(/^hol-guard-evidence.*\.csv$/);
    const csvText = readFileSync(await csv.path(), "utf8");
    expect(csvText.split("\n")[0]).toContain("policy_decision");
    expect(csvText).toContain(facts.featured.env.name);
    expect(csvText).toContain(facts.featured.ssh.name);
    expect(csvText.trim().split("\n")).toHaveLength(facts.total + 1);
    await expect(drawer.getByText("Export downloaded successfully.")).toBeVisible();

    const jsonDownload = page.waitForEvent("download");
    await drawer.getByRole("button", { name: "Download JSON" }).click();
    const json = JSON.parse(readFileSync(await (await jsonDownload).path(), "utf8"));
    expect(json.total_rows).toBe(facts.total);
    expect(json.items).toHaveLength(facts.total);
    expect(json.items.map((item: { artifact_name: string }) => item.artifact_name)).toContain(facts.featured.npm.name);

    // Export follows the active filter.
    await drawer.getByRole("button", { name: "Close export drawer" }).click();
    await page.getByRole("combobox", { name: "Decision filter" }).selectOption({ label: "Stopped" });
    await expect(page.getByText(count(facts.by_disposition.blocked), { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Export evidence" }).click();
    await expect(drawer).toContainText(`${facts.by_disposition.blocked} records`);
    const stoppedDownload = page.waitForEvent("download");
    await drawer.getByRole("button", { name: "Download JSON" }).click();
    const stopped = JSON.parse(readFileSync(await (await stoppedDownload).path(), "utf8"));
    expect(stopped.total_rows).toBe(facts.by_disposition.blocked);
    expect(stopped.items.map((item: { policy_decision: string }) => item.policy_decision)).toEqual(
      Array(facts.by_disposition.blocked).fill("block"),
    );
  });
});

test.describe("evidence: other views", () => {
  test("tabs switch views and keep the URL in sync", async ({ page, state }) => {
    const facts = receiptFacts(state);
    await page.goto(receiptsUrl(facts));
    for (const [tab, heading, view] of [
      ["Commands", "Commands", "commands"],
      ["Insights", "Insights", "insights"],
      ["Apps", "Apps", "apps"],
      ["Categories", "Categories", "categories"],
      ["Export", "Export", "export"],
      ["All actions", "All actions", "actions"],
    ] as const) {
      await page.getByRole("tab", { name: tab }).click();
      await expect(page.getByRole("tab", { name: tab })).toHaveAttribute("aria-selected", "true");
      await expect(page.getByRole("heading", { name: heading, level: 1 })).toBeVisible();
      if (view !== "actions") await expect(page).toHaveURL(new RegExp(`view=${view}`));
      await expectNoErrorBoundary(page);
    }

    await page.goto(receiptsUrl(facts, "view=categories"));
    await expect(page.getByRole("tab", { name: "Categories" })).toHaveAttribute("aria-selected", "true");
    await page.reload();
    await expect(page.getByRole("tab", { name: "Categories" })).toHaveAttribute("aria-selected", "true");
  });

  test("apps tab counts each app and drills into its actions", async ({ page, state }) => {
    const facts = receiptFacts(state);
    await page.goto(receiptsUrl(facts, "view=apps"));
    const names: Record<string, string> = {
      codex: "Codex",
      "claude-code": "Claude Code",
      cursor: "Cursor",
      opencode: "OpenCode",
    };
    for (const [harness, label] of Object.entries(names)) {
      const total = facts.by_harness[harness];
      const split = facts.by_harness_disposition[harness];
      await expect(
        page.getByRole("button", {
          name: new RegExp(
            `${label} ${total} actions · ${split.allowed} allowed · ${split.reviewed} review · ${split.blocked} stopped`,
          ),
        }),
      ).toBeVisible();
    }

    await page.getByRole("searchbox", { name: "Search apps" }).fill("cursor");
    await expect(page.getByRole("button", { name: /Codex \d+ actions/ })).toHaveCount(0);
    await page.getByRole("button", { name: /Cursor \d+ actions/ }).click();

    await expect(page.getByRole("heading", { name: "Cursor", level: 2 })).toBeVisible();
    const table = page.getByRole("table", { name: "Cursor actions" });
    await expect(bodyRows(table)).toHaveCount(facts.by_harness.cursor);
    await page.getByRole("combobox").filter({ has: page.getByRole("option", { name: "Stopped" }) }).selectOption({ label: "Stopped" });
    await expect(bodyRows(table)).toHaveCount(facts.by_harness_disposition.cursor.blocked);
    await expect(rowByName(table, /rm -rf \.\/dist/)).toBeVisible();

    await page.getByRole("button", { name: "Back" }).click();
    await expect(page.getByRole("searchbox", { name: "Search apps" })).toBeVisible();
  });

  test("categories tab groups receipts and drills into a category", async ({ page, state }) => {
    const facts = receiptFacts(state);
    await page.goto(receiptsUrl(facts, "view=categories"));
    const labels: Record<string, string> = {
      secret: "Secret read",
      network: "Network",
      destructive: "Destructive",
      hidden: "Hidden script",
      "file-write": "File write",
      mcp: "MCP tool",
      skill: "Skill / plugin",
      "supply-chain": "Supply chain",
      data: "Data access",
      "tool-call": "Tool call",
      other: "Other",
    };
    for (const [category, label] of Object.entries(labels)) {
      const n = facts.by_category[category];
      await expect(
        page.getByRole("button", { name: new RegExp(`^${label} ${n} actions?\\b`) }),
      ).toBeVisible();
    }

    await page.getByRole("button", { name: /^Secret read 2 actions/ }).click();
    await expect(page.getByRole("heading", { name: "Secret read", level: 2 })).toBeVisible();
    const table = page.getByRole("table", { name: "Secret read actions" });
    await expect(bodyRows(table)).toHaveCount(facts.by_category.secret);
    await expect(rowByName(table, facts.featured.env.name)).toBeVisible();
    await expect(rowByName(table, facts.featured.ssh.name)).toBeVisible();

    await page.getByRole("combobox").filter({ has: page.getByRole("option", { name: "Codex" }) }).selectOption({ label: "Codex" });
    await expect(bodyRows(table)).toHaveCount(facts.by_category.secret);
    await page.getByRole("button", { name: "Back to categories" }).click();
    await expect(page.getByRole("button", { name: /^Secret read / })).toBeVisible();
  });

  test("insights tab reports lifetime totals from the local store", async ({ page, state }) => {
    const facts = receiptFacts(state);
    await page.goto(receiptsUrl(facts, "view=insights"));
    await expect(page.getByText("Your Guard stats")).toBeVisible();
    await expect(page.getByRole("button", { name: "Share your Guard stats publicly" })).toBeVisible();
    await expect(page.getByRole("grid", { name: "90 day activity heatmap" })).toBeVisible();
    await expect(page.getByText("Most Active Apps")).toBeVisible();
    await expect(page.getByRole("group", { name: "Seven day activity chart" })).toBeVisible();
    // Other areas seed receipts into the same store, so totals are lower bounds.
    const stats = page.getByText("Lifetime actions").locator("..");
    await expect(async () => {
      expect(numberAfter(await stats.textContent() ?? "", "Lifetime actions")).toBeGreaterThanOrEqual(facts.total);
    }).toPass();
    await expect(page.getByRole("button", { name: /^Codex \d+ · \d+%$/ })).toBeVisible();
    await expect(page.getByText("from full local store")).toBeVisible();
  });
});
