import { daemonApi, expect, expectNoErrorBoundary, test } from "./fixtures";
import {
  escapeRegExp,
  inboxNavLink,
  inboxSeed,
  pendingCount,
  queue,
  queueRow,
  SEED_SEARCH,
  searchQueue,
} from "./inbox-helpers";

// Read-only checks of the Review Inbox against the seeded daemon. Decisions
// live in inbox.mutating.spec.ts.

test("the queue lists each seeded request kind with its risk and category", async ({ page, state }) => {
  const seed = inboxSeed(state);
  await page.goto("/inbox");
  await expect(page.getByRole("heading", { name: "Review", level: 1 })).toBeVisible();
  await searchQueue(page, SEED_SEARCH);
  await expect(queue(page).getByRole("option")).toHaveCount(seed.pendingCount);

  for (const [key, request] of Object.entries(seed.requests)) {
    // The row name reads "<preview> <harness · date> Risk: <level> <category>".
    // The MCP category is asserted in its own fixme test below.
    const category = key === "mcp" ? "" : `.*${escapeRegExp(request.category)}`;
    await expect(
      queue(page).getByRole("option", {
        name: new RegExp(`${escapeRegExp(request.preview)}.*Risk: ${request.risk}${category}`),
      }),
      `${request.kind} row`,
    ).toBeVisible();
  }
  await expectNoErrorBoundary(page);
});

// Product bug: the queue list payload omits the action envelope, so
// resolveQueueCategoryId (dashboard/src/queue-state.ts) never reaches its
// mcp_tool branch for a listed row and it reads "Other review".
test.fixme("the queue labels an MCP tool call row as an MCP tool call", async ({ page, state }) => {
  const mcp = inboxSeed(state).requests.mcp;
  await page.goto("/inbox");
  await searchQueue(page, SEED_SEARCH);
  await expect(
    queue(page).getByRole("option", { name: new RegExp(`${escapeRegExp(mcp.preview)}.*${mcp.category}`) }),
  ).toBeVisible();
});

test("the sidebar Inbox badge and the queue counter match the daemon's pending count", async ({ page, state }) => {
  const seed = inboxSeed(state);
  const waiting = await pendingCount(state);
  expect(waiting).toBeGreaterThanOrEqual(seed.pendingCount);

  await page.goto("/inbox");
  await expect(inboxNavLink(page)).toHaveAccessibleName(`Inbox, ${waiting} Guard actions waiting`);
  await expect(page.getByText(`${waiting}/${waiting}`, { exact: true })).toBeVisible();
});

test("a queue row opens its review detail", async ({ page, state }) => {
  const { package: pkg } = inboxSeed(state).requests;
  await page.goto("/inbox");
  await searchQueue(page, SEED_SEARCH);
  await queueRow(page, pkg.preview).click();

  await expect(page).toHaveURL(new RegExp(`/requests/${pkg.id}`));
  await expect(page.getByRole("heading", { level: 2 }).first()).toBeVisible();
  await expect(page.getByRole("main").getByText(pkg.preview).last()).toBeVisible();
  await expect(page.getByText("Working directory")).toBeVisible();
  await expect(page.getByText("Why paused")).toBeVisible();
  await expect(page.getByRole("radiogroup", { name: "Allow scope selection" })).toBeVisible();
});

test("each request detail shows the action Guard stopped", async ({ page, state }) => {
  const { shell, mcp, package: pkg, exfil, read_a: readA } = inboxSeed(state).requests;
  for (const request of [shell, pkg, exfil]) {
    await page.goto(`/requests/${request.id}`);
    await expect(page.getByRole("main").getByText(request.preview).last(), request.kind).toBeVisible();
    await expect(page.getByText("Working directory"), request.kind).toBeVisible();
  }

  await page.goto(`/requests/${readA.id}`);
  await expect(page.getByText("File path", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("main").getByText(readA.preview.replace("Read ", "")).last()).toBeVisible();

  await page.goto(`/requests/${mcp.id}`);
  await expect(page.getByText("MCP server / tool").first()).toBeVisible();
  await expect(page.getByRole("main").getByText(/create.?issue/i).last()).toBeVisible();
  await expectNoErrorBoundary(page);
});

test("shell and package reviews offer Allow once and Always allow, with a block choice", async ({ page, state }) => {
  const { shell, package: pkg } = inboxSeed(state).requests;
  for (const request of [shell, pkg]) {
    await page.goto(`/requests/${request.id}`);
    await expect(page.getByRole("radio", { name: /^Allow just this once/ }), request.kind).toBeVisible();
    await expect(page.getByRole("radio", { name: /^Allow and remember for this project/ })).toBeVisible();
    await expect(page.getByRole("button", { name: "Keep blocked" })).toBeVisible();

    // The exact-action duration choice appears with the once scope selected.
    await page.getByRole("radio", { name: /^Allow just this once/ }).click();
    const duration = page.getByRole("group", { name: "How long should Guard allow it?" });
    await expect(duration.getByRole("radio", { name: /^This time/ })).toBeChecked();
    await expect(page.getByRole("button", { name: "Allow just this once" })).toBeVisible();
    await duration.getByText("Always allow exact action", { exact: true }).click();
    await expect(duration.getByRole("radio", { name: /^Always allow exact action/ })).toBeChecked();
    await expect(page.getByRole("button", { name: "Approve and remember", exact: true })).toBeVisible();
  }
});

test("reviews without Always allow offer Allow once and say why", async ({ page, state }) => {
  const { mcp, read_a: readA, exfil } = inboxSeed(state).requests;
  for (const request of [readA, mcp]) {
    await page.goto(`/requests/${request.id}`);
    await page.getByRole("radio", { name: /^Allow just this once/ }).click();
    await expect(page.getByRole("radio", { name: /^Allow just this once/ }), request.kind).toBeChecked();
    await expect(page.getByRole("button", { name: "Allow just this once" })).toBeVisible();
    await expect(page.getByText(/Always allow is not available for this action/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Keep blocked" })).toBeVisible();
  }

  // A credential-exfiltration review can still be allowed once or blocked.
  await page.goto(`/requests/${exfil.id}`);
  await expect(page.getByRole("radio", { name: /^Allow just this once/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Keep blocked" })).toBeVisible();
});

test("search narrows the queue and reports when nothing matches", async ({ page, state }) => {
  const { package: pkg } = inboxSeed(state).requests;
  await page.goto("/inbox");
  await searchQueue(page, "left-pad");
  await expect(queue(page).getByRole("option")).toHaveCount(1);
  await expect(queueRow(page, pkg.preview)).toBeVisible();

  await searchQueue(page, "no-such-request-zzz");
  await expect(queue(page).getByRole("option")).toHaveCount(0);
  await expect(page.getByText("No matching actions")).toBeVisible();
});

test("category filters keep only the matching rows", async ({ page, state }) => {
  const { shell, package: pkg, exfil, read_a: readA, read_b: readB } = inboxSeed(state).requests;
  await page.goto("/inbox");
  await searchQueue(page, SEED_SEARCH);
  await page.getByRole("button", { name: "Show filters" }).click();

  await page.getByRole("button", { name: "Shell execution" }).click();
  await expect(queue(page).getByRole("option")).toHaveCount(1);
  await expect(queueRow(page, shell.preview)).toBeVisible();

  // Chips only list the groups present in the current view, so go back to All.
  await page.getByRole("button", { name: "All", exact: true }).click();
  await page.getByRole("button", { name: "File read / write" }).click();
  await expect(queue(page).getByRole("option")).toHaveCount(2);
  await expect(queueRow(page, readA.preview)).toBeVisible();
  await expect(queueRow(page, readB.preview)).toBeVisible();

  await page.getByRole("button", { name: "All", exact: true }).click();
  await page.getByRole("button", { name: "Network / data egress" }).click();
  await expect(queue(page).getByRole("option")).toHaveCount(1);
  await expect(queueRow(page, exfil.preview)).toBeVisible();

  await page.getByRole("button", { name: "All", exact: true }).click();
  await page.getByRole("button", { name: "MCP, skill & packages" }).click();
  await expect(queueRow(page, pkg.preview)).toBeVisible();
  await expect(queueRow(page, shell.preview)).toHaveCount(0);

  await page.getByRole("button", { name: "All", exact: true }).click();
  await expect(queue(page).getByRole("option")).toHaveCount(inboxSeed(state).pendingCount);
});

test("sorting reorders the queue by risk and by date", async ({ page, state }) => {
  const { shell, exfil, read_b: readB } = inboxSeed(state).requests;
  await page.goto("/inbox");
  await searchQueue(page, SEED_SEARCH);
  await page.getByRole("button", { name: "Show filters" }).click();
  const options = queue(page).getByRole("option");
  const sort = page.getByLabel("Sort review queue");

  await sort.selectOption({ label: "Highest risk first" });
  await expect(options.first()).toContainText(exfil.preview);
  await sort.selectOption({ label: "Oldest first" });
  await expect(options.first()).toContainText(shell.preview);
  await sort.selectOption({ label: "Newest first" });
  await expect(options.first()).toContainText(readB.preview);
});

test("Mark all read clears the unread state of every row", async ({ page, state }) => {
  const seed = inboxSeed(state);
  // The queue loads its read state after it renders. A click that lands first
  // is overwritten when that load returns, so wait for it.
  const readStateLoaded = page.waitForResponse(
    (response) => new URL(response.url()).pathname === "/v1/read-state" && response.request().method() === "GET",
  );
  await page.goto("/inbox");
  await readStateLoaded;
  await searchQueue(page, SEED_SEARCH);
  // Opening a request reads it, so the selected row is already read.
  await expect(queue(page).getByRole("option", { name: /^Unread request:/ }).first()).toBeVisible();

  await page.getByRole("button", { name: "Mark all read" }).click();
  await expect(queue(page).getByRole("option", { name: /^Unread request:/ })).toHaveCount(0);
  await expect(queue(page).getByRole("option")).toHaveCount(seed.pendingCount);
});

test("bulk approval offers file reads but never a credential-exfiltration review", async ({ page, state }) => {
  const { exfil, read_a: readA, read_b: readB } = inboxSeed(state).requests;
  await page.goto("/inbox");
  await searchQueue(page, SEED_SEARCH);

  await page.getByRole("checkbox", { name: `Select ${readA.preview}` }).check();
  await page.getByRole("checkbox", { name: `Select ${readB.preview}` }).check();
  const bar = page.getByRole("region", { name: "Bulk selection" });
  await expect(bar.getByText("2 requests selected · approve once")).toBeVisible();

  // The exfiltration review can be selected to block it, never to approve it.
  await expect(queueRow(page, exfil.preview)).toBeVisible();
  await page.getByRole("checkbox", { name: `Select ${exfil.preview}` }).check();
  await expect(bar.getByText("3 requests selected · 2 can be approved at once")).toBeVisible();
  await expect(bar.getByRole("button", { name: "Block selected" })).toBeVisible();

  await bar.getByRole("button", { name: "Clear" }).click();
  await expect(bar).toHaveCount(0);

  // Nothing was approved by looking at it.
  expect(await pendingCount(state)).toBeGreaterThanOrEqual(inboxSeed(state).pendingCount);
  const record = await daemonApi<{ status: string }>(state, `/v1/requests/${readA.id}`);
  expect(record.status).toBe("pending");
});
