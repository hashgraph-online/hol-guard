import { daemonApi, expect, expectNoErrorBoundary, readIntegrationState, test } from "./fixtures";
import {
  decide,
  inboxNavLink,
  inboxSeed,
  pendingCount,
  queue,
  queueRow,
  receiptDecision,
  requestRecord,
  savedDecisionArtifacts,
  SEED_SEARCH,
  searchQueue,
} from "./inbox-helpers";

// Decisions made through the Review Inbox against the seeded daemon. The steps
// run in order: each one resolves requests the next one no longer sees.
test.describe.configure({ mode: "serial" });

// Always allow saved a decision. Take it back so later areas see the policy
// list the seed left.
test.afterAll(async () => {
  const state = await readIntegrationState();
  const policy = await daemonApi<{
    items: Array<{ harness: string; source: string; scope: string; artifact_id: string | null; artifact_hash: string | null }>;
  }>(state, "/v1/policy");
  for (const item of policy.items.filter((saved) => saved.artifact_id?.includes(SEED_SEARCH))) {
    const cleared = await daemonApi<{ cleared: number }>(state, "/v1/policy/clear", {
      method: "POST",
      body: JSON.stringify({
        harness: item.harness,
        source: item.source,
        scope: item.scope,
        artifact_id: item.artifact_id,
        artifact_hash: item.artifact_hash,
        approval_password: state.approvalPassword,
      }),
    });
    expect(cleared.cleared).toBe(1);
  }
  const left = (await savedDecisionArtifacts(state)).filter((artifactId) => artifactId.includes(SEED_SEARCH));
  expect(left).toEqual([]);
});

test("allowing a shell command once removes it from the queue and records the allow", async ({ page, state }) => {
  const { shell } = inboxSeed(state).requests;
  const waitingBefore = await pendingCount(state);

  await page.goto(`/requests/${shell.id}`);
  await page.getByRole("radio", { name: /^Allow just this once/ }).click();
  await decide(page, state, page.getByRole("button", { name: "Allow just this once" }), shell.id, "Allow just this once");

  await expect(queueRow(page, shell.preview)).toHaveCount(0);
  await expect.poll(() => pendingCount(state)).toBe(waitingBefore - 1);
  const record = await requestRecord(state, shell.id);
  expect(record).toMatchObject({ status: "resolved", resolution_action: "allow" });
  expect(await receiptDecision(state, shell.id)).toBe("allow");
  // A once-only allow is not remembered.
  expect(await savedDecisionArtifacts(state)).not.toContain(`codex:project:tool-action:${shell.id}`);

  await page.goto("/inbox");
  await expect(inboxNavLink(page)).toHaveAccessibleName(`Inbox, ${waitingBefore - 1} Guard actions waiting`);
  await searchQueue(page, SEED_SEARCH);
  await expect(queueRow(page, shell.preview)).toHaveCount(0);
});

test("keeping an MCP tool call blocked removes it from the queue and records the block", async ({ page, state }) => {
  const { mcp } = inboxSeed(state).requests;
  const waitingBefore = await pendingCount(state);

  await page.goto(`/requests/${mcp.id}`);
  await decide(page, state, page.getByRole("button", { name: "Keep blocked" }), mcp.id, "Keep blocked");

  await expect(queueRow(page, mcp.preview)).toHaveCount(0);
  await expect.poll(() => pendingCount(state)).toBe(waitingBefore - 1);
  expect(await requestRecord(state, mcp.id)).toMatchObject({ status: "resolved", resolution_action: "block" });
  expect(await receiptDecision(state, mcp.id)).toBe("block");
  expect(await savedDecisionArtifacts(state)).not.toContain(`codex:project:tool-action:${mcp.id}`);
});

test("Always allow exact action saves a decision for the package install", async ({ page, state }) => {
  const { package: pkg } = inboxSeed(state).requests;
  const waitingBefore = await pendingCount(state);

  await page.goto(`/requests/${pkg.id}`);
  await page.getByRole("radio", { name: /^Allow just this once/ }).click();
  await page.getByText("Always allow exact action", { exact: true }).click();
  await decide(page, state, page.getByRole("button", { name: "Approve and remember", exact: true }), pkg.id, "Approve and remember");

  await expect(queueRow(page, pkg.preview)).toHaveCount(0);
  await expect.poll(() => pendingCount(state)).toBe(waitingBefore - 1);
  expect(await requestRecord(state, pkg.id)).toMatchObject({ status: "resolved", resolution_action: "allow" });
  expect(await receiptDecision(state, pkg.id)).toBe("allow");
  // Unlike the once-only allow, the exact action is now a saved decision.
  expect(await savedDecisionArtifacts(state)).toContain(`codex:project:tool-action:${pkg.id}`);
});

test("bulk approval allows the selected file reads once", async ({ page, state }) => {
  const { read_a: readA, read_b: readB } = inboxSeed(state).requests;
  const waitingBefore = await pendingCount(state);

  await page.goto("/inbox");
  await searchQueue(page, SEED_SEARCH);
  await page.getByRole("checkbox", { name: `Select ${readA.preview}` }).check();
  await page.getByRole("checkbox", { name: `Select ${readB.preview}` }).check();
  await page.getByRole("button", { name: "Review & approve" }).click();

  const dialog = page.getByRole("dialog", { name: "Review 2 selected actions" });
  await expect(dialog.getByRole("heading", { name: "Approving 2 file reads" })).toBeVisible();
  await expect(dialog.getByText(readA.preview)).toBeVisible();
  await expect(dialog.getByText(readB.preview)).toBeVisible();
  await dialog.getByLabel("Approval password").fill(state.approvalPassword);
  await dialog.getByRole("button", { name: "Approve once (2 actions)" }).click();
  await expect(dialog).toBeHidden();

  await expect(queueRow(page, readA.preview)).toHaveCount(0);
  await expect(queueRow(page, readB.preview)).toHaveCount(0);
  await expect.poll(() => pendingCount(state)).toBe(waitingBefore - 2);
  for (const read of [readA, readB]) {
    expect(await requestRecord(state, read.id)).toMatchObject({ status: "resolved", resolution_action: "allow" });
    expect(await receiptDecision(state, read.id)).toBe("allow");
    expect(await savedDecisionArtifacts(state)).not.toContain(`codex:project:tool-action:${read.id}`);
  }
});

test("Block selected refuses the last seeded request once and leaves nothing of ours in the queue", async ({ page, state }) => {
  const seed = inboxSeed(state);
  const { exfil } = seed.requests;

  // An exfiltration review can never be approved in bulk, but it can be refused.
  await page.goto("/inbox");
  await searchQueue(page, SEED_SEARCH);
  await page.getByRole("checkbox", { name: `Select ${exfil.preview}` }).check();
  const bar = page.getByRole("region", { name: "Bulk selection" });
  await expect(bar.getByRole("button", { name: "Review & approve" })).toHaveCount(0);
  await bar.getByRole("button", { name: "Block selected" }).click();
  await expect(bar.getByText("Block 1 request just this once? Any agent still waiting is told no.")).toBeVisible();
  await bar.getByRole("button", { name: "Block 1" }).click();
  await expect(queueRow(page, exfil.preview)).toHaveCount(0);
  expect(await requestRecord(state, exfil.id)).toMatchObject({ status: "resolved", resolution_action: "block" });
  expect(await receiptDecision(state, exfil.id)).toBe("block");
  // A one-time block expires and is not listed; no lasting block rule is saved.
  const policy = await daemonApi<{ items: Array<{ artifact_id: string | null; action: string }> }>(state, "/v1/policy");
  expect(policy.items.filter((item) => item.action === "block" && item.artifact_id?.includes(exfil.id))).toEqual([]);

  // Every seeded request has left the pending list, whatever else is queued.
  const pending = await daemonApi<{ items: Array<{ request_id: string; display_status: string }> }>(
    state,
    "/v1/requests?limit=200",
  );
  const stillPending = pending.items.filter((item) => item.request_id.startsWith(SEED_SEARCH)).map((item) => item.request_id);
  expect(stillPending).toEqual([]);

  // With no other area holding approvals, the whole inbox is empty.
  const waiting = await pendingCount(state);
  await page.goto("/inbox");
  if (waiting === 0) {
    await expect(page.getByRole("heading", { name: "Nothing to review" })).toBeVisible();
    await expect(page.getByText("No actions need your decision right now.", { exact: false })).toBeVisible();
    await expect(queue(page)).toHaveCount(0);
  } else {
    await searchQueue(page, SEED_SEARCH);
    await expect(page.getByText("No matching actions")).toBeVisible();
    await expect(page.getByText(`${waiting}/${waiting}`, { exact: true })).toBeVisible();
  }
  await expectNoErrorBoundary(page);
});
