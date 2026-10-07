import { expect, test } from "@playwright/test";
import { initialize, mount } from "./extension-control-fixtures";

for (const width of [1280, 390]) {
  test(`catalog refresh preserves drafts and scopes bulk choices at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const tool = (id: string, name: string) => ({
      command_id: id, name, usage: name, description: "Synthetic catalog fixture.", parent_id: null, state: "inherit",
    });
    const item = {
      cli_id: "local-cli.mcp-fixture", name: "Fixture connector", kind: "executable",
      identity_hash: "b".repeat(64), example_label: "fixture-mcp --connection synthetic",
      interpreter_name: null, observed_count: 2, last_seen_at: "2026-09-27T12:00:00Z",
      surface: "mcp", source_label: "Fixture host", source_path: null,
      help_status: "ok", state: "allowed", stale: false, suggestable: true,
      grant_revision: 1, authority_revision: 1,
      provider_catalog: {
        provider: "composio", known_count: 2, full_schema_count: 2,
        updated_at: "2026-09-27T12:00:00Z", coverage: "discovery-subset", account_binding: "unverified",
      },
      commands: [tool("read", "Read records"), tool("delete", "Delete records"), tool("other", "Other tools")],
      mcp_catalog: {
        complete: false, stale: true, reason: "list_failed" as string | null,
        pages: 1, listed_count: 1, known_count: 2, protocol_version: "2026-07-28",
        revision: 1, updated_at: "2026-09-27T12:01:00Z", last_complete_at: "2026-09-27T12:00:00Z",
        changes: { added: [] as string[], changed: [] as string[], removed: [] as string[], stale: ["delete"] },
        skills_catalog: { declared: true, complete: false, stale: true, known_count: 51,
          reason: "skill_discovery_failed", activation_supported: false },
      },
    };
    const refreshRequests: Record<string, unknown>[] = [];
    let cancelRequested = false;
    const cancelledJobIds: string[] = [];
    let holdStart = false;
    let releaseStart: (() => void) | null = null;
    let publicationState = "pending";
    let skillRevision = 1;
    const skillRequests: Record<string, unknown>[] = [];
    let workflowRequests = 0;
    await mount(page);
    await page.route("**/v1/local-clis**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path.endsWith("/provider-workflows")) {
        workflowRequests += 1;
        await route.fulfill({ json: { cli_id: item.cli_id, next_offset: null, proposals: [{
          proposal_id: "a".repeat(64), source: "composio-search-guidance", guidance_present: true,
          requirements_complete: false, permissions_granted: false, account_binding: "unverified",
          requirements: [{ tool_slug: "SLACK_SEARCH_MESSAGES", role: "primary", state: "ask", schema_observed: true },
            { tool_slug: "SLACK_SEND_MESSAGE", role: "primary", state: "saved-deny", schema_observed: true },
            { tool_slug: "SLACK_FIND_CHANNELS", role: "supporting", state: "unresolved", schema_observed: false }],
        }] } });
        return;
      }
      if (path.endsWith("/mcp-skills")) {
        const body = route.request().postDataJSON();
        skillRequests.push(body);
        if (body.revision && body.revision !== skillRevision) {
          await route.fulfill({ status: 409, json: { message: "Workflow metadata changed. Reload its first page." } });
          return;
        }
        const entries = Array.from({ length: 51 }, (_, index) => ({
          uri: `skill://report-${String(index).padStart(3, "0")}/SKILL.md`,
          name: `report-${String(index).padStart(3, "0")}`, description: "Synthetic remote workflow metadata.",
          origin: "mcp-served-skill", connection_identity_hash: item.identity_hash,
          activation_supported: false, permissions_granted: false, dynamic: false,
          manifest_digest: `sha256:${"f".repeat(64)}`, resource_count: 2,
        })).filter((entry) => !body.search || entry.name.includes(body.search));
        await route.fulfill({ json: { cli_id: item.cli_id, entries: entries.slice(body.offset, body.offset + 50),
          revision: skillRevision, activation_supported: false,
          next_offset: body.offset + 50 < entries.length ? body.offset + 50 : null } });
        return;
      }
      if (path.endsWith("/provider-actions")) {
        const body = route.request().postDataJSON();
        const actions = ["SLACK_SEARCH_MESSAGES", "SLACK_SEND_MESSAGE"].filter((slug) => (
          !body.search || slug.toLowerCase().includes(body.search.toLowerCase())
        )).map((slug) => ({
          tool_slug: slug, toolkit: "slack", description: "Synthetic provider metadata.", full_schema: true,
          revision: 1, updated_at: "2026-09-27T12:00:00Z", permission_state: "review", allow_supported: false,
          account_binding: "unverified",
        }));
        await route.fulfill({ json: { cli_id: item.cli_id, actions, next_offset: null, coverage: "discovery-subset", catalog_token: "c".repeat(64) } });
        return;
      }
      if (path.endsWith("/refresh-job")) {
        const body = route.request().postDataJSON();
        if (body.operation === "configured-connections") {
          await route.fulfill({ json: { job_id: "e".repeat(32), cli_id: "inventory:configured", state: "complete", error: null } });
          return;
        }
        if (body.cancel) {
          cancelRequested = true;
          cancelledJobIds.push(body.job_id);
          await route.fulfill({ json: { job_id: "d".repeat(32), cli_id: item.cli_id, state: "cancelled", error: null } });
          return;
        }
        if (!body.job_id) refreshRequests.push(body);
        if (holdStart && !body.job_id) {
          await new Promise<void>((resolve) => { releaseStart = resolve; });
          await route.fulfill({ json: { job_id: body.client_job_id, cli_id: item.cli_id,
            state: "cancelled", error: null } }).catch(() => undefined);
          return;
        }
        if (refreshRequests.length > 1) {
          await route.fulfill({ json: { job_id: "d".repeat(32), cli_id: item.cli_id,
            state: refreshRequests.length === 2 ? "failed" : "running",
            error: width === 390 ? "mcp_initialize_failed" : "discovery_failed" } });
          return;
        }
        item.commands.splice(2, 0, tool("search", "Search records"));
        item.mcp_catalog = { ...item.mcp_catalog, complete: true, stale: false, reason: null,
          listed_count: 3, known_count: 3, revision: 2, updated_at: "2026-09-27T12:02:00Z",
          changes: { added: ["search"], changed: [], removed: [], stale: [] } };
        await route.fulfill({ json: { job_id: "d".repeat(32), cli_id: item.cli_id, state: "complete", error: null } });
        return;
      }
      await route.fulfill({ json: { schema_version: "guard.daemon.local-clis.v1", revision: 1, items: [item],
        native_publication: { state: publicationState, revision: 1, generation: 2, policy_digest: "a".repeat(64) },
        cloud: { sync_local_only: true, summary: "Synthetic fixture; this device only." } } });
    });
    await initialize(page);
    await page.getByRole("button", { name: /Fixture connector/ }).click();
    const detail = page.getByTestId("local-cli-detail");
    expect(skillRequests).toHaveLength(0);
    await detail.getByText("Remote workflows · 51 cached", { exact: true }).click();
    expect(workflowRequests).toBe(0);
    await detail.getByText("Suggested action workflows", { exact: true }).click();
    const suggestions = detail.getByRole("region", { name: "Composio workflow suggestions", exact: true });
    await expect(suggestions).toContainText("They are not MCP Skills, account verification, or permission grants");
    await expect(suggestions).toContainText("slack send message · Primary · Saved Deny");
    await expect(suggestions).toContainText("slack find channels · Supporting · Not observed");
    expect(workflowRequests).toBe(1);
    await detail.getByText("Suggested action workflows", { exact: true }).click();
    const workflows = detail.getByRole("region", { name: "Remote workflow metadata", exact: true });
    await expect(workflows.getByRole("heading", { name: "report-000", exact: true })).toBeVisible();
    await expect(workflows).toContainText("workflow inventory is incomplete");
    await expect(workflows).toContainText("Instructions are not loaded");
    skillRevision = 2;
    await workflows.getByRole("button", { name: "Next", exact: true }).click();
    await expect(workflows.getByRole("alert")).toContainText("Workflow metadata changed");
    await expect(workflows.getByRole("heading", { name: "report-000", exact: true })).toHaveCount(0);
    await workflows.getByRole("button", { name: "Reload workflow metadata", exact: true }).click();
    await expect(workflows.getByRole("heading", { name: "report-000", exact: true })).toBeVisible();
    await workflows.getByRole("button", { name: "Next", exact: true }).click();
    await expect(workflows.getByRole("heading", { name: "report-050", exact: true })).toBeVisible();
    await workflows.getByRole("searchbox", { name: "Find a remote workflow", exact: true }).fill("no-match");
    await expect(workflows.getByText("No workflow metadata matches this search.", { exact: true })).toBeVisible();
    expect(skillRequests.every((body) => !body.activate && !body.uri && !body.confirm_directory_read)).toBe(true);
    await detail.getByText("Remote workflows · 51 cached", { exact: true }).click();
    const enforcement = detail.getByRole("region", { name: "Enforcement status", exact: true });
    await expect(enforcement.getByRole("status")).toContainText("Waiting for the native runtime");
    publicationState = "acknowledged";
    await detail.getByRole("button", { name: "Check enforcement status", exact: true }).click();
    await expect(enforcement.getByRole("status")).toContainText("acknowledged saved revision 1");
    const provider = detail.getByRole("region", { name: "Discovered app actions", exact: true });
    await expect(provider.getByRole("heading", { name: "Search messages", exact: true })).toBeVisible();
    await provider.getByRole("searchbox", { name: "Search actions or apps", exact: true }).fill("send");
    await expect(provider.getByRole("heading", { name: "Send message", exact: true })).toBeVisible();
    await expect(provider.getByRole("heading", { name: "Search messages", exact: true })).toHaveCount(0);
    await expect(provider.getByText("slack · Account not verified", { exact: true })).toBeVisible();
    await provider.getByRole("combobox", { name: "Permission for Send message", exact: true }).selectOption("block");
    await expect(detail.getByRole("button", { name: "Review 1 action changes", exact: true })).toBeVisible();
    await provider.getByRole("searchbox", { name: "Search actions or apps", exact: true }).fill("");
    await expect(provider.getByRole("combobox", { name: "Permission for Send message", exact: true })).toHaveValue("block");
    await expect(detail.getByRole("heading", { name: "2 tools cached · Refresh failed", exact: true })).toBeVisible();
    const read = detail.getByRole("radiogroup", { name: "Read records protection setting" });
    await read.getByRole("radio", { name: "Allow", exact: true }).click();
    await detail.getByRole("button", { name: "Refresh inventory", exact: true }).click();
    await expect(detail.getByRole("heading", { name: "3 tools listed", exact: true })).toBeVisible();
    await expect(detail.getByText("New tools · 1", { exact: true })).toBeVisible();
    await expect(read.getByRole("radio", { name: "Allow", exact: true })).toHaveAttribute("aria-checked", "true");
    await expect(detail.getByRole("radiogroup", { name: "Search records protection setting" })).toBeVisible();
    expect(refreshRequests[0]).toEqual({ cli_id: item.cli_id, confirm_process_start: true,
      client_job_id: expect.stringMatching(/^[a-f0-9]{32}$/) });
    await detail.getByTestId("custom-extension-bulk-policy").getByRole("radio", { name: "Allow listed", exact: true }).click();
    await expect(detail.getByRole("radiogroup", { name: "Other tools protection setting" })
      .getByRole("radio", { name: "Policy", exact: true })).toHaveAttribute("aria-checked", "true");
    await expect(detail.getByRole("radiogroup", { name: "Other tools protection setting" })
      .getByRole("radio", { name: "Allow", exact: true })).toBeDisabled();
    const search = detail.getByRole("radiogroup", { name: "Search records protection setting" });
    await search.getByRole("radio", { name: "Ask", exact: true }).click();
    await expect(search.getByRole("radio", { name: "Ask", exact: true })).toHaveAttribute("aria-checked", "true");
    await detail.getByRole("button", { name: "Refresh inventory", exact: true }).click();
    await expect(detail.getByRole("alert")).toContainText(width === 390
      ? "The MCP server did not complete initialization."
      : "Discovery did not finish. Known tools and choices were kept.");
    await expect(read.getByRole("radio", { name: "Allow", exact: true })).toHaveAttribute("aria-checked", "true");
    await detail.getByRole("button", { name: "Refresh inventory", exact: true }).click();
    await detail.getByRole("button", { name: "Cancel refresh", exact: true }).click();
    await expect.poll(() => cancelRequested).toBe(true);
    await expect(detail.getByRole("button", { name: "Refresh inventory", exact: true })).toBeEnabled();
    await expect(read.getByRole("radio", { name: "Allow", exact: true })).toHaveAttribute("aria-checked", "true");
    holdStart = true;
    cancelRequested = false;
    await detail.getByRole("button", { name: "Refresh inventory", exact: true }).click();
    await expect.poll(() => Boolean(releaseStart)).toBe(true);
    const pendingJobId = refreshRequests.at(-1)?.client_job_id;
    await detail.getByRole("button", { name: "Cancel refresh", exact: true }).click();
    await expect.poll(() => cancelledJobIds.includes(String(pendingJobId))).toBe(true);
    await expect(detail.getByRole("button", { name: "Refresh inventory", exact: true })).toBeEnabled();
    releaseStart?.();
    holdStart = false;
    await detail.getByRole("button", { name: /^Review \d+ tool changes$/ }).click();
    const review = page.getByRole("dialog");
    await expect(review.getByRole("region", { name: "Permission changes", exact: true })).toContainText("Read records: Policy → Allow");
    await expect(review).toContainText("Unknown and future tools still require review");
    await review.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(read.getByRole("radio", { name: "Allow", exact: true })).toHaveAttribute("aria-checked", "true");
    await detail.getByRole("button", { name: "Refresh inventory", exact: true }).scrollIntoViewIfNeeded();
    if (process.env.HOL_GUARD_MCP_CAPTURE_PROOF === "1") {
      await page.screenshot({ path: testInfo.outputPath(`catalog-recovery-${width}.png`), animations: "disabled", fullPage: width > 600 });
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    expect(errors).toEqual([]);
  });
}
