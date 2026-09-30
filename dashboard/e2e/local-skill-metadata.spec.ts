import { expect, test } from "@playwright/test";
import { initialize, mount } from "./extension-control-fixtures";

for (const width of [1280, 390]) {
  test(`skill metadata requires selected roots and keeps permissions separate at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const rootId = "a".repeat(64);
    let scanned = false;
    let scanCount = 0;
    let cancelled = false;
    const requests: Record<string, unknown>[] = [];
    await mount(page);
    await page.route("**/v1/local-clis**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      const body = route.request().method() === "POST" ? route.request().postDataJSON() : {};
      if (path.endsWith("/refresh-job")) {
        const skillJob = body.job_id === "c".repeat(32);
        if (body.cancel && skillJob) cancelled = true;
        await route.fulfill({ json: {
          job_id: skillJob ? "c".repeat(32) : "d".repeat(32),
          cli_id: skillJob ? "inventory:skills" : "inventory:configured",
          state: skillJob ? cancelled ? "cancelled" : "running" : "complete", error: null,
        } });
        return;
      }
      if (path.endsWith("/skills")) {
        requests.push(body);
        if (body.operation === "roots") {
          await route.fulfill({ json: { roots: [{ root_id: rootId, path: "/synthetic/.agents/skills", available: true }], permissions_granted: false } });
          return;
        }
        if (body.operation === "scan") {
          expect(body).toEqual({ operation: "scan", confirm_metadata_read: true, approved_root_ids: [rootId],
            client_job_id: expect.stringMatching(/^[a-f0-9]{32}$/) });
          scanCount += 1;
          scanned = true;
          await route.fulfill({ json: { job_id: scanCount === 1 ? "b".repeat(32) : "c".repeat(32),
            cli_id: "inventory:skills", state: scanCount === 1 ? "complete" : "running", error: null } });
          return;
        }
        if (body.operation === "preflight") {
          expect(body.confirm_directory_read).toBe(true);
          await route.fulfill({ json: { job_id: "f".repeat(32), cli_id: `skill:${body.skill_id}`, state: "complete", error: null } });
          return;
        }
        if (body.operation === "preflight-result") {
          await route.fulfill({ json: { skill_id: body.skill_id, schema_version: "guard.workflow-preflight.v1",
            dependency_source: "guard-extension", dependency_status: "declared", authority_revision: 0,
            requirements_complete: false, permissions_granted: false, runtime_checks_required: true, expires_in_seconds: 30,
            inspection: { status: "complete", manifest_digest: `sha256:${"e".repeat(64)}`, entry_count: 2, permissions_granted: false },
            native_publication: { state: "unavailable", revision: 0 },
            requirements: [{ connection_id: "local-cli.synthetic", tool_name: "mcp__host__composio_execute_tool", state: "ask" }],
          } });
          return;
        }
        const skills = scanned ? Array.from({ length: 55 }, (_, index) => ({
          skill_id: index.toString(16).padStart(64, "0"), root_id: rootId, uri: `file:///synthetic/skills/report-${index}/SKILL.md`,
          origin: "local-agent-skill", name: `report-${index}`, description: "Prepare a synthetic report.",
          compatibility: "Requires an external app.", requested_tools: "*", duplicate_name: index === 0,
          metadata_digest: "e".repeat(64), permission_state: "not-granted", requirements_complete: false,
          instruction_content_loaded: false,
        })).filter((skill) => !body.search || skill.name.includes(body.search)) : [];
        const offset = body.offset ?? 0;
        await route.fulfill({ json: { skills: skills.slice(offset, offset + 50), known_count: scanned ? 55 : 0,
          matched_count: skills.length, revision: scanned ? 1 : 0, complete: scanned, issue_count: 0,
          next_offset: offset + 50 < skills.length ? offset + 50 : null, permissions_granted: false } });
        return;
      }
      await route.fulfill({ json: { schema_version: "guard.daemon.local-clis.v1", revision: 0, items: [],
        cloud: { sync_local_only: true, summary: "Synthetic fixture." } } });
    });
    await initialize(page);
    expect(requests).toEqual([]);
    await page.getByText("Local skills and workflows", { exact: true }).click();
    const workspace = page.getByRole("region", { name: "Local skill metadata", exact: true });
    const read = workspace.getByRole("button", { name: "Read selected skill metadata", exact: true });
    await expect(read).toBeDisabled();
    expect(scanCount).toBe(0);
    await workspace.getByRole("checkbox", { name: "/synthetic/.agents/skills", exact: true }).check();
    await read.click();
    await expect(workspace.getByRole("status")).toContainText("55 skills indexed. No permissions granted.");
    await expect(workspace.getByRole("heading", { name: "report-0", exact: true })).toBeVisible();
    await expect(workspace.getByText("Same name found in another origin.", { exact: false })).toBeVisible();
    await workspace.getByRole("navigation", { name: "Local skill pages" }).getByRole("button", { name: "Next", exact: true }).click();
    await expect(workspace.getByRole("heading", { name: "report-50", exact: true })).toBeVisible();
    expect(requests.some((request) => request.offset === 50 && request.revision === 1)).toBe(true);
    await workspace.getByRole("searchbox", { name: "Find a local skill", exact: true }).fill("report-54");
    await expect(workspace.getByRole("heading", { name: "report-54", exact: true })).toBeVisible();
    await expect(workspace.getByRole("heading", { name: "report-50", exact: true })).toHaveCount(0);
    await workspace.getByText("Origin and requirements", { exact: true }).click();
    await expect(workspace.getByText("Requested tools: *", { exact: true })).toBeVisible();
    await expect(workspace.getByText("Loading this skill cannot allow its tools.", { exact: false })).toBeVisible();
    await expect(workspace.getByRole("button", { name: /Allow|Activate|Run/ })).toHaveCount(0);
    await workspace.getByRole("button", { name: "Prepare report-54", exact: true }).click();
    const preflight = workspace.getByRole("region", { name: "Workflow preflight", exact: true });
    await expect(preflight).toContainText("Guard dependency manifest (nonstandard extension)");
    await expect(preflight).toContainText("Needs review");
    await expect(preflight).toContainText("Preparing grants nothing");
    await expect(preflight.getByRole("link", { name: "Review connection permissions" })).toHaveAttribute("href", /extensions\/local-cli\/local-cli.synthetic/);
    await read.click();
    await workspace.getByRole("button", { name: "Cancel skill scan", exact: true }).click();
    await expect.poll(() => cancelled).toBe(true);
    await expect(read).toBeEnabled();
    await expect(workspace.getByRole("heading", { name: "report-54", exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  });
}
