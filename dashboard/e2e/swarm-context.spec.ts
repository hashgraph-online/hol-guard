import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { defaultSettingsPayload } from "./fixture-states";
import { makeAgent, swarmFixture, swarmUrl } from "./swarm-fixture";
import type { ContextWorkspaceScope } from "../src/context-assistance/workspaces-api";

const ready = JSON.parse(readFileSync(new URL("../src/context-assistance/fixtures/intent-state.json", import.meta.url), "utf8")).native_test.ready_observation;
const project = "/Projects/agent-project";
const observed = makeAgent({ id: "process-codex", origin: "observed", state: "observed", workspace: project, task: null,
  controls: { message: false, steer: false, interrupt: false, stop: false }, context_calls: 0 });
const scope = (): ContextWorkspaceScope => ({ scope_id: "scope:picked", workspace: project, app: "dashboard", policy_revision: "a".repeat(64),
  sources: [{ source_id: "file:readme", path: "README.md", sha256: "b".repeat(64), documents: 1 }], retained_contexts: 0, revoked: false });

async function fixture(page: Page, options: { existing?: boolean; enabled?: boolean; unknown?: boolean; harness?: string } = {}) {
  await swarmFixture(page, [{ ...observed, ...(options.unknown ? { workspace: null } : {}), ...(options.harness ? { harness: options.harness } : {}) }]);
  const enabled = options.enabled !== false;
  const preferences = { ...ready.preferences, enabled, features: { ...ready.preferences.features, agent_context: true },
    sources: { ...ready.preferences.sources, workspace_documents: true, source_set_id: "selected-workspaces" } };
  const state = { scopes: options.existing ? [scope()] : [] as ContextWorkspaceScope[], failCompile: false, failGrant: false,
    calls: [] as { path: string; body: any }[] };
  const status = { ...ready, availability: enabled ? "ready" : "off", requested_enabled: enabled, effective_enabled: enabled,
    preferences, effective_preferences: preferences, runtime: enabled ? ready.runtime : null, diagnostic: null, job: null };
  await page.route("**/v1/settings", (route) => route.fulfill({ json: { ...defaultSettingsPayload, settings: {
    ...defaultSettingsPayload.settings, context_assistance: preferences, context_assistance_requested: preferences,
    approval_gate: { enabled: true, configured: true, cooldown_seconds: 0, cooldown_active: false, cooldown_expires_at: null,
      locked_until: null, fail_closed: false, strict_all_decisions: false, totp_enabled: false, totp_pending: false },
  } } }));
  await page.route("**/v1/context-assistance{,/**}", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().postDataJSON();
    state.calls.push({ path, body });
    const result = (value: unknown) => ({ schema: "guard-cigar-workspace-result.v1", data_role: true, result: value });
    if (path.endsWith("/workspace-grant")) {
      expect(body.approval_password).toBe("swarm-context-proof");
      if (state.failGrant) { await route.fulfill({ status: 403, json: { code: "native_context_assistance_context_scope_denied" } }); return; }
      const value = { ...scope(), workspace: body.input.workspace };
      state.scopes.push(value);
      await route.fulfill({ json: result(value) });
    } else if (path.endsWith("/workspace")) {
      if (body.input.action === "compile") {
        if (state.failCompile) { await route.fulfill({ status: 503, json: { code: "native_context_assistance_runtime_deadline_exceeded" } }); return; }
        const citation = { source: "file:readme", node_id: "readme:1", start_line: 1, end_line: 1, document_digest: "b".repeat(64) };
        await route.fulfill({ json: result({ current: true, scope: state.scopes[0], brief: {
          schema: "guard-cigar-context-brief.v1", data_role: true, snapshot_id: "c".repeat(64), policy_revision: "a".repeat(64), graph_revision: 1,
          rendered: "Reviewed project context", rendered_tokens: 4, excerpts: [{ text: "Reviewed project context", citations: [citation] }], citations: [citation],
        } }) });
      } else await route.fulfill({ json: result(body.input.action === "list_agents" ? { agent_sessions: [] } : { scopes: state.scopes }) });
    } else if (path.endsWith("/folders")) {
      await route.fulfill({ json: { schema: "guard-context-folders.v1", mode: "files", workspace: body.workspace, path: "", entries: [],
        max_file_bytes: 65536, truncated: false, suggested: [{ relative: "README.md", size: 120 }],
        files: [{ name: "README.md", relative: "README.md", size: 120, available: true, reason: null }] } });
    } else if (path.endsWith("/installations")) await route.fulfill({ json: { ...status, installation_options: [] } });
    else if (path === "/v1/context-assistance") await route.fulfill({ json: status });
    else await route.fallback();
  });
  return state;
}

async function openContext(page: Page) {
  await page.goto(swarmUrl);
  await page.locator(".swarm-node").first().click();
  await page.getByRole("tab", { name: "Context", exact: true }).click();
  await page.getByRole("button", { name: /Add to CIGAR|Manage CIGAR context/ }).click();
  await expect(page.getByRole("region", { name: "Context for Swarm agent" })).toBeVisible();
}

test("an observed Swarm agent can pick files, approve access, preview context and return to its updated inspector", async ({ page }, info) => {
  const state = await fixture(page);
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await openContext(page);
  await expect(page.getByRole("heading", { name: "Context for Codex" })).toBeVisible();
  await expect(page.getByRole("checkbox", { name: /README.md/ })).toBeChecked();
  await page.screenshot({ path: info.outputPath("swarm-cigar-handoff.png"), fullPage: true });
  expect(page.url()).not.toContain(encodeURIComponent(project));
  expect(state.calls.some((call) => call.path.endsWith("/workspace-grant"))).toBe(false);
  await page.getByRole("button", { name: "Add project", exact: true }).click();
  const proof = page.getByRole("dialog", { name: "Add this project" });
  await expect(proof).toContainText("every AI app");
  await proof.getByLabel("Approval password").fill("swarm-context-proof");
  await proof.getByRole("button", { name: "Add project", exact: true }).click();
  await expect(page.getByText("This project already has 1 approved file.", { exact: false })).toBeVisible();
  expect(state.calls.find((call) => call.path.endsWith("/workspace-grant"))?.body.input).toEqual({ action: "grant", workspace: project, app: "dashboard", sources: ["README.md"] });
  await page.getByRole("button", { name: "Show what your AI would get", exact: true }).click();
  await expect(page.getByRole("region", { name: "What your AI would get", exact: true })).toContainText("Reviewed project context");
  await page.getByText("Where each part came from", { exact: true }).click();
  await expect(page.getByText("README.md, lines 1–1")).toBeVisible();
  await page.getByRole("button", { name: "Back to agent" }).click();
  await expect(page.getByRole("tab", { name: "Context", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.locator(".swarm-context-panel")).toContainText("Project context ready");
  await expect(page.locator(".swarm-context-panel")).toContainText("does not confirm this agent has used it");
  expect(errors).toEqual([]);
});

test("an existing every-app project opens without another grant; a failed preview stays recoverable", async ({ page }) => {
  const state = await fixture(page, { existing: true });
  await openContext(page);
  await expect(page.getByRole("button", { name: "Add project", exact: true })).toHaveCount(0);
  state.failCompile = true;
  await page.getByRole("button", { name: "Show what your AI would get", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Restart CIGAR");
  await expect(page.getByRole("button", { name: "Show what your AI would get", exact: true })).toBeEnabled();
  state.failCompile = false;
  await page.getByRole("button", { name: "Show what your AI would get", exact: true }).click();
  await expect(page.getByRole("region", { name: "What your AI would get", exact: true })).toBeVisible();
  expect(state.calls.some((call) => call.path.endsWith("/workspace-grant"))).toBe(false);
});

test("a refused grant keeps the chosen files and approval dialog available for retry", async ({ page }) => {
  const state = await fixture(page);
  state.failGrant = true;
  await openContext(page);
  await page.getByRole("button", { name: "Add project", exact: true }).click();
  const proof = page.getByRole("dialog", { name: "Add this project" });
  await proof.getByLabel("Approval password").fill("swarm-context-proof");
  await proof.getByRole("button", { name: "Add project", exact: true }).click();
  await expect(proof).toContainText("couldn't add these files");
  state.failGrant = false;
  await proof.getByRole("button", { name: "Add project", exact: true }).click();
  await expect(proof).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Show what your AI would get", exact: true })).toBeEnabled();
});

test("unknown projects require a folder; external apps retain MCP pairing and off CIGAR retains the handoff", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 1000 });
  await fixture(page, { unknown: true, harness: "gemini" });
  await openContext(page);
  await expect(page.getByRole("button", { name: /Choose a project folder/ })).toBeVisible();
  await expect(page.getByRole("region", { name: "Context for Swarm agent" })).toContainText("needs a CIGAR MCP connection");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await expect(page.getByRole("button", { name: "Add project", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Back to agent" }).click();
  await fixture(page, { enabled: false });
  await openContext(page);
  await expect(page.getByRole("region", { name: "Context for Swarm agent" })).toContainText("Turn on or restart CIGAR");
  await expect(page.getByRole("button", { name: "Add project", exact: true })).toHaveCount(0);
});
