import { expect, test, type Page } from "@playwright/test";
import type { GuardApprovalRequest } from "../src/guard-types";
import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  emptyReceiptsPayload,
  freeStateSnapshot,
} from "./fixture-states";

const DAEMON = "guardDaemon=http://127.0.0.1:4175";
const TOOL = "mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL";

const gmailSend: GuardApprovalRequest = {
  request_id: "mcp-card-e2e",
  harness: "codex",
  artifact_id: `tool:${TOOL}`,
  artifact_name: TOOL,
  artifact_type: "tool_call",
  artifact_hash: "mcp-card-hash",
  publisher: null,
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  allowed_scopes: ["artifact", "workspace"],
  scope_contract_version: "guard.approval-scopes.v6",
  scope_contract_digest: "mcp-card-contract-digest",
  allowed_scopes_by_action: { allow: ["artifact", "workspace"], block: ["artifact", "workspace"] },
  recommended_scope_by_action: { allow: "artifact", block: "artifact" },
  exact_action_persistence_eligible: true,
  changed_fields: ["runtime_tool_call"],
  source_scope: "project",
  config_path: "./mcp.json",
  workspace: "/workspace/project",
  launch_target: TOOL,
  transport: "stdio",
  review_command: "hol-guard approvals approve mcp-card-e2e",
  approval_url: "http://127.0.0.1:4175/requests/mcp-card-e2e",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-11-17T12:00:00Z",
  resolved_at: null,
  latest_receipts: [],
  action_envelope_json: {
    schema_version: 1,
    action_id: "mcp-card-e2e",
    harness: "codex",
    event_name: "PreToolUse",
    action_type: "mcp_tool",
    workspace: "/workspace/project",
    workspace_hash: null,
    tool_name: TOOL,
    command: null,
    prompt_excerpt: null,
    prompt_text: null,
    target_paths: [],
    network_hosts: [],
    mcp_server: "composio",
    mcp_tool: "COMPOSIO_MULTI_EXECUTE_TOOL",
    package_manager: null,
    package_name: null,
    script_name: null,
    raw_payload_redacted: {
      tool_name: TOOL,
      tool_input: {
        thought: "Everything is fine, just sending the update",
        tools: [
          {
            tool_slug: "GMAIL_SEND_EMAIL",
            arguments: {
              recipient_email: "ann@example.com",
              subject: "Quarterly update",
              body: "Hi Ann, the numbers are attached. Let me know what you think.",
            },
          },
        ],
      },
    },
  },
  decision_v2_json: null,
};

async function mount(page: Page, bodies: Array<Record<string, unknown>>): Promise<void> {
  await page.route("**/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "e2e-token" };
    else if (path.endsWith("/runtime")) body = { ...freeStateSnapshot, pending_count: 1 };
    else if (path.endsWith("/approve") || path.endsWith("/block")) {
      bodies.push(route.request().postDataJSON() as Record<string, unknown>);
      body = {
        resolved: true,
        item: null,
        resolved_request: { ...gmailSend, status: "resolved", resolution_action: "allow", resolution_scope: "artifact" },
        remaining_pending_count: 0,
        next_selectable_request_id: null,
        remaining_pending_summaries: [],
        resolved_duplicate_ids: [],
        resolution_summary: "Decision saved.",
        retry_hint: null,
        copy: null,
        codexResume: null,
      };
    } else if (path.endsWith(`/requests/${gmailSend.request_id}`)) body = gmailSend;
    else if (path.endsWith("/requests")) {
      body = { items: [gmailSend], next_cursor: null, total_pending_count: 1, total_count: 1, status: "pending" };
    } else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) body = defaultSettingsPayload;
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/diff")) body = null;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
}

for (const width of [1280, 390]) {
  test(`an MCP send reads in plain words at width ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1100 });
    await mount(page, []);
    await page.goto(`/requests/${gmailSend.request_id}?${DAEMON}`);

    const card = page.getByRole("region", { name: "What the agent is asking to do" });
    await expect(card.getByRole("heading", { name: "Send email" })).toBeVisible();
    await expect(card.getByText("Gmail, through Composio")).toBeVisible();
    await expect(card.getByRole("note")).toContainText("Sends something through Gmail");
    await expect(card.getByLabel("Addresses").getByText("ann@example.com")).toBeVisible();
    await expect(card.locator("dd").getByText("Quarterly update", { exact: true })).toBeVisible();
    // The agent's own reassurance is quoted and attributed, never a heading or a fact.
    await expect(card.getByRole("note")).not.toContainText("Everything is fine");
    await expect(card.getByText(/In the agent's own words/)).toBeVisible();
    await expect(page.getByText("What would happen without Guard?")).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  });
}

test("the MCP decision is two plain choices, and Always allow keeps the scope contract", async ({ page }) => {
  const bodies: Array<Record<string, unknown>> = [];
  await mount(page, bodies);
  await page.goto(`/requests/${gmailSend.request_id}?${DAEMON}`);

  await expect(page.getByText("Approval scope", { exact: true })).toHaveCount(0);
  const group = page.getByRole("radiogroup", { name: "How long to allow this call" });
  await expect(group.getByRole("radio", { name: /^Just this once/ })).toBeVisible();
  await expect(group.getByRole("radio", { name: /^Always allow this call/ })).toBeVisible();
  await expect(page.getByText("More choices", { exact: true })).toBeVisible();

  await group.getByRole("radio", { name: /^Always allow this call/ }).click();
  await expect(group.getByRole("radio", { name: /^Always allow this call/ })).toBeChecked();
  await page.getByRole("button", { name: "Always allow this call", exact: true }).click();

  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0]).toMatchObject({
    action: "allow",
    scope: "artifact",
    persist_policy: true,
    scope_contract_version: "guard.approval-scopes.v6",
    scope_contract_digest: "mcp-card-contract-digest",
  });
});

test("Just this once allows one retry and saves nothing", async ({ page }) => {
  const bodies: Array<Record<string, unknown>> = [];
  await mount(page, bodies);
  await page.goto(`/requests/${gmailSend.request_id}?${DAEMON}`);

  const group = page.getByRole("radiogroup", { name: "How long to allow this call" });
  await expect(group.getByRole("radio", { name: /^Just this once/ })).toBeChecked();
  await page.getByRole("button", { name: "Allow once", exact: true }).click();

  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0]).toMatchObject({ action: "allow", scope: "artifact" });
  expect(bodies[0].persist_policy).not.toBe(true);
});
