import { expect, test, type Page } from "@playwright/test";
import type { GuardApprovalRequest, GuardBrowserCardV1 } from "../src/guard-types";
import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  emptyReceiptsPayload,
  freeStateSnapshot,
} from "./fixture-states";

const DAEMON = "guardDaemon=http://127.0.0.1:4175";
const TOOL = "mcp__playwright__browser_type";
const TYPED = "typed-sample-value";

const typeCard: GuardBrowserCardV1 = {
  headline: "Claude Code wants to type into a form on shop.example.test",
  verb: "type",
  site: { origin: "https://shop.example.test", first_visit_in_task: true, left_granted_site: true },
  profile_line: "shared",
  detail: { element_preview: "Password", input_kind: "text", input_length: TYPED.length, input_masked: true },
  risk_chips: ["password_field", "cookies", "auth_headers"],
  provider_findings: [],
  choices: ["allow_once", "always_allow", "deny"],
  steps: [],
};

const browserType: GuardApprovalRequest = {
  request_id: "browser-card-e2e",
  harness: "claude-code",
  artifact_id: `tool:${TOOL}`,
  artifact_name: TOOL,
  artifact_type: "tool_call",
  artifact_hash: "browser-card-hash",
  publisher: null,
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  allowed_scopes: ["artifact", "workspace"],
  scope_contract_version: "guard.approval-scopes.v6",
  scope_contract_digest: "browser-card-contract-digest",
  allowed_scopes_by_action: { allow: ["artifact", "workspace"], block: ["artifact", "workspace"] },
  recommended_scope_by_action: { allow: "artifact", block: "artifact" },
  exact_action_persistence_eligible: true,
  changed_fields: ["runtime_tool_call"],
  source_scope: "project",
  config_path: "./mcp.json",
  workspace: "/workspace/project",
  launch_target: TOOL,
  transport: "stdio",
  review_command: "hol-guard approvals approve browser-card-e2e",
  approval_url: "http://127.0.0.1:4175/requests/browser-card-e2e",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-11-26T12:00:00Z",
  resolved_at: null,
  latest_receipts: [],
  action_envelope_json: {
    schema_version: 1,
    action_id: "browser-card-e2e",
    harness: "claude-code",
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
    mcp_server: "playwright",
    mcp_tool: "browser_type",
    package_manager: null,
    package_name: null,
    script_name: null,
    raw_payload_redacted: {
      tool_name: TOOL,
      tool_input: { element: "Password", ref: "e7", text: TYPED },
    },
  },
  decision_v2_json: null,
  browser_card: typeCard,
};

async function mount(page: Page, bodies: Array<Record<string, unknown>>, request: GuardApprovalRequest): Promise<void> {
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
        resolved_request: { ...request, status: "resolved", resolution_action: "allow", resolution_scope: "artifact" },
        remaining_pending_count: 0,
        next_selectable_request_id: null,
        remaining_pending_summaries: [],
        resolved_duplicate_ids: [],
        resolution_summary: "Decision saved.",
        retry_hint: null,
        copy: null,
        codexResume: null,
      };
    } else if (path.endsWith(`/requests/${request.request_id}`)) body = request;
    else if (path.endsWith("/requests")) {
      body = { items: [request], next_cursor: null, total_pending_count: 1, total_count: 1, status: "pending" };
    } else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) body = defaultSettingsPayload;
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/diff")) body = null;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
}

for (const width of [320, 390, 720, 800, 1024, 1440]) {
  test(`a browser step reads from Core's card at width ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1200 });
    await mount(page, [], browserType);
    await page.goto(`/requests/${browserType.request_id}?${DAEMON}`);

    const card = page.locator('[data-browser-card="type"]');
    await expect(card).toBeVisible();
    // Core's headline is the page heading, said once; the card names the step.
    await expect(page.getByRole("heading", { name: typeCard.headline })).toHaveCount(1);
    await expect(card.getByRole("heading", { name: typeCard.headline })).toHaveCount(0);
    await expect(card.getByText("shop.example.test", { exact: true })).toBeVisible();
    await expect(card.getByText("First visit in this task")).toBeVisible();
    await expect(card.getByText("Outside the site you allowed")).toBeVisible();
    await expect(card.getByText("Your signed-in sites and saved data are reachable.")).toBeVisible();
    await expect(card.getByText(`Hidden · ${TYPED.length} characters`)).toBeVisible();

    const reach = card.getByRole("list", { name: "Can reach" });
    await expect(reach.getByRole("listitem")).toHaveCount(3);
    await expect(reach.getByRole("listitem").filter({ hasText: "Password field" })).toBeVisible();

    // A masked step's typed text is nowhere on the card, the exact input included.
    const main = page.locator("main");
    expect(await main.innerText()).not.toContain(TYPED);
    await card.getByText("See the exact input", { exact: true }).click();
    await expect(card.getByText("so Guard does not show its input.", { exact: false })).toBeVisible();
    expect(await main.innerText()).not.toContain(TYPED);

    // Allow once, Always allow and Keep blocked stay offered for a browser step.
    await expect(main.getByRole("button", { name: "Allow once", exact: true })).toBeVisible();
    await expect(main.getByRole("button", { name: "Keep blocked", exact: true })).toBeVisible();
    const group = page.getByRole("radiogroup", { name: "How long to allow this call" });
    await expect(group.getByRole("radio", { name: /^Always allow this call/ })).toBeVisible();

    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    if (process.env.BROWSER_SHOT_DIR) {
      await page.screenshot({ path: `${process.env.BROWSER_SHOT_DIR}/browser-card-${width}.png`, fullPage: true });
    }
  });
}

test("Always allow on a browser step saves the exact call under the scope contract", async ({ page }) => {
  const bodies: Array<Record<string, unknown>> = [];
  await mount(page, bodies, browserType);
  await page.goto(`/requests/${browserType.request_id}?${DAEMON}`);

  const group = page.getByRole("radiogroup", { name: "How long to allow this call" });
  await group.getByRole("radio", { name: /^Always allow this call/ }).click();
  await page.getByRole("button", { name: "Always allow this call", exact: true }).click();

  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0]).toMatchObject({
    action: "allow",
    scope: "artifact",
    persist_policy: true,
    scope_contract_version: "guard.approval-scopes.v6",
    scope_contract_digest: "browser-card-contract-digest",
  });
});

test("a browser call without Core's card keeps the ordinary MCP card", async ({ page }) => {
  const plain: GuardApprovalRequest = { ...browserType, request_id: "browser-card-plain", browser_card: null };
  await mount(page, [], plain);
  await page.goto(`/requests/${plain.request_id}?${DAEMON}`);

  await expect(page.getByRole("region", { name: "What the agent is asking to do" })).toBeVisible();
  await expect(page.locator("[data-browser-card]")).toHaveCount(0);
});
