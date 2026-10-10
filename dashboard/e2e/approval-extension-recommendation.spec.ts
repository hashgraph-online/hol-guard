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
const DIGEST = "a".repeat(64);

const gitAddPermission = {
  permission_id: "command.git.permission.add",
  label: "Git add",
  description: "Stage files for the next commit.",
  example_command: "git add",
  extension_id: "command.git",
  extension_name: "Git protection",
  rule_id: "command.git.add",
  risk_tier: "high",
  caution: false,
  caution_reason: null,
  caution_detail: null,
  cli_command: "hol-guard command controls set command.git.permission.add --state allow",
};

function recommendation(overrides: Record<string, unknown> = {}) {
  return {
    schema: "guard.approval-extension-recommendation.v1",
    status: "available",
    permissions: [gitAddPermission],
    caution: false,
    revision: 7,
    catalog_digest: DIGEST,
    ...overrides,
  };
}

function request(extensionRecommendation: unknown): GuardApprovalRequest {
  return {
    request_id: "ext-rec-e2e",
    harness: "codex",
    artifact_id: "codex:project:tool-action:ext-rec-e2e",
    artifact_name: "Run workspace command",
    artifact_type: "tool_action_request",
    artifact_hash: "ext-rec-hash",
    publisher: "codex-local",
    policy_action: "require-reapproval",
    recommended_scope: "artifact",
    changed_fields: ["command"],
    source_scope: "project",
    config_path: "project-config.json",
    workspace: "/workspace/project",
    launch_target: "git add src/app.py",
    transport: "stdio",
    review_command: "hol-guard approvals approve ext-rec-e2e",
    approval_url: "http://127.0.0.1:4175/requests/ext-rec-e2e",
    status: "pending",
    resolution_action: null,
    resolution_scope: null,
    reason: null,
    created_at: "2026-10-09T05:00:00Z",
    resolved_at: null,
    action_envelope_json: null,
    decision_v2_json: null,
    extension_recommendation: extensionRecommendation,
  } as GuardApprovalRequest;
}

function gateSettings(gate: Record<string, unknown> | null) {
  if (gate === null) return defaultSettingsPayload;
  return {
    ...defaultSettingsPayload,
    settings: {
      ...defaultSettingsPayload.settings,
      approval_gate: {
        enabled: true,
        configured: true,
        cooldown_seconds: 0,
        cooldown_active: false,
        cooldown_expires_at: null,
        locked_until: null,
        fail_closed: true,
        strict_all_decisions: false,
        totp_enabled: false,
        ...gate,
      },
    },
  };
}

const semanticPreview = {
  schema_version: "guard.daemon.extension-control-semantic-preview.v1",
  global_lockdown: { before: false, after: false, changed: false },
  changed_target_count: 0,
  affected_permission_count: 0,
  affected_rule_count: 0,
  approval_required: true,
  changed_targets: [],
  summary: { newly_blocked_permissions: 0, newly_allowed_permissions: 1, effective_change_count: 1 },
};

async function mount(
  page: Page,
  item: GuardApprovalRequest,
  calls: Array<{ path: string; body: Record<string, unknown> }>,
  gate: Record<string, unknown> | null = {},
): Promise<void> {
  await page.route("**/v1/**", async (route) => {
    const routeRequest = route.request();
    const path = new URL(routeRequest.url()).pathname;
    const post = routeRequest.method() === "POST" ? (routeRequest.postDataJSON() as Record<string, unknown>) : null;
    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "e2e-ext-rec-token" };
    else if (path.endsWith("/runtime")) body = { ...freeStateSnapshot, pending_count: 1 };
    else if (path.endsWith("/extension-controls/effective")) {
      calls.push({ path, body: {} });
      body = {
        schema_version: "guard.daemon.extension-controls.v1",
        health: "protected",
        revision: 7,
        catalog_digest: DIGEST,
        global_lockdown: false,
        controls: [],
        layers: [],
        failures: [],
      };
    } else if (path.endsWith("/extension-controls/preview")) {
      calls.push({ path, body: post ?? {} });
      body = {
        schema_version: "guard.daemon.extension-controls.v1",
        previous_revision: 7,
        next_revision: 8,
        catalog_digest: DIGEST,
        canonical_diff_digest: "b".repeat(64),
        global_lockdown: false,
        controls: 1,
        semantic_preview: semanticPreview,
        proof_id: "proof-e2e",
      };
    } else if (path.endsWith("/extension-controls/apply")) {
      calls.push({ path, body: post ?? {} });
      body = { schema_version: "guard.daemon.extension-controls.v1", status: "applied", revision: 8, catalog_digest: DIGEST };
    } else if (path.endsWith(`/requests/${item.request_id}/approve`)) {
      calls.push({ path, body: post ?? {} });
      body = {
        resolved: true,
        item: null,
        resolved_request: { ...item, status: "resolved", resolution_action: "allow", resolution_scope: "artifact" },
        remaining_pending_count: 0,
        next_selectable_request_id: null,
        remaining_pending_summaries: [],
        resolved_duplicate_ids: [],
        resolution_summary: "Decision saved.",
        retry_hint: null,
        copy: null,
        codexResume: null,
      };
    } else if (path.endsWith(`/requests/${item.request_id}`)) body = item;
    else if (path.endsWith("/requests")) {
      body = { items: [item], next_cursor: null, total_pending_count: 1, total_count: 1, status: "pending" };
    } else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) body = gateSettings(gate);
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/diff")) body = null;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
}

test("one tap allows the extension permission, then approves the request", async ({ page }) => {
  const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
  await mount(page, request(recommendation()), calls);
  await page.goto(`/requests/ext-rec-e2e?${DAEMON}`);

  const card = page.getByTestId("approval-extension-recommendation");
  await expect(card.getByRole("heading", { name: "Git protection covers git add" })).toBeVisible();
  await card.getByRole("button", { name: "Approve & always allow git add" }).click();

  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Always allow git add?")).toBeVisible();
  await dialog.getByLabel("Approval password", { exact: true }).fill("test-password");
  await dialog.getByRole("button", { name: "Approve & always allow git add" }).click();

  await expect(page.getByText("Approved. Git protection now allows git add automatically.")).toBeVisible();
  const order = calls.map((call) => call.path.replace(/^.*\/v1\//, ""));
  expect(order).toEqual([
    "extension-controls/effective",
    "extension-controls/preview",
    "extension-controls/apply",
    "requests/ext-rec-e2e/approve",
  ]);
  const preview = calls[1]!.body;
  expect(preview).toMatchObject({ previous_revision: 7, catalog_digest: DIGEST, approval_password: "test-password" });
  expect(preview.layers).toEqual([
    expect.objectContaining({
      kind: "local-admin",
      controls: [{ target_kind: "permission", target_id: "command.git.permission.add", state: "enabled" }],
    }),
  ]);
  expect(calls[2]!.body).toMatchObject({ proof_id: "proof-e2e" });
  expect(calls[3]!.body).toMatchObject({ scope: "artifact", approval_password: "test-password" });
  expect(calls[3]!.body.persist_policy).not.toBe(true);
  await page.screenshot({ path: test.info().outputPath("approved.png") });
});

test("configure link opens the exact pattern without command text in the URL", async ({ page }) => {
  await mount(page, request(recommendation()), []);
  await page.goto(`/requests/ext-rec-e2e?${DAEMON}`);
  await page.getByTestId("approval-extension-recommendation").screenshot({ path: test.info().outputPath("card.png") });
  await page.getByRole("button", { name: "Configure in Git protection" }).click();

  await expect(page).toHaveURL(/\/extensions\/command\.git/);
  const url = page.url();
  expect(url).toContain("rule=command.git.add");
  expect(new URL(url).searchParams.get("tab")).toBe("permissions");
  expect(url).not.toContain("src");
  expect(url).not.toContain("app.py");
});

test("missing approval password offers setup instead of one tap", async ({ page }) => {
  await mount(page, request(recommendation()), [], { enabled: false, configured: false });
  await page.goto(`/requests/ext-rec-e2e?${DAEMON}`);

  const card = page.getByTestId("approval-extension-recommendation");
  await expect(card.getByRole("link", { name: "Set up approval password" })).toBeVisible();
  await expect(card.getByRole("button", { name: /Approve & always allow/ })).toHaveCount(0);
});

test("destructive permissions show a caution before allowing", async ({ page }) => {
  const forcePush = {
    ...gitAddPermission,
    permission_id: "command.git.permission.force-push",
    label: "Forced Git push",
    example_command: "git push --force",
    rule_id: "command.git.push-force",
    caution: true,
    caution_reason: "destructive",
    caution_detail: "Rewrites remote history.",
    cli_command: "hol-guard command controls set command.git.permission.force-push --state allow",
  };
  await mount(page, request(recommendation({ caution: true, permissions: [forcePush] })), []);
  await page.goto(`/requests/ext-rec-e2e?${DAEMON}`);

  const card = page.getByTestId("approval-extension-recommendation");
  await expect(card.getByText("git push --force can destroy work or history. Rewrites remote history.")).toBeVisible();
  await card.screenshot({ path: test.info().outputPath("caution.png") });
});

test("unhealthy protection authority shows the link only", async ({ page }) => {
  await mount(page, request(recommendation({ status: "authority_unavailable" })), []);
  await page.goto(`/requests/ext-rec-e2e?${DAEMON}`);

  const card = page.getByTestId("approval-extension-recommendation");
  await expect(card.getByText(/Protection settings need attention/)).toBeVisible();
  await expect(card.getByRole("button", { name: /Approve & always allow/ })).toHaveCount(0);
  await expect(card.getByRole("button", { name: "Configure in Git protection" })).toBeVisible();
});

test("malformed recommendation is not rendered", async ({ page }) => {
  await mount(page, request(recommendation({ schema: "guard.other.v1" })), []);
  await page.goto(`/requests/ext-rec-e2e?${DAEMON}`);

  await expect(page.getByRole("heading", { name: "Run workspace command" })).toBeVisible();
  await expect(page.getByTestId("approval-extension-recommendation")).toHaveCount(0);
});
