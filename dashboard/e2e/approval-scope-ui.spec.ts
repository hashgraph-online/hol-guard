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

const request: GuardApprovalRequest = {
  request_id: "scope-e2e",
  harness: "codex",
  artifact_id: "codex:project:tool-action:scope-e2e",
  artifact_name: "Run workspace command",
  artifact_type: "tool_action_request",
  artifact_hash: "scope-hash",
  publisher: "codex-local",
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  allowed_scopes: ["artifact"],
  scope_contract_version: "guard.approval-scopes.v2",
  scope_contract_digest: "scope-contract-digest",
  allowed_scopes_by_action: {
    allow: ["artifact"],
    block: ["artifact", "workspace", "publisher", "harness", "global"],
  },
  recommended_scope_by_action: { allow: "artifact", block: "artifact" },
  scope_restrictions: ["broad_allow_requires_positive_proof", "task_capability_not_enabled"],
  task_capability_eligibility: {
    eligible: false,
    reason_codes: ["task_capability_not_enabled"],
  },
  changed_fields: ["command"],
  source_scope: "project",
  config_path: "project-config.json",
  workspace: "/workspace/project",
  launch_target: "bun test",
  transport: "stdio",
  review_command: "hol-guard approvals approve scope-e2e",
  approval_url: "http://127.0.0.1:4175/requests/scope-e2e",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-07-20T05:00:00Z",
  resolved_at: null,
  action_envelope_json: null,
  decision_v2_json: null,
};

async function mountApprovalFixture(
  page: Page,
  resolutionBodies: Array<Record<string, unknown>>,
  approvalRequest: GuardApprovalRequest = request,
  options: {
    settingsReady?: Promise<void>;
    settingsPayload?: unknown;
  } = {},
): Promise<void> {
  await page.route("**/v1/**", async (route) => {
    const routeRequest = route.request();
    const path = new URL(routeRequest.url()).pathname;
    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "e2e-approval-token" };
    else if (path.endsWith("/runtime")) body = { ...freeStateSnapshot, pending_count: 1 };
    else if (
      path.endsWith(`/requests/${approvalRequest.request_id}/approve`) ||
      path.endsWith(`/requests/${approvalRequest.request_id}/block`)
    ) {
      resolutionBodies.push(routeRequest.postDataJSON() as Record<string, unknown>);
      body = {
        resolved: true,
        item: null,
        resolved_request: { ...approvalRequest, status: "resolved", resolution_action: "block", resolution_scope: "global" },
        remaining_pending_count: 0,
        next_selectable_request_id: null,
        remaining_pending_summaries: [],
        resolved_duplicate_ids: [],
        resolution_summary: "Decision saved.",
        retry_hint: null,
        copy: null,
        codex_resume: null,
      };
    } else if (path.endsWith(`/requests/${approvalRequest.request_id}`)) body = approvalRequest;
    else if (path.endsWith("/requests")) {
      body = {
        items: [approvalRequest],
        next_cursor: null,
        total_pending_count: 1,
        total_count: 1,
        status: "pending",
      };
    } else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) {
      await options.settingsReady;
      body = options.settingsPayload ?? defaultSettingsPayload;
    }
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/diff")) body = null;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
}

test("approval review renders action-eligible scopes and binds the selected contract", async ({ page }) => {
  const resolutionBodies: Array<Record<string, unknown>> = [];
  await mountApprovalFixture(page, resolutionBodies);
  await page.goto(`/requests/scope-e2e?${DAEMON}`);

  await expect(page.getByRole("heading", { name: "Run workspace command" })).toBeVisible();
  await expect(page.getByRole("radio", { name: /Approve once/ })).toBeVisible();
  await expect(page.getByText("Everywhere", { exact: true })).toHaveCount(0);
  await expect(page.getByText(/Task access is not available/)).toBeVisible();

  await page.getByText("Block matching actions", { exact: true }).first().click();
  await page.getByRole("radio", { name: /Block everywhere/ }).click();
  await page.getByRole("button", { name: "Block matching actions" }).click();

  await expect.poll(() => resolutionBodies.length).toBe(1);
  expect(resolutionBodies[0]).toMatchObject({
    action: "block",
    scope: "global",
    scope_contract_version: "guard.approval-scopes.v2",
    scope_contract_digest: "scope-contract-digest",
  });
});

test("non-overridable actions disable approval while preserving eligible block scopes", async ({ page }) => {
  const resolutionBodies: Array<Record<string, unknown>> = [];
  const blockedRequest: GuardApprovalRequest = {
    ...request,
    request_id: "scope-blocked-e2e",
    policy_action: "block",
    recommended_scope: null,
    allowed_scopes: [],
    allowed_scopes_by_action: { allow: [], block: ["artifact", "global"] },
    recommended_scope_by_action: { allow: null, block: "artifact" },
    scope_restrictions: ["current_action_not_overridable", "task_capability_not_enabled"],
  };
  await page.setViewportSize({ width: 390, height: 844 });
  await mountApprovalFixture(page, resolutionBodies, blockedRequest);
  await page.goto(`/requests/${blockedRequest.request_id}?${DAEMON}`);

  await expect(page.getByText("This action cannot be approved under its current Guard policy.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve once" })).toBeDisabled();
  await expect(page.getByText(/Task access cannot override/)).toBeVisible();
  await page.getByText("Block matching actions", { exact: true }).first().click();
  await expect(page.getByRole("radio", { name: /Block everywhere/ })).toBeVisible();
  expect(resolutionBodies).toHaveLength(0);
});

test("keyboard approval uses gate settings that arrive after request detail", async ({ page }) => {
  const resolutionBodies: Array<Record<string, unknown>> = [];
  let releaseSettings: (() => void) | undefined;
  const settingsReady = new Promise<void>((resolve) => {
    releaseSettings = resolve;
  });
  const gatedSettingsPayload = {
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
        strict_all_decisions: true,
        totp_enabled: false,
      },
    },
  };
  await mountApprovalFixture(page, resolutionBodies, request, {
    settingsReady,
    settingsPayload: gatedSettingsPayload,
  });
  await page.goto(`/requests/scope-e2e?${DAEMON}`);
  await expect(page.getByRole("heading", { name: "Run workspace command" })).toBeVisible();

  const settingsResponse = page.waitForResponse((response) =>
    new URL(response.url()).pathname.endsWith("/settings"),
  );
  releaseSettings?.();
  await settingsResponse;
  await page.evaluate(
    () => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))),
  );
  await page.keyboard.press("a");

  await expect(page.getByRole("dialog", { name: "Approval password required" })).toBeVisible();
  expect(resolutionBodies).toHaveLength(0);
});

test("browser MCP review offers bounded capability access on mobile", async ({ page }) => {
  const resolutionBodies: Array<Record<string, unknown>> = [];
  const browserRequest: GuardApprovalRequest = {
    ...request,
    request_id: "browser-mcp-e2e",
    artifact_id: "codex:project:mcp-tool-call:chrome-devtools:new-page",
    artifact_name: "chrome-devtools:new_page",
    artifact_type: "mcp_tool_call",
    launch_target: "chrome-devtools new_page hol.org",
    changed_fields: ["runtime_browser_tool_call"],
    policy_action: "review",
    temporary_mcp_approval: {
      eligible: true,
      server_name: "chrome-devtools",
      server_identity_hash: "sha256:browser-e2e",
      category: "browser_navigation",
      target_label: "hol.org",
      allowed_targets: ["exact", "category", "server"],
      allowed_durations: ["once", "15m", "1h", "5h"],
      hard_risk_exclusions: ["browser_privileged", "browser_transfer"],
    },
  };
  await page.setViewportSize({ width: 390, height: 844 });
  await mountApprovalFixture(page, resolutionBodies, browserRequest);
  await page.goto(`/requests/${browserRequest.request_id}?${DAEMON}`);

  await expect(page.getByRole("heading", { name: "chrome-devtools:new_page" })).toBeVisible();
  await expect(page.getByRole("radio", { name: "1 hour" })).toBeChecked();
  await expect(page.getByRole("radio", { name: "This browser capability" })).toBeChecked();
  await expect(page.getByText(/Privileged browser access.*still require review/)).toBeVisible();
  await page.getByText("5 hours", { exact: true }).click();
  await page.getByRole("button", { name: "Allow for 5 hours" }).click();

  await expect.poll(() => resolutionBodies.length).toBe(1);
  expect(resolutionBodies[0]).toMatchObject({
    action: "allow",
    scope: "artifact",
    mcp_grant_target: "category",
    mcp_grant_duration: "5h",
  });
});
