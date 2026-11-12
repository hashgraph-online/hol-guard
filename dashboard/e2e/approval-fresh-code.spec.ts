import { expect, test, type Page } from "@playwright/test";
import type { GuardApprovalRequest } from "../src/guard-types";

import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  emptyReceiptsPayload,
  freeStateSnapshot,
} from "./fixture-states";

// #7528: Guard's settings can keep reporting a recent authenticator confirmation while its
// resolve check refuses the same decision for want of a code. The review card must then ask
// for a code instead of retrying without one.

const DAEMON = "guardDaemon=http://127.0.0.1:4175";

const request: GuardApprovalRequest = {
  request_id: "fresh-code-e2e",
  harness: "claude-code",
  artifact_id: "claude-code:project:tool-action:fresh-code-e2e",
  artifact_name: "Run workspace command",
  artifact_type: "tool_action_request",
  artifact_hash: "fresh-code-hash",
  publisher: "claude-code-local",
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  allowed_scopes: ["artifact", "workspace", "harness", "global"],
  scope_contract_version: "guard.approval-scopes.v6",
  scope_contract_digest: "scope-contract-digest",
  allowed_scopes_by_action: {
    allow: ["artifact", "workspace", "harness", "global"],
    block: ["artifact", "workspace", "publisher", "harness", "global"],
  },
  recommended_scope_by_action: { allow: "artifact", block: "artifact" },
  scope_restrictions: ["reusable_allow_is_action_bound", "task_capability_not_enabled"],
  task_capability_eligibility: { eligible: false, reason_codes: ["task_capability_not_enabled"] },
  changed_fields: ["command"],
  source_scope: "project",
  config_path: "project-config.json",
  workspace: "/workspace/project",
  launch_target: "bun test",
  transport: "stdio",
  review_command: "hol-guard approvals approve fresh-code-e2e",
  approval_url: "http://127.0.0.1:4175/requests/fresh-code-e2e",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-11-11T13:00:00Z",
  resolved_at: null,
  action_envelope_json: null,
  decision_v2_json: null,
};

// Every settings read, including the refresh after a refusal, reports a recent confirmation.
const recentlyConfirmedGate = {
  enabled: true, configured: true, cooldown_seconds: 0,
  cooldown_active: false, cooldown_expires_at: null, locked_until: null,
  fail_closed: true, strict_all_decisions: true,
  totp_enabled: true, totp_recent_satisfied: true,
};

async function mountFixture(
  page: Page,
  bodies: Array<Record<string, unknown>>,
  refusals: number,
  gate: Record<string, unknown> = recentlyConfirmedGate,
): Promise<void> {
  const settings = { ...defaultSettingsPayload, settings: { ...defaultSettingsPayload.settings, approval_gate: gate } };
  let remainingRefusals = refusals;
  await page.route("**/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "e2e-approval-token" };
    else if (path.endsWith("/runtime")) body = { ...freeStateSnapshot, pending_count: 1 };
    else if (path.endsWith(`/requests/${request.request_id}/approve`)) {
      bodies.push(route.request().postDataJSON() as Record<string, unknown>);
      if (remainingRefusals > 0) {
        remainingRefusals -= 1;
        await route.fulfill({
          status: 403,
          contentType: "application/json",
          body: JSON.stringify({ error: "approval_gate_totp_required", message: "TOTP code is required." }),
        });
        return;
      }
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
    else if (path.endsWith("/settings")) body = settings;
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/diff")) body = null;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
}

test("a recent authenticator confirmation still approves without asking for a code", async ({ page }) => {
  const bodies: Array<Record<string, unknown>> = [];
  await mountFixture(page, bodies, 0);
  await page.goto(`/requests/${request.request_id}?${DAEMON}`);
  await page.getByRole("button", { name: "Allow just this once", exact: true }).click();
  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0]).not.toHaveProperty("approval_totp_code");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Retry", exact: true })).toHaveCount(0);
});

test("after Guard refuses a decision for want of a code, Retry asks for one and sends it", async ({ page }) => {
  const bodies: Array<Record<string, unknown>> = [];
  await mountFixture(page, bodies, 1);
  await refuseThenEnterCode(page, bodies);
});

// A password cooldown recorded before the authenticator was turned on still reads as active,
// but Guard ignores it once the authenticator is on, so it must not suppress the code either.
test("a recorded password cooldown does not stop Retry from asking for a code", async ({ page }) => {
  const bodies: Array<Record<string, unknown>> = [];
  await mountFixture(page, bodies, 1, {
    ...recentlyConfirmedGate,
    cooldown_seconds: 300, cooldown_active: true, cooldown_expires_at: "2099-01-01T00:00:00Z",
    strict_all_decisions: false,
  });
  await refuseThenEnterCode(page, bodies);
});

async function refuseThenEnterCode(page: Page, bodies: Array<Record<string, unknown>>): Promise<void> {
  await page.goto(`/requests/${request.request_id}?${DAEMON}`);
  await page.getByRole("button", { name: "Allow just this once", exact: true }).click();
  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0]).not.toHaveProperty("approval_totp_code");

  await page.getByRole("button", { name: "Retry", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("heading", { name: "Authenticator code required" })).toBeVisible();
  // The dialog opened instead of a second request without a code.
  expect(bodies).toHaveLength(1);

  const code = dialog.getByLabel("Authenticator code", { exact: true });
  await code.fill("123456");
  await code.press("Enter");
  await expect.poll(() => bodies.length).toBe(2);
  expect(bodies[1]).toMatchObject({ approval_totp_code: "123456" });
  await expect(page.getByRole("dialog")).toHaveCount(0);
}
