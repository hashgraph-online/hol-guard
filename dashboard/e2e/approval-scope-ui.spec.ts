import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
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
  allowed_scopes: ["artifact", "workspace", "harness", "global"],
  scope_contract_version: "guard.approval-scopes.v6",
  scope_contract_digest: "scope-contract-digest",
  allowed_scopes_by_action: {
    allow: ["artifact", "workspace", "harness", "global"],
    block: ["artifact", "workspace", "publisher", "harness", "global"],
  },
  recommended_scope_by_action: { allow: "artifact", block: "artifact" },
  scope_restrictions: ["reusable_allow_is_action_bound", "task_capability_not_enabled"],
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
    requests?: GuardApprovalRequest[];
  } = {},
): Promise<void> {
  await page.route("**/v1/**", async (route) => {
    const routeRequest = route.request();
    const path = new URL(routeRequest.url()).pathname;
    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "e2e-approval-token" };
    else if (path.endsWith("/runtime")) body = { ...freeStateSnapshot, pending_count: options.requests?.length ?? 1 };
    else if (path.endsWith("/requests/bulk-allow-once")) {
      resolutionBodies.push(routeRequest.postDataJSON() as Record<string, unknown>);
      body = {
        approved_count: options.requests?.length ?? 1,
        approved_request_ids: options.requests?.map((item) => item.request_id) ?? [approvalRequest.request_id],
        rejected_request_ids: [],
        resolution_summary: "Selected actions approved once.",
      };
    }
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
        codexResume: null,
      };
    } else if (path.endsWith(`/requests/${approvalRequest.request_id}`)) body = approvalRequest;
    else if (path.endsWith("/requests")) {
      body = {
        items: options.requests ?? [approvalRequest],
        next_cursor: null,
        total_pending_count: options.requests?.length ?? 1,
        total_count: options.requests?.length ?? 1,
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
  await expect(page.getByRole("radio", { name: /Allow just this once/ })).toBeVisible();
  await expect(page.getByRole("radio", { name: /Allow and remember for this project/ })).toBeVisible();
  await page.getByText("Save for this app", { exact: true }).click();
  await expect(page.getByRole("radio", { name: /This app/ })).toBeVisible();
  await page.getByText("Advanced: save everywhere on this machine", { exact: true }).click();
  await expect(page.getByRole("radio", { name: /Everywhere/ })).toBeVisible();
  await expect(page.getByText(/Task access is not available/)).toBeVisible();

  await page.getByText("Block matching actions", { exact: true }).first().click();
  await page.getByRole("radio", { name: /Block everywhere/ }).click();
  await page.getByRole("button", { name: "Block matching actions" }).click();

  await expect.poll(() => resolutionBodies.length).toBe(1);
  expect(resolutionBodies[0]).toMatchObject({
    action: "block",
    scope: "global",
    scope_contract_version: "guard.approval-scopes.v6",
    scope_contract_digest: "scope-contract-digest",
  });
});

for (const toolName of ["read", "eval"]) {
  test(`native ${toolName} review shows the exact redacted action`, async ({ page }) => {
    const envelope = JSON.parse(readFileSync(
      new URL("../../tests/fixtures/native-review-action-envelope.json", import.meta.url), "utf8",
    ));
    const nativeRequest: GuardApprovalRequest = {
      ...request,
      harness: "omp", policy_action: "review", artifact_type: "tool_call", launch_target: `tool:${toolName}`,
      action_envelope_json: {
        ...envelope, action_id: request.request_id, tool_name: toolName,
        action_type: toolName === "read" ? "file_read" : "mcp_tool",
        target_paths: toolName === "read" ? ["src/example.py"] : [],
        raw_payload_redacted: { tool_name: toolName, tool_input: { code: "1 + 1" } },
      },
    };
    await mountApprovalFixture(page, [], nativeRequest);
    await page.goto(`/requests/scope-e2e?${DAEMON}`);
    await expect(page.getByText(toolName === "read" ? /src\/example\.py/ : /1 \+ 1/).first()).toBeVisible();
    await expect(page.getByText("Launch details were not available.")).toHaveCount(0);
    await expect(page.getByText(/inconsistent stored decision data/)).toHaveCount(0);
  });
}

for (const totpEnabled of [false, true]) {
  test(`Enter submits multiple selected reads with ${totpEnabled ? "Authenticator" : "password"} proof`, async ({ page }) => {
    const bodies: Array<Record<string, unknown>> = [];
    const pageErrors: string[] = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    const requests = ["alpha.ts", "beta.ts"].map((path, index): GuardApprovalRequest => ({
      ...request,
      request_id: `bulk-enter-${index}`,
      artifact_id: `codex:project:read:${index}`,
      artifact_name: `Read ${path}`,
      artifact_hash: `read-hash-${index}`,
      launch_target: path,
      action_envelope_json: {
        schema_version: 1,
        action_id: `bulk-enter-${index}`,
        harness: "codex",
        event_name: "PreToolUse",
        action_type: "file_read",
        workspace: "/workspace/project",
        workspace_hash: null,
        tool_name: "read",
        command: null,
        prompt_excerpt: null,
        target_paths: [`src/${path}`],
        network_hosts: [],
        mcp_server: null,
        mcp_tool: null,
        package_manager: null,
        package_name: null,
        script_name: null,
        raw_payload_redacted: {},
      },
    }));
    await mountApprovalFixture(page, bodies, requests[0], {
      requests,
      settingsPayload: {
        ...defaultSettingsPayload,
        settings: {
          ...defaultSettingsPayload.settings,
          approval_gate: {
            enabled: true, configured: true, cooldown_seconds: 900,
            cooldown_active: false, cooldown_expires_at: null, locked_until: null,
            fail_closed: true, strict_all_decisions: true, totp_enabled: totpEnabled,
          },
        },
      },
    });
    await page.goto(`/inbox?${DAEMON}`);
    await page.getByRole("checkbox", { name: "Select all eligible reads on this page" }).check();
    await page.getByRole("button", { name: "Review & approve" }).click();
    const proof = page.getByLabel(totpEnabled ? "Authenticator code" : "Approval password", { exact: true });
    await proof.focus();
    await proof.press("Enter");
    expect(bodies).toHaveLength(0);
    await proof.fill(totpEnabled ? "123456" : "test-password");
    await proof.press("Enter");
    await expect.poll(() => bodies.length).toBe(1);
    expect(bodies[0]).toMatchObject({
      request_ids: expect.arrayContaining(["bulk-enter-0", "bulk-enter-1"]),
      approval_gate_use_cooldown: false,
      ...(totpEnabled ? { approval_totp_code: "123456" } : { approval_password: "test-password" }),
    });
    expect(bodies[0].request_ids).toHaveLength(2);
    await expect(page.getByRole("button", { name: "Done", exact: true })).toBeVisible();
    expect(pageErrors).toEqual([]);
  });
}

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

  await expect(page.getByText("This decision cannot be overridden")).toBeVisible();
  await expect(page.getByText(/Policy terminally blocked this action/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Allow just this once" })).toHaveCount(0);
  await expect(page.getByText("Block matching actions", { exact: true })).toHaveCount(0);
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
