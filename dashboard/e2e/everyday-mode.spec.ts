import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
const fixture = JSON.parse(readFileSync(new URL("../src/__fixtures__/everyday-action-explanation.json", import.meta.url), "utf8"));
import { defaultSettingsPayload, emptyInventoryPayload, emptyPoliciesPayload, emptyReceiptsPayload, freeStateSnapshot } from "./fixture-states";

const DAEMON = "guardDaemon=http://127.0.0.1:4175";
const identity = fixture.action_identity;
const request = {
  request_id: "everyday-review", harness: "claude-code", artifact_id: "test:everyday-action",
  artifact_name: "Workspace action", artifact_type: "command", artifact_hash: "everyday-hash",
  publisher: null, policy_action: "require-reapproval", recommended_scope: "artifact",
  allowed_scopes: ["artifact"], scope_contract_version: "guard.approval-scopes.v5",
  scope_contract_digest: "everyday-scope-contract", allowed_scopes_by_action: { allow: ["artifact"], block: ["artifact"] },
  recommended_scope_by_action: { allow: "artifact", block: "artifact" },
  scope_restrictions: [], changed_fields: ["first_seen"], source_scope: "project", config_path: null,
  workspace: "/private/everyday-project", launch_target: null, transport: "stdio",
  review_command: "hol-guard approvals approve everyday-review", approval_url: null,
  status: "pending", resolution_action: null, resolution_scope: null, reason: null,
  created_at: "2026-09-09T12:00:00Z", resolved_at: null, action_identity: identity,
  action_explanation: fixture.action_explanation, raw_command_text: "rm -rf ./build",
  action_envelope_json: { schema_version: 1, action_id: "everyday-review", harness: "claude-code",
    event_name: "tool_call", action_type: "shell_command", command: "rm -rf ./build",
    workspace: "/private/everyday-project", workspace_hash: null, tool_name: "Bash", prompt_excerpt: null,
    target_paths: [], network_hosts: [], mcp_server: null, mcp_tool: null, package_manager: null,
    package_name: null, script_name: null, raw_payload_redacted: {} },
};

function createState() {
  return { mode: "everyday" as "everyday" | "technical", revision: 0, explicit: false,
    supported: true, rejectNextWrite: false, mismatched: false, writes: [] as Record<string, unknown>[] };
}
type State = ReturnType<typeof createState>;
function settings(state: State) {
  return { ...defaultSettingsPayload, settings: { ...defaultSettingsPayload.settings,
    ...(state.supported ? { presentation_mode: state.mode, presentation_revision: state.revision,
      presentation_mode_explicit: state.explicit, presentation_schema_version: 1,
      presentation: { value: state.mode, source: state.explicit ? "local-explicit" : "default",
        explicit: state.explicit, writable: true, schema_version: 1, revision: state.revision, diagnostic: null } } : {}),
  } };
}
async function mount(page: Page, state: State) {
  page.on("pageerror", (error) => { console.error("Dashboard runtime error:", error.message); });
  page.on("console", (message) => { if (message.type() === "error") console.error("Browser console:", message.text()); });
  await page.route("**/v1/**", async (route) => {
    const incoming = route.request();
    const path = new URL(incoming.url()).pathname;
    let body: unknown = {};
    let status = 200;
    const item = state.mismatched ? { ...request, action_identity: "a different action" } : request;
    if (path.endsWith("/initialize")) body = { auth_token: "e2e-everyday-token" };
    else if (path.endsWith("/runtime")) body = { ...freeStateSnapshot, pending_count: 1 };
    else if (path.endsWith("/requests/everyday-review")) body = item;
    else if (path.endsWith("/requests")) body = { items: [item], next_cursor: null, total_pending_count: 1, total_count: 1, status: "pending" };
    else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/diff") || path.endsWith("/previous")) body = null;
    else if (path.endsWith("/settings")) {
      if (incoming.method() !== "GET") {
        const payload = (incoming.postDataJSON() as { settings: Record<string, unknown> }).settings;
        state.writes.push(payload);
        if (state.rejectNextWrite || payload.presentation_revision !== state.revision) {
          state.rejectNextWrite = false;
          state.mode = "technical"; state.revision += 1; state.explicit = true;
          status = 400; body = { error: "stale_revision", message: "Settings changed on another surface." };
        } else {
          state.mode = payload.presentation_mode as State["mode"];
          state.revision += 1; state.explicit = true;
        }
      }
      if (status === 200) body = settings(state);
    }
    await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
  });
}

test("Technical Mode is keyboard accessible, revision-bound and shared across tabs", async ({ page, context }) => {
  test.setTimeout(60000);
  const state = createState();
  await mount(page, state);
  await page.goto(`/settings?section=experience&${DAEMON}`);
  const toggle = page.getByRole("switch", { name: "Technical Mode" });
  await expect(toggle).toBeEnabled({ timeout: 15000 });
  const other = await context.newPage();
  await mount(other, state);
  await other.goto(`/settings?section=experience&${DAEMON}`);
  await other.bringToFront();
  await expect(other.getByRole("switch", { name: "Technical Mode" })).toBeEnabled({ timeout: 15000 });
  await page.bringToFront();
  await expect(toggle).not.toBeChecked();
  await toggle.focus(); await page.keyboard.press("Space");
  await expect(toggle).toBeChecked();
  await expect(page.getByText("Saved on this device.", { exact: true })).toBeVisible();
  expect(state.writes).toEqual([{ presentation_mode: "technical", presentation_schema_version: 1, presentation_revision: 0 }]);
  await other.bringToFront();
  await expect(other.getByRole("switch", { name: "Technical Mode" })).toBeChecked({ timeout: 10000 });
  await page.reload();
  await expect(page.getByRole("switch", { name: "Technical Mode" })).toBeChecked();
  await other.close();
});

test("old Core is read-only and a stale save never claims success", async ({ page }) => {
  const state = createState(); state.supported = false;
  await mount(page, state);
  await page.goto(`/settings?section=experience&${DAEMON}`);
  await expect(page.getByRole("switch", { name: "Technical Mode" })).toBeDisabled();
  await expect(page.getByText(/Update HOL Guard Core/)).toBeVisible();
  expect(state.writes).toEqual([]);
  state.supported = true; state.rejectNextWrite = true;
  await page.reload();
  const toggle = page.getByRole("switch", { name: "Technical Mode" });
  await expect(toggle).toBeEnabled(); await toggle.click();
  await expect(page.getByRole("alert").filter({ hasText: "could not be confirmed" })).toBeVisible();
  await expect(toggle).toBeChecked();
  await expect(page.getByText("Saved on this device.", { exact: true })).toHaveCount(0);
});

test("Everyday review hides retained commands until a deliberate per-item disclosure", async ({ page }) => {
  const state = createState();
  await mount(page, state);
  await page.goto(`/requests/everyday-review?${DAEMON}`);
  const summary = page.locator("[data-guard-action-explanation]");
  await expect(summary).toContainText(fixture.action_explanation.everyday.headline);
  const disclosure = page.locator("[data-guard-technical-disclosure]");
  await expect(disclosure.getByRole("button", { name: "Show technical details", exact: true })).toBeVisible();
  await expect(page.locator("[data-guard-technical-stopped-action]")).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText("rm -rf ./build");
  await expect(page.getByRole("option").filter({ hasText: "rm -rf" })).toHaveCount(0);
  await disclosure.getByRole("button", { name: "Show technical details", exact: true }).click();
  await expect(page.locator("[data-guard-technical-stopped-action]")).toContainText("rm -rf ./build");
  await disclosure.getByRole("button", { name: "Hide technical details", exact: true }).click();
  await expect(page.locator("[data-guard-technical-stopped-action]")).toHaveCount(0);
  expect(state.writes).toEqual([]);
});

test("a mismatched explanation is rejected and Experience fits a narrow screen", async ({ page }) => {
  const state = createState(); state.mismatched = true;
  await mount(page, state);
  await page.goto(`/requests/everyday-review?${DAEMON}`);
  await expect(page.getByText(/could not be matched to the retained action/)).toBeVisible();
  await expect(page.locator("[data-guard-action-explanation]")).toHaveCount(0);
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto(`/settings?section=experience&${DAEMON}`);
  const toggle = page.getByRole("switch", { name: "Technical Mode" });
  await expect(toggle).toBeVisible();
  const bounds = await toggle.boundingBox();
  expect(bounds).not.toBeNull(); expect(bounds!.width).toBeGreaterThanOrEqual(44); expect(bounds!.height).toBeGreaterThanOrEqual(44);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
