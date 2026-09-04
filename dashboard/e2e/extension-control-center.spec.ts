import { expect, test, type Page } from "@playwright/test";

import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  emptyReceiptsPayload,
  freeStateSnapshot,
} from "./fixture-states";

const DAEMON_ORIGIN = "http://127.0.0.1:4175";
const DIGEST = "a".repeat(64);

function extension(id = "command.git", alias = "command.scm") {
  const slug = id.slice("command.".length);
  const ruleId = `${id}.hard-reset`;
  const permissionId = `${id}.permission.hard-reset`;
  return {
    schema_version: 2,
    extension_id: id,
    version: "1.2.3",
    name: slug === "git" ? "Git" : slug.replaceAll("-", " "),
    description: "Canonical extension metadata <script>window.__ecc_xss = true</script>",
    enabled: true,
    required: false,
    trust_class: "first-party",
    activation: "default-on",
    publisher: { id: "hol", displayName: "Hashgraph Online" },
    icon: { kind: "none" },
    source: "built-in",
    aliases: alias ? [alias] : [],
    dependencies: [],
    conflicts: [],
    delegated_protection: null,
    ecosystem_ids: [slug],
    executables: [slug],
    project_markers: [`.${slug}`],
    reference_urls: ["https://example.com/reference"],
    action_classes: [`${slug}.history.rewrite`],
    risk_classes: ["destructive_shell"],
    safer_alternatives: ["Create a checkpoint first."],
    rule_count: 1,
    rules: [{
      rule_id: ruleId,
      rule_version: 1,
      title: "Hard reset",
      description: "Detects destructive reset behavior.",
      severity: "high",
      risk_classes: ["destructive_shell"],
      action_classes: [`${slug}.history.rewrite`],
      safer_alternatives: ["Use a narrower restore operation."],
      default_mode: "review",
      matcher_kind: "ExecutableMatcher",
      safe_variants: [{ variant_id: "status", title: "Status", matcher_kind: "ExecutableMatcher" }],
      compatibility_fallback: false,
    }],
    permission_count: 1,
    permissions: [{
      permission_id: permissionId,
      schema_version: 1,
      extension_id: id,
      implementation_version: "1.2.3",
      label: "Hard reset",
      description: "Controls destructive reset behavior.",
      risk_tier: "high",
      baseline_floor: "review",
      default_enabled: true,
      configurable: true,
      fixed_reason: null,
      typed_capabilities: [],
      action_classes: [`${slug}.history.rewrite`],
      rule_ids: [ruleId],
      dependencies: [],
      conflicts: [],
      implied_permissions: [],
      introduced_version: "1.0.0",
      deprecated: false,
      replacement_permission_id: null,
      safer_guidance: ["Create a checkpoint first."],
    }],
  };
}

function catalog() {
  return {
    schema_version: "guard.daemon.extension-controls.v1",
    control_schema_version: "1.0.0",
    catalog_digest: DIGEST,
    extensions: [extension(), extension("command.filesystem", ""), extension("command.cloud.aws", "")],
    limits: { max_body_bytes: 1_000_000, max_controls: 4096, max_observations: 2048 },
  };
}

function effective(overrides: Record<string, unknown> = {}) {
  return {
    schema_version: "guard.daemon.extension-controls.v1",
    health: "protected",
    revision: 7,
    catalog_digest: DIGEST,
    global_lockdown: false,
    controls: [],
    layers: [],
    failures: [],
    ...overrides,
  };
}

async function mount(page: Page, options: { malformedCatalog?: boolean; effective?: Record<string, unknown>; runtime?: unknown } = {}) {
  await page.route("**/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "fixture-session-token" };
    else if (path.endsWith("/runtime")) body = options.runtime ?? freeStateSnapshot;
    else if (path.endsWith("/requests")) body = { items: [], next_cursor: null, total_pending_count: 0, total_count: 0, status: "pending" };
    else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) body = defaultSettingsPayload;
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/extension-controls/catalog")) {
      body = options.malformedCatalog ? { ...catalog(), extensions: [{ extension_id: "../../bad" }] } : catalog();
    } else if (path.endsWith("/extension-controls/effective")) body = options.effective ?? effective();
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
}

async function initialize(page: Page) {
  await page.goto(`/extensions?guardDaemon=${DAEMON_ORIGIN}`);
  await expect(page.getByRole("heading", { name: "Extensions", exact: true })).toBeVisible();
}

test("extension cards navigate through one canonical detail action", async ({ page }) => {
  await mount(page);
  await initialize(page);
  const card = page.getByRole("button", { name: /^Git/ });
  await expect(card).toBeVisible();
  await card.press("Enter");
  await expect(page).toHaveURL(/\/extensions\/command\.git$/);
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();
  expect(await page.evaluate(() => (window as typeof window & { __ecc_xss?: boolean }).__ecc_xss ?? false)).toBe(false);
});

test("canonical Extension detail exposes managed authority without gating local safety", async ({ page }) => {
  await mount(page, {
    runtime: {
      ...freeStateSnapshot,
      latest_receipts: [{
        receipt_id: "receipt-git-blocked",
        harness: "codex",
        artifact_id: "artifact-git",
        artifact_hash: "c".repeat(64),
        policy_decision: "block",
        capabilities_summary: "Git command protection",
        changed_capabilities: [],
        provenance_summary: "Guard decision",
        user_override: null,
        source_scope: null,
        timestamp: "2026-08-25T12:00:00Z",
        action_envelope_json: {
          schema_version: 1,
          action_id: "action-git-blocked",
          harness: "codex",
          event_name: "tool.execute",
          action_type: "shell_command",
          workspace: null,
          workspace_hash: null,
          tool_name: "git",
          command: null,
          prompt_excerpt: null,
          target_paths: [],
          network_hosts: [],
          mcp_server: null,
          mcp_tool: null,
          package_manager: null,
          package_name: null,
          script_name: null,
          raw_payload_redacted: {},
        },
      }],
    },
    effective: effective({
      layers: [{
        schema_version: "1.0.0",
        kind: "signed-cloud",
        catalog_digest: DIGEST,
        global_lockdown: false,
        controls: [{
          target_kind: "permission",
          target_id: "command.git.permission.hard-reset",
          state: "enabled",
        }],
      }, {
        schema_version: "1.0.0",
        kind: "local-admin",
        catalog_digest: DIGEST,
        global_lockdown: false,
        controls: [{
          target_kind: "permission",
          target_id: "command.git.permission.hard-reset",
          state: "disabled",
        }],
      }],
      projection: {
        schema_version: "guard.daemon.extension-control-projection.v1",
        revision: 7,
        catalog_digest: DIGEST,
        health: "protected",
        extensions: [{
          extension_id: "command.git",
          effective_state: "allowed",
          local_state: "inherited",
          managed_state: "inherited",
          required: false,
          reason_codes: [],
        }],
        permissions: [{
          permission_id: "command.git.permission.hard-reset",
          extension_id: "command.git",
          effective_state: "blocked",
          local_state: "disabled",
          managed_state: "enabled",
          configurable: true,
          fixed_reason: null,
          reason_codes: ["control.disabled-permission"],
        }],
      },
      managed_controls: {
        control_set_id: "managed-git-safety",
        control_set_name: "Managed Git safety",
        bundle_version: 7,
        workspace_id: "workspace-managed-controls",
        authority_mode: "managed-restrictive",
        catalog_digest: DIGEST,
        acknowledgement: {
          extension_authority_revision: 3,
          effective_projection_digest: "b".repeat(64),
          status: "applied",
        },
      },
    }),
  });
  await initialize(page);
  await page.getByRole("button", { name: /^Git/ }).click();
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByTestId("protection-module-detail").getByText("Set on this device").first()).toBeVisible();
  await expect(page.getByText("Blocked", { exact: true })).toBeVisible();
  await expect(page.getByText("Managed by workspace-managed-controls · Set on this device")).toBeVisible();
  await page.getByRole("tab", { name: "Overview" }).focus();
  await page.getByRole("tab", { name: "Overview" }).press("End");
  await expect(page.getByRole("tab", { name: "Technical details" })).toBeFocused();
  await expect(page.getByRole("tab", { name: "Technical details" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Technical details" }).press("Home");
  await expect(page.getByRole("tab", { name: "Overview" })).toBeFocused();
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Overview" }).press("ArrowRight");
  await expect(page.getByRole("tab", { name: "Permissions" })).toBeFocused();
  await expect(page.getByRole("tab", { name: "Permissions" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Permissions" }).press("ArrowLeft");
  await expect(page.getByRole("tab", { name: "Overview" })).toBeFocused();
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Activity" }).click();
  await expect(page.getByRole("heading", { name: "Recent Extension decisions" })).toBeVisible();
  await expect(page.getByText("Blocked · codex")).toBeVisible();
  await expect(page.getByRole("link", { name: "Open receipt" })).toHaveAttribute("href", /selected=receipt-git-blocked/);
  await page.getByRole("tab", { name: "Managed controls" }).click();
  await expect(page).toHaveURL(/tab=managed-controls/);
  await expect(page.getByRole("heading", { name: "Active managed control" })).toBeVisible();
  await expect(page.getByText("Managed Git safety")).toBeVisible();
  await expect(page.getByText(/cannot weaken this workspace restriction/)).toBeVisible();
  await expect(page.getByText(/Local protection and local tightening remain available/)).toBeVisible();
});

test("dirty permission drafts require confirmation before click or keyboard tab changes", async ({ page }) => {
  await mount(page);
  await initialize(page);
  await page.getByRole("button", { name: /^Git/ }).click();
  await page.getByRole("tab", { name: "Permissions" }).click();
  await page.getByRole("radio", { name: "Block" }).click();
  await expect(page.getByText("1 unsaved setting change.")).toBeVisible();

  page.once("dialog", async (dialog) => {
    expect(dialog.message()).toBe("Discard your unreviewed protection setting changes?");
    await dialog.dismiss();
  });
  await page.getByRole("tab", { name: "Activity" }).click();
  await expect(page.getByRole("tab", { name: "Permissions" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("radio", { name: "Block" })).toHaveAttribute("aria-checked", "true");

  await page.getByRole("tab", { name: "Permissions" }).focus();
  page.once("dialog", async (dialog) => {
    expect(dialog.message()).toBe("Discard your unreviewed protection setting changes?");
    await dialog.dismiss();
  });
  await page.getByRole("tab", { name: "Permissions" }).press("ArrowRight");
  await expect(page.getByRole("tab", { name: "Permissions" })).toBeFocused();
  await expect(page.getByRole("tab", { name: "Permissions" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("radio", { name: "Block" })).toHaveAttribute("aria-checked", "true");

  page.once("dialog", async (dialog) => {
    await dialog.accept();
  });
  await page.getByRole("tab", { name: "Activity" }).click();
  await expect(page.getByRole("tab", { name: "Activity" })).toHaveAttribute("aria-selected", "true");
});

test("managed controls starts the supported Guard Cloud connection flow", async ({ page }) => {
  let connectStarts = 0;
  await mount(page, {
    runtime: { ...freeStateSnapshot, dashboard_url: "", connect_url: "" },
  });
  await page.route("**/v1/cloud/connect", async (route) => {
    connectStarts += 1;
    expect(route.request().method()).toBe("POST");
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        connect_required: true,
        connect_flow: {
          state: "running",
          title: "Connect Guard Cloud",
          detail: "Complete sign-in.",
          action_label: "Open sign-in",
          connect_url: "https://example.test/connect",
          authorize_url: "https://example.test/authorize",
          browser_opened: false,
          request_id: "request-1",
          poll_after_ms: 1500,
        },
      }),
    });
  });
  await initialize(page);
  await page.getByRole("button", { name: /^Git/ }).click();
  await page.getByRole("tab", { name: "Managed controls" }).click();
  await page.getByRole("button", { name: "Connect Guard Cloud" }).click();
  await expect(page.getByRole("link", { name: "Open Guard Cloud sign-in" })).toHaveAttribute(
    "href",
    "https://example.test/authorize",
  );
  await expect(page.getByRole("status")).toContainText("Complete sign-in");
  expect(connectStarts).toBe(1);
});

test("alias direct loads canonicalize and preserve only supported detail state", async ({ page }) => {
  await mount(page);
  await initialize(page);
  await page.goto("/extensions/command.scm?tab=commands&risk=high&sort=risk&guard-token=should-disappear#private-fragment");
  await expect(page).toHaveURL(/\/extensions\/command\.git\?tab=commands&risk=high&sort=risk#/);
  expect(new URL(page.url()).searchParams.has("guard-token")).toBe(false);
  expect(page.url()).not.toContain("private-fragment");
  await expect(page.getByRole("tab", { name: "Permissions" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("heading", { name: "Protection settings" })).toBeVisible();
});

test("unknown and encoded invalid extension IDs fail closed", async ({ page }) => {
  await mount(page);
  await initialize(page);
  await page.goto("/extensions/command.unknown");
  await expect(page.getByRole("heading", { name: "Extension not found" })).toBeVisible();
  await page.goto("/extensions/%2Fetc%2Fpasswd");
  await expect(page.getByRole("heading", { name: "Extension not found" })).toBeVisible();
});

test("global lockdown and narrow viewport remain explicit and usable", async ({ page }) => {
  await mount(page, { effective: effective({ global_lockdown: true }) });
  await page.setViewportSize({ width: 320, height: 720 });
  await initialize(page);
  await page.getByRole("button", { name: /^Git/ }).click();
  await expect(page.getByText(/Emergency Lockdown currently controls this module/)).toBeVisible();
  await page.getByRole("tab", { name: "Permissions" }).click();
  await expect(page.getByText(/Emergency Lockdown remains dominant/)).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

test("search results offer safe bulk actions with clear scope on desktop and mobile", async ({ page }) => {
  await mount(page);
  await initialize(page);

  await page.getByRole("searchbox", { name: "Search command patterns" }).fill("git");
  await expect(page.getByText("Quick apply to 1 matching capability")).toBeVisible();
  const quickApply = page.getByRole("group", { name: "Quick apply to 1 matching capabilities" });
  await expect(quickApply.getByRole("button", { name: "Recommended" })).toHaveAttribute("aria-pressed", "true");
  await quickApply.getByRole("button", { name: "Recommended" }).click();
  await expect(page.getByText("1 unsaved setting change.")).toHaveCount(0);

  await quickApply.getByRole("button", { name: "Deny all" }).click();
  await expect(page.getByText("1 unsaved setting change.")).toBeVisible();
  await expect(page.getByRole("radio", { name: "Block" })).toHaveAttribute("aria-checked", "true");

  await page.getByRole("searchbox", { name: "Search command patterns" }).fill("no matching capability");
  await expect(page.getByText("No command patterns or tools match this search.")).toBeVisible();
  await expect(page.getByText("1 unsaved setting change.")).toBeVisible();
  await page.getByRole("searchbox", { name: "Search command patterns" }).fill("git");

  await quickApply.getByRole("button", { name: "Recommended" }).click();
  await expect(page.getByText("1 unsaved setting change.")).toHaveCount(0);
  await quickApply.getByRole("button", { name: "Allow all" }).click();
  await expect(page.getByRole("button", { name: "Review 1 change" })).toBeVisible();

  await page.setViewportSize({ width: 320, height: 720 });
  await expect(quickApply.getByRole("button", { name: "Allow all" })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

test("bulk allow preserves organization blocks", async ({ page }) => {
  await mount(page, {
    effective: effective({
      layers: [{
        schema_version: "1.0.0",
        kind: "signed-cloud",
        catalog_digest: DIGEST,
        global_lockdown: false,
        controls: [{
          target_kind: "permission",
          target_id: "command.git.permission.hard-reset",
          state: "disabled",
        }],
      }],
    }),
  });
  await initialize(page);
  await page.getByRole("searchbox", { name: "Search command patterns" }).fill("git");

  await expect(page.getByText("1 organization block stays enforced.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Allow all" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Deny all" })).toBeEnabled();
});

test("malformed catalog response is rejected at the client boundary", async ({ page }) => {
  await mount(page, { malformedCatalog: true });
  await page.goto(`/extensions?guardDaemon=${DAEMON_ORIGIN}`);
  await expect(page.getByRole("heading", { name: "Extensions unavailable" })).toBeVisible();
  await expect(page.getByRole("alert")).toContainText("Invalid extension-control response");
});
