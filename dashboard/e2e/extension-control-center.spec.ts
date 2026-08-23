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

async function mount(page: Page, options: { malformedCatalog?: boolean; effective?: Record<string, unknown> } = {}) {
  await page.route("**/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "fixture-session-token" };
    else if (path.endsWith("/runtime")) body = freeStateSnapshot;
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

test("extension cards navigate without nesting or conflating capability policy", async ({ page }) => {
  await mount(page);
  await initialize(page);
  const card = page.getByRole("article").filter({ hasText: "Git" }).first();
  await expect(card.getByRole("button", { name: "View Git details" })).toBeVisible();
  await card.getByRole("button", { name: "Review capability policy" }).click();
  await expect(page.getByRole("dialog", { name: /Git capability/ })).toBeVisible();
  await expect(page).toHaveURL(/\/extensions(?:\?|$)/);
  await page.getByRole("button", { name: "Close review" }).click();
  await card.getByRole("button", { name: "View Git details" }).press("Enter");
  await expect(page).toHaveURL(/\/extensions\/command\.git$/);
  await expect(page.getByTestId("extension-control-center-detail")).toBeVisible();
  expect(await page.evaluate(() => (window as typeof window & { __ecc_xss?: boolean }).__ecc_xss ?? false)).toBe(false);
});

test("alias direct loads canonicalize, preserve only safe query state, and deep-link rules", async ({ page }) => {
  await mount(page);
  await initialize(page);
  await page.goto("/extensions/command.scm?tab=commands&risk=high&sort=risk&guard-token=should-disappear#private-fragment");
  await expect(page).toHaveURL(/\/extensions\/command\.git\?tab=commands&risk=high&sort=risk$/);
  expect(page.url()).not.toContain("guard-token");
  expect(page.url()).not.toContain("private-fragment");
  await expect(page.getByRole("tab", { name: "Commands & rules" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("button", { name: "Inspect rule Hard reset" }).click();
  await expect(page.getByRole("dialog", { name: "Hard reset" })).toBeVisible();
  await expect(page).toHaveURL(/rule=command\.git\.hard-reset/);
  await page.getByRole("button", { name: "Test this rule" }).click();
  await expect(page.getByRole("tab", { name: "Test Lab" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByText("Selected rule:")).toBeVisible();
  await page.goBack();
  await expect(page.getByRole("dialog", { name: "Hard reset" })).toBeVisible();
  await page.getByRole("button", { name: "Close rule details" }).press("Escape");
  await expect(page.getByRole("dialog", { name: "Hard reset" })).toHaveCount(0);
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
  await page.getByRole("button", { name: "View Git details" }).click();
  await expect(page.getByText("Global lockdown controls this capability.")).toBeVisible();
  await page.getByRole("tab", { name: "Commands & rules" }).click();
  await expect(page.getByText("Lockdown").first()).toBeVisible();
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

  await quickApply.getByRole("button", { name: "Deny all" }).click();
  await expect(page.getByText("1 unsaved setting change.")).toBeVisible();
  await expect(page.getByRole("radio", { name: "Block" })).toHaveAttribute("aria-checked", "true");

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
